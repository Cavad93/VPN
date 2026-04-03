//go:build darwin

// cmd/vpnclient — native Go VPN client for macOS.
//
// Replaces the Python client. Uses the same crypto and transport packages as
// the server. Go goroutines have ~5 µs overhead per packet versus ~500 µs in
// Python (GIL + interpreter), giving 5–10× better throughput.
//
// Usage (run as root):
//
//	sudo ./vpnclient -server 193.124.93.240:8443
//	sudo ./vpnclient -server 193.124.93.240:8443 -key /etc/vpn/client.key
//	sudo ./vpnclient -server 193.124.93.240:8443 -server-key bc05f3a7...
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cavad93/vpn/server/crypto"
	"github.com/cavad93/vpn/server/transport"
)

// ---------------------------------------------------------------------------
// Control-stream constants — must match server/main.go
// ---------------------------------------------------------------------------

const (
	ctlHello         = byte(0x01)
	ctlAssign        = byte(0x02)
	ctlError         = byte(0xFF)
	ctlAssignPayload = 9    // ip(4) + prefixLen(1) + gw(4)
	noiseMaxMsg      = 4096 // max handshake message size
)

// ---------------------------------------------------------------------------
// noiseConn — encrypts/decrypts using Noise session (mirrors server/main.go)
// ---------------------------------------------------------------------------

type noiseConn struct {
	conn    net.Conn
	session *crypto.Session
	readBuf []byte
}

func (nc *noiseConn) Write(p []byte) (int, error) {
	ciphertext, err := nc.session.SendCipher.Encrypt(p, nil)
	if err != nil {
		return 0, fmt.Errorf("noiseConn encrypt: %w", err)
	}
	frame := make([]byte, 2+len(ciphertext))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(ciphertext)))
	copy(frame[2:], ciphertext)
	if _, err := nc.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (nc *noiseConn) Read(p []byte) (int, error) {
	for len(nc.readBuf) == 0 {
		var lb [2]byte
		if _, err := io.ReadFull(nc.conn, lb[:]); err != nil {
			return 0, err
		}
		fl := int(binary.BigEndian.Uint16(lb[:]))
		if fl == 0 || fl > 65535 {
			return 0, fmt.Errorf("noiseConn: bad frame len %d", fl)
		}
		enc := make([]byte, fl)
		if _, err := io.ReadFull(nc.conn, enc); err != nil {
			return 0, err
		}
		plain, err := nc.session.RecvCipher.Decrypt(enc, nil)
		if err != nil {
			return 0, fmt.Errorf("noiseConn decrypt: %w", err)
		}
		nc.readBuf = plain
	}
	n := copy(p, nc.readBuf)
	nc.readBuf = nc.readBuf[n:]
	return n, nil
}

// noiseConn satisfies net.Conn so it can be passed to transport.NewMux.
func (nc *noiseConn) Close() error                        { return nc.conn.Close() }
func (nc *noiseConn) LocalAddr() net.Addr                 { return nc.conn.LocalAddr() }
func (nc *noiseConn) RemoteAddr() net.Addr                { return nc.conn.RemoteAddr() }
func (nc *noiseConn) SetDeadline(t time.Time) error       { return nc.conn.SetDeadline(t) }
func (nc *noiseConn) SetReadDeadline(t time.Time) error   { return nc.conn.SetReadDeadline(t) }
func (nc *noiseConn) SetWriteDeadline(t time.Time) error  { return nc.conn.SetWriteDeadline(t) }

// ---------------------------------------------------------------------------
// Handshake framing (2-byte big-endian length prefix, same as server)
// ---------------------------------------------------------------------------

func readHandshakeMsg(r io.Reader) ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n == 0 || n > noiseMaxMsg {
		return nil, fmt.Errorf("handshake msg size %d out of range", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeHandshakeMsg(w io.Writer, msg []byte) error {
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(msg)))
	frame := append(lb[:0:2], lb[:]...)
	frame = append(frame, msg...)
	_, err := w.Write(frame)
	return err
}

// ---------------------------------------------------------------------------
// Main VPN logic
// ---------------------------------------------------------------------------

var log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

func run() error {
	serverAddr := flag.String("server", "", "VPN server host:port (required)")
	keyFile := flag.String("key", "client_privkey.hex", "path to hex-encoded private key file")
	serverKeyHex := flag.String("server-key", "", "expected server public key hex (optional, for verification)")
	flag.Parse()

	if *serverAddr == "" {
		flag.Usage()
		return fmt.Errorf("flag -server is required")
	}

	// Load or generate the client key pair.
	kp, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	log.Info("client key", "public_key", hex.EncodeToString(kp.PublicKey[:]))

	// 1. TCP connect with socket tuning.
	log.Info("connecting", "server", *serverAddr)
	rawConn, err := net.Dial("tcp", *serverAddr)
	if err != nil {
		return fmt.Errorf("tcp dial: %w", err)
	}
	tc := rawConn.(*net.TCPConn)
	_ = tc.SetNoDelay(true)
	_ = tc.SetReadBuffer(4 * 1024 * 1024)
	_ = tc.SetWriteBuffer(4 * 1024 * 1024)

	// 2. TLS obfuscation handshake.
	obfs := transport.NewObfsConn(rawConn)
	if err := obfs.ClientHandshake(); err != nil {
		return fmt.Errorf("obfs handshake: %w", err)
	}
	log.Debug("obfs done")

	// 3. Noise_XX initiator handshake.
	hs, err := crypto.NewHandshake(crypto.Initiator, kp)
	if err != nil {
		return fmt.Errorf("noise init: %w", err)
	}
	msg1, err := hs.WriteMessage1()
	if err != nil {
		return fmt.Errorf("noise msg1: %w", err)
	}
	if err := writeHandshakeMsg(obfs, msg1); err != nil {
		return fmt.Errorf("noise send msg1: %w", err)
	}
	msg2, err := readHandshakeMsg(obfs)
	if err != nil {
		return fmt.Errorf("noise recv msg2: %w", err)
	}
	if err := hs.ReadMessage2(msg2); err != nil {
		return fmt.Errorf("noise process msg2: %w", err)
	}
	msg3, session, err := hs.WriteMessage3()
	if err != nil {
		return fmt.Errorf("noise msg3: %w", err)
	}
	if err := writeHandshakeMsg(obfs, msg3); err != nil {
		return fmt.Errorf("noise send msg3: %w", err)
	}
	log.Info("noise handshake done", "server_key", hex.EncodeToString(session.RemoteStatic[:]))

	if *serverKeyHex != "" {
		if hex.EncodeToString(session.RemoteStatic[:]) != strings.ToLower(*serverKeyHex) {
			return fmt.Errorf("server public key mismatch — possible MITM!")
		}
		log.Info("server key verified")
	}

	// 4. Noise conn + mux (client uses even stream IDs: 2, 4, 6…).
	nc := &noiseConn{conn: obfs, session: session}
	mux := transport.NewMux(nc, true)

	// 5. Control stream: send ctlHello, receive IP assignment.
	ctlStream, err := mux.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	if _, err := ctlStream.Write([]byte{ctlHello}); err != nil {
		return fmt.Errorf("send ctlHello: %w", err)
	}
	resp := make([]byte, 1+ctlAssignPayload)
	if _, err := io.ReadFull(ctlStream, resp); err != nil {
		return fmt.Errorf("read ctlAssign: %w", err)
	}
	ctlStream.Close()
	if resp[0] == ctlError {
		return fmt.Errorf("server refused connection (ctlError)")
	}
	if resp[0] != ctlAssign {
		return fmt.Errorf("unexpected control byte 0x%02x", resp[0])
	}
	assignedIP := fmt.Sprintf("%d.%d.%d.%d", resp[1], resp[2], resp[3], resp[4])
	prefixLen := int(resp[5])
	gateway := fmt.Sprintf("%d.%d.%d.%d", resp[6], resp[7], resp[8], resp[9])
	log.Info("ip assigned", "ip", assignedIP, "prefix_len", prefixLen, "gateway", gateway)

	// 6. Data stream for IP packet forwarding.
	dataStream, err := mux.OpenStream()
	if err != nil {
		return fmt.Errorf("open data stream: %w", err)
	}

	// 7. Open utun interface.
	tun, err := openTun()
	if err != nil {
		return fmt.Errorf("open utun: %w", err)
	}
	defer tun.Close()
	log.Info("tun interface", "name", tun.Name())

	// ifconfig utunX <assignedIP> <gateway> mtu 1420 up
	if out, err := exec.Command("ifconfig", tun.Name(),
		assignedIP, gateway, "mtu", "1420", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig: %s: %w", out, err)
	}

	// 8. Add routes: server IP via original gateway, then split-default via VPN.
	host, _, _ := net.SplitHostPort(*serverAddr)
	origGW, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("get default gateway: %w", err)
	}
	log.Info("routing", "orig_gw", origGW, "vpn_gw", gateway)

	must := func(cmd string, args ...string) {
		if out, err := exec.Command(cmd, args...).CombinedOutput(); err != nil {
			log.Warn("route cmd failed", "args", args, "out", string(out))
		}
	}
	must("route", "add", "-host", host, origGW)
	must("route", "add", "-net", "0.0.0.0/1", gateway)
	must("route", "add", "-net", "128.0.0.0/1", gateway)

	defer func() {
		must("route", "delete", "-host", host, origGW)
		must("route", "delete", "-net", "0.0.0.0/1", gateway)
		must("route", "delete", "-net", "128.0.0.0/1", gateway)
		log.Info("routes removed")
	}()

	// 9. Bidirectional forwarding.
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 2)

	// TUN → VPN: read from the utun device, encrypt & send to server.
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					errCh <- nil
				default:
					errCh <- fmt.Errorf("tun read: %w", err)
				}
				return
			}
			if n < 20 {
				continue
			}
			if _, err := dataStream.Write(buf[:n]); err != nil {
				errCh <- fmt.Errorf("vpn write: %w", err)
				return
			}
		}
	}()

	// VPN → TUN: receive from server, decrypt & inject into utun.
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := dataStream.Read(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					errCh <- nil
				default:
					errCh <- fmt.Errorf("vpn read: %w", err)
				}
				return
			}
			if n < 20 {
				continue
			}
			if _, err := tun.Write(buf[:n]); err != nil {
				errCh <- fmt.Errorf("tun write: %w", err)
				return
			}
		}
	}()

	log.Info("VPN running — press Ctrl+C to disconnect")
	select {
	case <-ctx.Done():
		log.Info("shutting down...")
	case err := <-errCh:
		if err != nil {
			log.Error("error", "err", err)
		}
	}

	mux.Close()
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func loadKey(path string) (*crypto.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Generate and save a new key.
		kp, err2 := crypto.GenerateKeyPair()
		if err2 != nil {
			return nil, err2
		}
		privHex := hex.EncodeToString(kp.PrivateKey[:])
		if err3 := os.WriteFile(path, []byte(privHex+"\n"), 0600); err3 != nil {
			log.Warn("cannot save key", "path", path, "err", err3)
		} else {
			log.Info("generated new key pair", "path", path,
				"public_key", hex.EncodeToString(kp.PublicKey[:]))
		}
		return kp, nil
	}

	privHex := strings.TrimSpace(string(data))
	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != 32 {
		return nil, fmt.Errorf("invalid key file %s: must contain 64 hex chars", path)
	}

	// Derive the public key from the private key via X25519(priv, basepoint).
	kp, err := crypto.KeyPairFromPrivate(privBytes)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return kp, nil
}

// defaultGateway returns the current default IPv4 gateway on macOS by parsing
// `route -n get default`.
func defaultGateway() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("route get default: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(line[len("gateway:"):]), nil
		}
	}
	return "", fmt.Errorf("default gateway not found")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
