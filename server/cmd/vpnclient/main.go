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
	"sync"
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

	// reconnectMaxAttempts limits consecutive reconnect failures before giving up.
	reconnectMaxAttempts = 30
	// reconnectBaseDelay is the initial delay between reconnection attempts.
	reconnectBaseDelay = 2 * time.Second
	// reconnectMaxDelay caps the exponential backoff.
	reconnectMaxDelay = 60 * time.Second
	// keepaliveInterval is how often an application-level ping is sent through the
	// mux data stream to keep NAT/firewall entries alive. Russian ISPs (Rostelecom,
	// MTS) typically expire "idle" TCP entries after 60–120 s; 15 s is well within.
	keepaliveInterval = 15 * time.Second
)

// ---------------------------------------------------------------------------
// noiseConn — encrypts/decrypts using Noise session (mirrors server/main.go)
// ---------------------------------------------------------------------------

type noiseConn struct {
	conn    net.Conn
	session *crypto.Session
	readBuf []byte
	// Pre-allocated buffers for zero-alloc hot path.
	recvBuf    [65535 + 16]byte // max noise frame
	decryptBuf [65535]byte
	encryptBuf [2 + 65535 + 16]byte // length prefix + max ciphertext
}

func (nc *noiseConn) Write(p []byte) (int, error) {
	ctLen := len(p) + 16 // plaintext + AEAD tag
	need := 2 + ctLen
	frame := nc.encryptBuf[:need]

	ciphertext, err := nc.session.SendCipher.EncryptTo(frame[2:2], p, nil)
	if err != nil {
		return 0, fmt.Errorf("noiseConn encrypt: %w", err)
	}
	binary.BigEndian.PutUint16(frame[:2], uint16(len(ciphertext)))

	if _, err := nc.conn.Write(frame[:2+len(ciphertext)]); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read decrypts the next frame into p. Single-read optimisation: reads the
// entire noise frame from ObfsConn in one call, triggering ObfsConn's
// zero-alloc fast path (payload read directly into recvBuf without make()).
func (nc *noiseConn) Read(p []byte) (int, error) {
	for len(nc.readBuf) == 0 {
		// Single Read into the full recvBuf triggers ObfsConn's zero-alloc path.
		nr, err := nc.conn.Read(nc.recvBuf[:])
		if err != nil {
			return 0, err
		}
		if nr < 2 {
			return 0, fmt.Errorf("noiseConn: frame too short (%d)", nr)
		}
		fl := int(binary.BigEndian.Uint16(nc.recvBuf[:2]))
		if fl == 0 || fl > len(nc.recvBuf)-2 {
			return 0, fmt.Errorf("noiseConn: bad frame len %d", fl)
		}
		// Common case: TLS record contained the complete noise frame.
		// Rare fallback: read remaining ciphertext bytes.
		if have := nr - 2; have < fl {
			if _, err := io.ReadFull(nc.conn, nc.recvBuf[nr:2+fl]); err != nil {
				return 0, err
			}
		}
		plain, err := nc.session.RecvCipher.DecryptTo(nc.decryptBuf[:], nc.recvBuf[2:2+fl], nil)
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
func (nc *noiseConn) Close() error                       { return nc.conn.Close() }
func (nc *noiseConn) LocalAddr() net.Addr                { return nc.conn.LocalAddr() }
func (nc *noiseConn) RemoteAddr() net.Addr               { return nc.conn.RemoteAddr() }
func (nc *noiseConn) SetDeadline(t time.Time) error      { return nc.conn.SetDeadline(t) }
func (nc *noiseConn) SetReadDeadline(t time.Time) error  { return nc.conn.SetReadDeadline(t) }
func (nc *noiseConn) SetWriteDeadline(t time.Time) error { return nc.conn.SetWriteDeadline(t) }

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
	frame := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(msg)))
	copy(frame[2:], msg)
	_, err := w.Write(frame)
	return err
}

// ---------------------------------------------------------------------------
// VPN session — one connection attempt
// ---------------------------------------------------------------------------

// vpnSession holds the state for a single VPN connection.
type vpnSession struct {
	serverAddr   string
	kp           *crypto.KeyPair
	serverKeyHex string
	origGW       string // original default gateway, computed once
	tun          *tunDevice
}

// connect performs the full connection sequence: TCP → obfs → Noise → mux → IP
// assignment → data stream. Returns the data stream, mux, assigned IP info, and
// a cleanup function, or an error.
func (vs *vpnSession) connect() (
	dataStream *transport.Stream,
	mux *transport.Mux,
	assignedIP string,
	gateway string,
	cleanup func(),
	err error,
) {
	// 1. TCP connect with socket tuning.
	rawConn, err := net.DialTimeout("tcp", vs.serverAddr, 15*time.Second)
	if err != nil {
		return nil, nil, "", "", nil, fmt.Errorf("tcp dial: %w", err)
	}

	tc := rawConn.(*net.TCPConn)
	// Disable Nagle — VPN packets must not be coalesced.
	_ = tc.SetNoDelay(true)
	// 16 MB socket buffers — matched to server-side sysctl/netsh tuning.
	// BDP at 128 Mbps × 93 ms RTT = 1.5 MB; 16 MB provides 10× headroom
	// for bursts and ensures the TCP window can grow to full link speed.
	_ = tc.SetReadBuffer(16 * 1024 * 1024)
	_ = tc.SetWriteBuffer(16 * 1024 * 1024)
	// TCP keepalive: prevents ISP NAT/firewall from dropping "idle" connections.
	// This is the PRIMARY fix for the 29-minute disconnect issue.
	// Russian/Kazakh ISPs expire TCP NAT entries after 60–120 s of no TCP-level
	// keepalive probes. 15 s is well within.
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(15 * time.Second)

	cleanupConn := func() { rawConn.Close() }

	// 2. TLS obfuscation handshake.
	obfs := transport.NewObfsConn(rawConn)
	if err := obfs.ClientHandshake(); err != nil {
		cleanupConn()
		return nil, nil, "", "", nil, fmt.Errorf("obfs handshake: %w", err)
	}

	// 3. Noise_XX initiator handshake.
	hs, err := crypto.NewHandshake(crypto.Initiator, vs.kp)
	if err != nil {
		cleanupConn()
		return nil, nil, "", "", nil, fmt.Errorf("noise init: %w", err)
	}
	msg1, err := hs.WriteMessage1()
	if err != nil {
		cleanupConn()
		return nil, nil, "", "", nil, fmt.Errorf("noise msg1: %w", err)
	}
	if err := writeHandshakeMsg(obfs, msg1); err != nil {
		cleanupConn()
		return nil, nil, "", "", nil, fmt.Errorf("noise send msg1: %w", err)
	}
	msg2, err := readHandshakeMsg(obfs)
	if err != nil {
		cleanupConn()
		return nil, nil, "", "", nil, fmt.Errorf("noise recv msg2: %w", err)
	}
	if err := hs.ReadMessage2(msg2); err != nil {
		cleanupConn()
		return nil, nil, "", "", nil, fmt.Errorf("noise process msg2: %w", err)
	}
	msg3, session, err := hs.WriteMessage3()
	if err != nil {
		cleanupConn()
		return nil, nil, "", "", nil, fmt.Errorf("noise msg3: %w", err)
	}
	if err := writeHandshakeMsg(obfs, msg3); err != nil {
		cleanupConn()
		return nil, nil, "", "", nil, fmt.Errorf("noise send msg3: %w", err)
	}
	log.Info("noise handshake done", "server_key", hex.EncodeToString(session.RemoteStatic[:]))

	if vs.serverKeyHex != "" {
		if hex.EncodeToString(session.RemoteStatic[:]) != strings.ToLower(vs.serverKeyHex) {
			cleanupConn()
			return nil, nil, "", "", nil, fmt.Errorf("server public key mismatch — possible MITM!")
		}
		log.Info("server key verified")
	}

	// 4. Noise conn + mux.
	nc := &noiseConn{conn: obfs, session: session}
	mux = transport.NewMux(nc, true)

	cleanupMux := func() {
		mux.Close()
		cleanupConn()
	}

	// 5. Control stream: send ctlHello, receive IP assignment.
	ctlStream, err := mux.OpenStream()
	if err != nil {
		cleanupMux()
		return nil, nil, "", "", nil, fmt.Errorf("open control stream: %w", err)
	}
	if _, err := ctlStream.Write([]byte{ctlHello}); err != nil {
		ctlStream.Close()
		cleanupMux()
		return nil, nil, "", "", nil, fmt.Errorf("send ctlHello: %w", err)
	}
	resp := make([]byte, 1+ctlAssignPayload)
	if _, err := io.ReadFull(ctlStream, resp); err != nil {
		ctlStream.Close()
		cleanupMux()
		return nil, nil, "", "", nil, fmt.Errorf("read ctlAssign: %w", err)
	}
	ctlStream.Close()
	if resp[0] == ctlError {
		cleanupMux()
		return nil, nil, "", "", nil, fmt.Errorf("server refused connection (ctlError)")
	}
	if resp[0] != ctlAssign {
		cleanupMux()
		return nil, nil, "", "", nil, fmt.Errorf("unexpected control byte 0x%02x", resp[0])
	}
	assignedIP = fmt.Sprintf("%d.%d.%d.%d", resp[1], resp[2], resp[3], resp[4])
	gateway = fmt.Sprintf("%d.%d.%d.%d", resp[6], resp[7], resp[8], resp[9])
	prefixLen := int(resp[5])
	log.Info("ip assigned", "ip", assignedIP, "prefix_len", prefixLen, "gateway", gateway)

	// 6. Data stream for IP packet forwarding.
	dataStream, err = mux.OpenStream()
	if err != nil {
		cleanupMux()
		return nil, nil, "", "", nil, fmt.Errorf("open data stream: %w", err)
	}

	return dataStream, mux, assignedIP, gateway, cleanupMux, nil
}

// ---------------------------------------------------------------------------
// Main VPN logic with auto-reconnect
// ---------------------------------------------------------------------------

var log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

// applyMacOSTuning sets kernel parameters for optimal TCP throughput on macOS.
// The vpnclient runs as root, so sysctl writes succeed. Best-effort: failures
// are logged but do not prevent the VPN from starting.
//
// Key settings:
//   - maxsockbuf=16 MB: allows SO_RCVBUF/SO_SNDBUF up to 16 MB per socket
//   - sendspace/recvspace=1 MB: default TCP buffer per new socket (auto-tuning
//     grows it further). macOS default is 128 KB which limits initial throughput.
//   - tcp_fastopen=3: enable TFO for both client and server
//   - delayed_ack=0: disable 100 ms delayed ACK timer (macOS equivalent of
//     Linux TCP_QUICKACK). This is the highest-impact fix for download speed:
//     without it, the server's congestion window can only grow once per
//     100 ms + 93 ms = 193 ms round-trip, capping download at ~5 Mbps.
func applyMacOSTuning() {
	sysctls := map[string]string{
		"kern.ipc.maxsockbuf":          "16777216",
		"net.inet.tcp.sendspace":       "1048576",
		"net.inet.tcp.recvspace":       "1048576",
		"net.inet.tcp.delayed_ack":     "0",
		"net.inet.tcp.mssdflt":         "1440",
		"net.inet.tcp.win_scale_factor": "8",
		"net.inet.tcp.fastopen":        "3",
	}
	for k, v := range sysctls {
		if out, err := exec.Command("sysctl", "-w", k+"="+v).CombinedOutput(); err != nil {
			log.Debug("sysctl failed (non-fatal)", "key", k, "err", string(out))
		}
	}
}

func run() error {
	serverAddr := flag.String("server", "", "VPN server host:port (required)")
	keyFile := flag.String("key", "client_privkey.hex", "path to hex-encoded private key file")
	serverKeyHex := flag.String("server-key", "", "expected server public key hex (optional, for verification)")
	flag.Parse()

	if *serverAddr == "" {
		flag.Usage()
		return fmt.Errorf("flag -server is required")
	}

	// Apply macOS TCP kernel tuning before opening any sockets.
	// Must run as root (vpnclient always runs with sudo).
	applyMacOSTuning()

	// Load or generate the client key pair.
	kp, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	log.Info("client key", "public_key", hex.EncodeToString(kp.PublicKey[:]))

	// Resolve original default gateway ONCE (before VPN routes are installed).
	origGW, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("get default gateway: %w", err)
	}

	// Open utun ONCE — survives across reconnects.
	tun, err := openTun()
	if err != nil {
		return fmt.Errorf("open utun: %w", err)
	}
	defer tun.Close()
	log.Info("tun interface", "name", tun.Name())

	vs := &vpnSession{
		serverAddr:   *serverAddr,
		kp:           kp,
		serverKeyHex: *serverKeyHex,
		origGW:       origGW,
		tun:          tun,
	}

	// Top-level context: Ctrl+C or SIGTERM cancels everything.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	host, _, _ := net.SplitHostPort(*serverAddr)

	// Reconnect loop with exponential backoff.
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down...")
			return nil
		default:
		}

		if attempt > 0 {
			delay := reconnectDelay(attempt)
			log.Info("reconnecting...", "attempt", attempt, "delay", delay)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
		}

		dataStream, mux, assignedIP, gateway, cleanup, err := vs.connect()
		if err != nil {
			log.Warn("connection failed", "err", err, "attempt", attempt+1)
			attempt++
			if attempt >= reconnectMaxAttempts {
				return fmt.Errorf("gave up after %d reconnect attempts: %w", attempt, err)
			}
			continue
		}

		// Успешное подключение — сбросить счётчик.
		attempt = 0

		// Configure TUN interface.
		if out, err := exec.Command("ifconfig", tun.Name(),
			assignedIP, gateway, "mtu", "1420", "up").CombinedOutput(); err != nil {
			log.Warn("ifconfig failed", "out", string(out), "err", err)
			cleanup()
			continue
		}

		// Install routes.
		log.Info("routing", "orig_gw", origGW, "vpn_gw", gateway)
		routeCmd("add", "-host", host, origGW)
		routeCmd("add", "-net", "0.0.0.0/1", gateway)
		routeCmd("add", "-net", "128.0.0.0/1", gateway)

		removeRoutes := func() {
			routeCmd("delete", "-host", host, origGW)
			routeCmd("delete", "-net", "0.0.0.0/1", gateway)
			routeCmd("delete", "-net", "128.0.0.0/1", gateway)
			log.Info("routes removed")
		}

		// Run bidirectional forwarding until disconnection.
		log.Info("VPN running — press Ctrl+C to disconnect")
		disconnectErr := runForwarding(ctx, tun, dataStream)

		// Cleanup this session.
		removeRoutes()
		cleanup()

		if disconnectErr == nil {
			// Чистое завершение (Ctrl+C).
			return nil
		}
		log.Warn("connection lost", "err", disconnectErr)
		// Инкремент attempt для backoff при следующей попытке.
		attempt = 1
		_ = mux // silence unused warning
	}
}

// runForwarding performs bidirectional TUN↔VPN packet forwarding with an
// application-level keepalive. Returns nil on clean shutdown (ctx cancelled),
// or an error on connection loss.
func runForwarding(ctx context.Context, tun *tunDevice, dataStream *transport.Stream) error {
	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	// Application-level keepalive: sends a tiny (4-byte) packet through the
	// data stream every 15 s. This keeps the VPN tunnel "alive" for any
	// middlebox that inspects payload flow, not just TCP segments.
	// The server ignores packets < 20 bytes (not valid IPv4).
	keepaliveDone := make(chan struct{})
	go func() {
		defer close(keepaliveDone)
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		// 4-byte keepalive "packet" — not valid IPv4, ignored by server TUN writer.
		ping := []byte{0x00, 0x00, 0x00, 0x00}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := dataStream.Write(ping); err != nil {
					return // connection dead, forwarding goroutines will report it
				}
			}
		}
	}()

	// TUN → VPN
	wg.Add(1)
	go func() {
		defer wg.Done()
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
				select {
				case <-ctx.Done():
					errCh <- nil
				default:
					errCh <- fmt.Errorf("vpn write: %w", err)
				}
				return
			}
		}
	}()

	// VPN → TUN
	wg.Add(1)
	go func() {
		defer wg.Done()
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
				select {
				case <-ctx.Done():
					errCh <- nil
				default:
					errCh <- fmt.Errorf("tun write: %w", err)
				}
				return
			}
		}
	}()

	// Wait for first error or clean shutdown.
	var result error
	select {
	case <-ctx.Done():
		result = nil
	case err := <-errCh:
		result = err
	}

	// Stop keepalive and wait for goroutines.
	<-keepaliveDone
	return result
}

// reconnectDelay returns the delay for the given attempt number using
// exponential backoff: 2s, 4s, 8s, 16s, …, capped at 60s.
func reconnectDelay(attempt int) time.Duration {
	d := reconnectBaseDelay
	for i := 1; i < attempt; i++ {
		d *= 2
		if d > reconnectMaxDelay {
			d = reconnectMaxDelay
			break
		}
	}
	return d
}

// routeCmd runs a route command, logging any errors.
func routeCmd(args ...string) {
	if out, err := exec.Command("route", args...).CombinedOutput(); err != nil {
		log.Warn("route cmd failed", "args", args, "out", string(out))
	}
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
