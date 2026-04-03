package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cavad93/vpn/server/crypto"
	"github.com/cavad93/vpn/server/transport"
)

// Control-stream constants (must match server/main.go).
const (
	ctlHello         = byte(0x01)
	ctlAssign        = byte(0x02)
	ctlError         = byte(0xFF)
	ctlAssignPayload = 9    // ip(4) + prefixLen(1) + gw(4)
	noiseMaxMsg      = 4096 // max handshake message size
)

// AssignedRoute holds the IP routing information returned by the server.
type AssignedRoute struct {
	AssignedIP string
	PrefixLen  int
	Gateway    string
	CIDR       string
}

// VPNClient manages the connection lifecycle.
type VPNClient struct {
	cfg *Config

	mu         sync.Mutex
	cancelConn context.CancelFunc
	mux        *transport.Mux
	nc         *noiseConn
	rawConn    net.Conn

	// Buffer pools for zero-alloc reads and writes.
	readPool  sync.Pool
	writePool sync.Pool
}

// NewVPNClient creates a VPNClient from the given configuration.
func NewVPNClient(cfg *Config) *VPNClient {
	return &VPNClient{
		cfg: cfg,
		readPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 65536)
				return &buf
			},
		},
		writePool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 0, 2+1460+16)
				return &buf
			},
		},
	}
}

// Connect establishes the VPN connection and returns route information.
func (vc *VPNClient) Connect(ctx context.Context) (*AssignedRoute, error) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Load key pair
	kp, err := loadKeyPairFromHex(vc.cfg.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("vpnclient: load key: %w", err)
	}

	// 1. TCP dial with socket tuning
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	rawConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", vc.cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("vpnclient: dial %s: %w", vc.cfg.ServerAddr, err)
	}

	// Speed optimization 1: TCP_NODELAY and large socket buffers
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 * 1024 * 1024)
		_ = tc.SetWriteBuffer(4 * 1024 * 1024)
	}

	// 2. TLS obfuscation
	obfs := transport.NewObfsConn(rawConn)
	if err := obfs.ClientHandshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: obfs handshake: %w", err)
	}

	// 3. Noise_XX initiator handshake
	hs, err := crypto.NewHandshake(crypto.Initiator, kp)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: noise init: %w", err)
	}
	msg1, err := hs.WriteMessage1()
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: noise msg1: %w", err)
	}
	if err := writeHandshakeMsg(obfs, msg1); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: send msg1: %w", err)
	}
	msg2, err := readHandshakeMsg(obfs)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: recv msg2: %w", err)
	}
	if err := hs.ReadMessage2(msg2); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: process msg2: %w", err)
	}
	msg3, session, err := hs.WriteMessage3()
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: noise msg3: %w", err)
	}
	if err := writeHandshakeMsg(obfs, msg3); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: send msg3: %w", err)
	}

	// Verify server key if configured
	if vc.cfg.ServerKeyHex != "" {
		got := hex.EncodeToString(session.RemoteStatic[:])
		if got != strings.ToLower(vc.cfg.ServerKeyHex) {
			rawConn.Close()
			return nil, fmt.Errorf("vpnclient: server key mismatch (possible MITM)")
		}
	}

	// 4. Noise conn + mux (client uses even stream IDs)
	nc := newNoiseConn(obfs, session, &vc.writePool)
	mux := transport.NewMux(nc, true)

	// 5. Control stream: send ctlHello, receive IP assignment
	ctlStream, err := mux.OpenStream()
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: open control stream: %w", err)
	}
	if _, err := ctlStream.Write([]byte{ctlHello}); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: send ctlHello: %w", err)
	}
	resp := make([]byte, 1+ctlAssignPayload)
	if _, err := io.ReadFull(ctlStream, resp); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: read ctlAssign: %w", err)
	}
	ctlStream.Close()

	if resp[0] == ctlError {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: server refused connection")
	}
	if resp[0] != ctlAssign {
		rawConn.Close()
		return nil, fmt.Errorf("vpnclient: unexpected control byte 0x%02x", resp[0])
	}

	assignedIP := fmt.Sprintf("%d.%d.%d.%d", resp[1], resp[2], resp[3], resp[4])
	prefixLen := int(resp[5])
	gateway := fmt.Sprintf("%d.%d.%d.%d", resp[6], resp[7], resp[8], resp[9])
	cidr := fmt.Sprintf("%s/%d", assignedIP, prefixLen)

	route := &AssignedRoute{
		AssignedIP: assignedIP,
		PrefixLen:  prefixLen,
		Gateway:    gateway,
		CIDR:       cidr,
	}

	vc.rawConn = rawConn
	vc.nc = nc
	vc.mux = mux

	return route, nil
}

// OpenDataStream opens a bidirectional stream for IP packet forwarding.
func (vc *VPNClient) OpenDataStream() (*transport.Stream, error) {
	vc.mu.Lock()
	mux := vc.mux
	vc.mu.Unlock()

	if mux == nil {
		return nil, fmt.Errorf("vpnclient: not connected")
	}
	return mux.OpenStream()
}

// Disconnect closes all connections.
func (vc *VPNClient) Disconnect() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if vc.mux != nil {
		vc.mux.Close()
		vc.mux = nil
	}
	if vc.rawConn != nil {
		vc.rawConn.Close()
		vc.rawConn = nil
	}
	vc.nc = nil
}

// IsConnected returns whether the client is currently connected.
func (vc *VPNClient) IsConnected() bool {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	return vc.mux != nil
}

// GetBuffers returns read/write buffer pools for use in packet forwarding.
func (vc *VPNClient) GetReadBuffer() *[]byte {
	return vc.readPool.Get().(*[]byte)
}

// PutReadBuffer returns a buffer to the read pool.
func (vc *VPNClient) PutReadBuffer(buf *[]byte) {
	vc.readPool.Put(buf)
}

// ---------------------------------------------------------------------------
// noiseConn — encrypts/decrypts using Noise session
// ---------------------------------------------------------------------------

// maxNoiseFrame is the largest ciphertext we will ever read in one frame.
const maxNoiseFrame = 65535 + 16

// noiseConn wraps a net.Conn with Noise session encryption.
type noiseConn struct {
	conn      net.Conn
	session   *crypto.Session
	readBuf   []byte
	recvBuf   [maxNoiseFrame]byte
	writePool *sync.Pool
}

func newNoiseConn(conn net.Conn, session *crypto.Session, pool *sync.Pool) *noiseConn {
	return &noiseConn{conn: conn, session: session, writePool: pool}
}

func (nc *noiseConn) Write(p []byte) (int, error) {
	ciphertext, err := nc.session.SendCipher.Encrypt(p, nil)
	if err != nil {
		return 0, fmt.Errorf("noiseConn encrypt: %w", err)
	}

	// Speed optimization 2: use pool to reduce GC pressure
	need := 2 + len(ciphertext)
	var frame []byte
	if nc.writePool != nil {
		bp := nc.writePool.Get().(*[]byte)
		if cap(*bp) < need {
			*bp = make([]byte, need)
		}
		*bp = (*bp)[:need]
		frame = *bp
		binary.BigEndian.PutUint16(frame[:2], uint16(len(ciphertext)))
		copy(frame[2:], ciphertext)
		_, err = nc.conn.Write(frame)
		nc.writePool.Put(bp)
	} else {
		frame = make([]byte, need)
		binary.BigEndian.PutUint16(frame[:2], uint16(len(ciphertext)))
		copy(frame[2:], ciphertext)
		_, err = nc.conn.Write(frame)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (nc *noiseConn) Read(p []byte) (int, error) {
	if len(nc.readBuf) > 0 {
		n := copy(p, nc.readBuf)
		nc.readBuf = nc.readBuf[n:]
		return n, nil
	}

	// Read 2-byte length prefix
	if _, err := io.ReadFull(nc.conn, nc.recvBuf[:2]); err != nil {
		return 0, err
	}
	frameLen := int(binary.BigEndian.Uint16(nc.recvBuf[:2]))
	if frameLen == 0 || frameLen > maxNoiseFrame {
		return 0, fmt.Errorf("noiseConn: bad frame len %d", frameLen)
	}

	if _, err := io.ReadFull(nc.conn, nc.recvBuf[:frameLen]); err != nil {
		return 0, err
	}

	plain, err := nc.session.RecvCipher.Decrypt(nc.recvBuf[:frameLen], nil)
	if err != nil {
		return 0, fmt.Errorf("noiseConn decrypt: %w", err)
	}

	n := copy(p, plain)
	if n < len(plain) {
		nc.readBuf = append(nc.readBuf[:0], plain[n:]...)
	}
	return n, nil
}

func (nc *noiseConn) Close() error                       { return nc.conn.Close() }
func (nc *noiseConn) LocalAddr() net.Addr                { return nc.conn.LocalAddr() }
func (nc *noiseConn) RemoteAddr() net.Addr               { return nc.conn.RemoteAddr() }
func (nc *noiseConn) SetDeadline(t time.Time) error      { return nc.conn.SetDeadline(t) }
func (nc *noiseConn) SetReadDeadline(t time.Time) error  { return nc.conn.SetReadDeadline(t) }
func (nc *noiseConn) SetWriteDeadline(t time.Time) error { return nc.conn.SetWriteDeadline(t) }

// ---------------------------------------------------------------------------
// Handshake framing helpers
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
// Key loading helpers
// ---------------------------------------------------------------------------

// loadKeyPairFromHex loads a key pair from a 64-char hex-encoded private key.
func loadKeyPairFromHex(privHex string) (*crypto.KeyPair, error) {
	privHex = strings.TrimSpace(privHex)
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("loadKeyPairFromHex: invalid hex: %w", err)
	}
	if len(privBytes) != 32 {
		return nil, fmt.Errorf("loadKeyPairFromHex: expected 32 bytes, got %d", len(privBytes))
	}
	return crypto.KeyPairFromPrivate(privBytes)
}
