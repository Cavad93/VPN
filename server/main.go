// Package main implements the VPN server.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"


	"golang.org/x/crypto/curve25519"

	"github.com/cavad93/vpn/server/api"
	"github.com/cavad93/vpn/server/crypto"
	"github.com/cavad93/vpn/server/notify"
	"github.com/cavad93/vpn/server/transport"
)

// Control message type constants.
const (
	ctlHello            = uint8(0x01) // client→server: request IP assignment
	ctlAssign           = uint8(0x02) // server→client: IP assignment response
	ctlError            = uint8(0x03) // server→client: error
	ctlAssignPayloadLen = 9           // 4(ip) + 1(prefix_len) + 4(gateway)

	noiseHandshakeMsgMaxSize = 4096
)

// TunDevice is the interface for reading/writing raw IP packets to/from a TUN device.
type TunDevice interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// Config holds the server configuration.
type Config struct {
	ListenAddr  string
	TunCIDR     string
	PrivKeyFile string
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:  "0.0.0.0:443",
		TunCIDR:     "10.8.0.1/24",
		PrivKeyFile: "server_privkey.hex",
	}
}

// SessionStats is an alias for api.SessionInfo — exported for compatibility.
type SessionStats = api.SessionInfo

// clientSession holds per-client runtime state.
type clientSession struct {
	id           uint64
	remoteKey    [32]byte
	noiseSession *crypto.Session
	mux          *transport.Mux
	assignedIP   net.IP
	dataStream   atomic.Pointer[transport.Stream] // lock-free on the hot TUN→client path
	bytesIn      atomic.Uint64
	bytesOut     atomic.Uint64
	connectedAt  time.Time
	cancel       context.CancelFunc
}

func (cs *clientSession) stats() SessionStats {
	ip := ""
	if cs.assignedIP != nil {
		ip = cs.assignedIP.String()
	}
	dur := time.Since(cs.connectedAt).Round(time.Second).String()
	return SessionStats{
		ID:          cs.id,
		RemoteKey:   hex.EncodeToString(cs.remoteKey[:]),
		AssignedIP:  ip,
		BytesIn:     cs.bytesIn.Load(),
		BytesOut:    cs.bytesOut.Load(),
		ConnectedAt: cs.connectedAt,
		Duration:    dur,
	}
}

// Server is the VPN server.
type Server struct {
	cfg         Config
	staticKP    *crypto.KeyPair
	logger      *slog.Logger
	mu          sync.RWMutex
	sessions    map[uint64]*clientSession
	// ipIndex maps packed uint32 IPv4 → *clientSession.
	// sync.Map is used instead of a plain map+RWMutex because routeFromTun
	// performs a read on every outgoing packet (read-heavy) while writes
	// happen only on connect/disconnect (rare).  sync.Map avoids any lock
	// in the steady-state read path via an atomic pointer swap.
	ipIndex     sync.Map
	allowedKeys map[[32]byte]struct{}
	tun         TunDevice
	pool        *ipPool
	nextIDMu    sync.Mutex
	nextID      uint64
	// notifSvc is optional; when set, push notifications are fired on
	// session connect / disconnect events.
	notifSvc *notify.NotificationService
}

// NewServer creates a new Server. allowedKeys may be nil/empty to allow any key.
func NewServer(cfg Config, kp *crypto.KeyPair, tun TunDevice, allowedKeys [][crypto.KeySize]byte, logger *slog.Logger) (*Server, error) {
	if kp == nil {
		return nil, errors.New("server: key pair is required")
	}
	if tun == nil {
		return nil, errors.New("server: tun device is required")
	}

	pool, err := newIPPool(cfg.TunCIDR)
	if err != nil {
		return nil, fmt.Errorf("server: invalid TunCIDR: %w", err)
	}

	s := &Server{
		cfg:      cfg,
		staticKP: kp,
		logger:   logger,
		sessions: make(map[uint64]*clientSession),
		tun:      tun,
		pool:     pool,
		nextID:   1,
	}

	if len(allowedKeys) > 0 {
		s.allowedKeys = make(map[[32]byte]struct{}, len(allowedKeys))
		for _, k := range allowedKeys {
			s.allowedKeys[k] = struct{}{}
		}
	}

	return s, nil
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", s.cfg.ListenAddr, err)
	}
	// TCP_DEFER_ACCEPT: kernel holds connections in SYN_RECV until the client
	// sends data (the TLS ClientHello), reducing context switches per accept
	// and silently dropping port-scan SYN probes.
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		setListenerDeferAccept(tcpLn, 5) // 5-second timeout
		setListenerTFO(tcpLn)            // TCP Fast Open — saves 1 RTT on reconnect
	}
	s.logger.Info("server listening", "addr", s.cfg.ListenAddr)

	go s.routeFromTun(ctx)

	go func() {
		<-ctx.Done()
		ln.Close()
		// Close TUN to unblock the blocking tun.Read() in routeFromTun.
		s.tun.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Warn("accept error", "err", err)
				continue
			}
		}
		// Increase TCP socket buffers to match the bandwidth-delay product
		// for Russia↔Kazakhstan (RTT ≈ 80-120 ms). Default Linux buffers
		// (128-256 KB) cap throughput at ~2 Mbps; 8 MB allows ≥64 Mbps.
		// setForcedSocketBuffers uses SO_RCVBUFFORCE/SO_SNDBUFFORCE (Linux,
		// CAP_NET_ADMIN) to bypass the net.core.rmem_max kernel limit.
		if tc, ok := conn.(*net.TCPConn); ok {
			setForcedSocketBuffers(tc, 16<<20) // 16 MB, force-bypass rmem_max
			tc.SetNoDelay(true)               // disable Nagle — VPN packets must not be coalesced
			// TCP keepalive: probe idle connections every 15 s with 3 retries.
			// Detects dead connections in 30 s (15+3×5) — 2× faster than before.
			// Prevents ISP NAT/firewall from silently dropping "idle" VPN connections
			// after a few minutes (common with Rostelecom / MTS stateful firewalls).
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(15 * time.Second)
		}
		go s.handleConn(ctx, conn)
	}
}

// Sessions returns a snapshot of current session statistics.
func (s *Server) Sessions() []api.SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]api.SessionInfo, 0, len(s.sessions))
	for _, cs := range s.sessions {
		out = append(out, cs.stats())
	}
	return out
}

// AddAllowedKey adds key to the allowlist. If no allowlist existed, one is
// created (switching the server from open-access to allowlist mode).
func (s *Server) AddAllowedKey(key [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.allowedKeys == nil {
		s.allowedKeys = make(map[[32]byte]struct{})
	}
	s.allowedKeys[key] = struct{}{}
}

// RemoveAllowedKey removes key from the allowlist.
func (s *Server) RemoveAllowedKey(key [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.allowedKeys, key)
}

// AllowedKeys returns a copy of the current allowlist, or nil if open access.
func (s *Server) AllowedKeys() [][32]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.allowedKeys) == 0 {
		return nil
	}
	out := make([][32]byte, 0, len(s.allowedKeys))
	for k := range s.allowedKeys {
		out = append(out, k)
	}
	return out
}

// PublicKey returns the server's static X25519 public key.
// Implements api.QRServerIface.
func (s *Server) PublicKey() [32]byte { return s.staticKP.PublicKey }

// VPNListenAddr returns the VPN server's listen address (host:port).
// Implements api.QRServerIface.
func (s *Server) VPNListenAddr() string { return s.cfg.ListenAddr }

// DisconnectSession cancels the session with the given ID.
// Returns true if the session existed.
func (s *Server) DisconnectSession(id uint64) bool {
	s.mu.RLock()
	cs, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	cs.cancel()
	return true
}

// handleConn handles a newly accepted TCP connection.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// TLS obfuscation handshake
	obfs := transport.NewObfsConn(conn)
	if err := obfs.ServerHandshake(); err != nil {
		s.logger.Warn("obfs handshake failed", "err", err)
		return
	}

	// Noise_XX handshake
	session, err := s.doNoiseHandshake(obfs)
	if err != nil {
		s.logger.Warn("noise handshake failed", "err", err)
		return
	}

	// Check if this key is allowed
	if !s.isKeyAllowed(session.RemoteStatic) {
		s.logger.Warn("key not allowed", "key", hex.EncodeToString(session.RemoteStatic[:]))
		return
	}

	// Wrap in encrypted noise conn
	nc := newNoiseConn(obfs, session)

	// Create mux (server = not client)
	mux := transport.NewMux(nc, false)

	// Register session
	connCtx, cancel := context.WithCancel(ctx)
	cs := &clientSession{
		id:           s.nextSessionID(),
		remoteKey:    session.RemoteStatic,
		noiseSession: session,
		mux:          mux,
		connectedAt:  time.Now(),
		cancel:       cancel,
	}

	s.mu.Lock()
	s.sessions[cs.id] = cs
	s.mu.Unlock()

	defer func() {
		cancel()
		mux.Close()
		s.mu.Lock()
		delete(s.sessions, cs.id)
		s.mu.Unlock()
		assignedIP := ""
		if cs.assignedIP != nil {
			assignedIP = cs.assignedIP.String()
			packed := binary.BigEndian.Uint32(cs.assignedIP.To4())
			s.ipIndex.Delete(packed)
			s.pool.release(cs.assignedIP)
		}
		s.logger.Info("session closed", "id", cs.id)
		// Fire push notification for disconnect (non-blocking, after cleanup).
		if s.notifSvc != nil && assignedIP != "" {
			s.notifSvc.NotifySessionDisconnected(cs.id, assignedIP)
		}
	}()

	s.logger.Info("new session", "id", cs.id, "key", hex.EncodeToString(session.RemoteStatic[:]))

	// Accept stream loop
	for {
		stream, err := mux.AcceptStream(connCtx)
		if err != nil {
			return
		}
		go s.handleStream(connCtx, cs, stream)
	}
}

// handleStream dispatches a stream to the appropriate handler.
func (s *Server) handleStream(ctx context.Context, cs *clientSession, stream *transport.Stream) {
	if cs.assignedIP == nil {
		if err := s.handleControlStream(ctx, cs, stream); err != nil {
			s.logger.Warn("control stream error", "id", cs.id, "err", err)
		}
	} else {
		s.handleDataStream(ctx, cs, stream)
	}
}

// handleControlStream processes the control stream for IP assignment.
func (s *Server) handleControlStream(ctx context.Context, cs *clientSession, stream *transport.Stream) error {
	defer stream.Close()

	// Read control byte
	buf := make([]byte, 1)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return fmt.Errorf("read control byte: %w", err)
	}
	if buf[0] != ctlHello {
		// Send error and return
		stream.Write([]byte{ctlError}) //nolint:errcheck
		return fmt.Errorf("expected ctlHello (0x%02x), got 0x%02x", ctlHello, buf[0])
	}

	// Allocate IP
	ip, err := s.pool.allocate()
	if err != nil {
		stream.Write([]byte{ctlError}) //nolint:errcheck
		return fmt.Errorf("ip allocation failed: %w", err)
	}

	cs.assignedIP = ip

	// Register in O(1) reverse IP index so routeFromTun avoids O(n) scan.
	packed := binary.BigEndian.Uint32(ip.To4())
	s.ipIndex.Store(packed, cs)

	// Build 10-byte response: ctlAssign + ip[4] + prefixLen[1] + gw[4]
	resp := make([]byte, 1+ctlAssignPayloadLen)
	resp[0] = ctlAssign
	ip4 := ip.To4()
	copy(resp[1:5], ip4)
	resp[5] = byte(s.pool.prefixLen())
	gw := s.pool.serverIP().To4()
	copy(resp[6:10], gw)

	if _, err := stream.Write(resp); err != nil {
		return fmt.Errorf("write assign response: %w", err)
	}

	s.logger.Info("assigned IP", "id", cs.id, "ip", ip.String())

	// Fire push notification for new connection (non-blocking).
	if s.notifSvc != nil {
		s.notifSvc.NotifySessionConnected(cs.id, ip.String())
	}

	return nil
}

// handleDataStream relays data between the stream and the TUN device.
func (s *Server) handleDataStream(ctx context.Context, cs *clientSession, stream *transport.Stream) {
	cs.dataStream.Store(stream)

	defer func() {
		cs.dataStream.CompareAndSwap(stream, nil)
		stream.Close()
	}()

	// stream.Read() blocks until data arrives or the mux/conn is closed.
	// Context cancellation closes the mux (see handleConn defer), which
	// unblocks Read() with an error — no per-iteration select needed.
	//
	// Borrow a 64 KB buffer from the pool to avoid one heap allocation per
	// session (streamReadBufPool, PERF IMPROVEMENT 2).
	bp := streamReadBufPool.Get().(*[]byte)
	buf := *bp
	defer streamReadBufPool.Put(bp)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			return
		}
		if n < 20 {
			// Too short to be a valid IPv4 packet
			continue
		}

		// tun.Write is a synchronous syscall; buf is safe to reuse after it returns.
		cs.bytesIn.Add(uint64(n))
		s.tun.Write(buf[:n]) //nolint:errcheck
	}
}

// tunReadBufPool pools the 64 KB TUN read buffers used in routeFromTun.
// Consistent with streamReadBufPool pattern — avoids a 64 KB heap allocation
// that lives for the lifetime of the server. When routeFromTun restarts
// (e.g. TUN reopen), the buffer returns to the pool instead of being GC'd.
var tunReadBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 65536)
		return &b
	},
}

// routeFromTun reads packets from the TUN device and routes them to clients.
// Termination: the Run() goroutine closes the TUN device when ctx is cancelled,
// which causes tun.Read() to return an error and this loop to exit.
func (s *Server) routeFromTun(ctx context.Context) {
	// Pin this goroutine to a dedicated OS thread to avoid scheduler preemption
	// on the hot TUN→client forwarding path. Without this, Go's cooperative
	// scheduler can pause this goroutine mid-packet-burst to run other goroutines,
	// introducing up to 10 ms jitter at high packet rates.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	bp := tunReadBufPool.Get().(*[]byte)
	buf := *bp
	defer tunReadBufPool.Put(bp)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			// Normal shutdown path: ctx cancelled → TUN closed → read error.
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Warn("tun read error", "err", err)
				continue
			}
		}
		if n < 20 {
			continue
		}

		// Lock-free O(1) lookup via sync.Map (read-optimised for the hot path).
		dstKey := binary.BigEndian.Uint32(buf[16:20])
		val, ok := s.ipIndex.Load(dstKey)
		if !ok {
			continue
		}
		target := val.(*clientSession)

		ds := target.dataStream.Load()
		if ds == nil {
			continue
		}

		// ds.Write → mux.writeFrame already copies payload into a frame buffer,
		// so we can pass buf[:n] directly without an extra allocation.
		if _, err := ds.Write(buf[:n]); err == nil {
			target.bytesOut.Add(uint64(n))
		}
	}
}

// doNoiseHandshake performs the server-side Noise_XX handshake over conn.
func (s *Server) doNoiseHandshake(conn net.Conn) (*crypto.Session, error) {
	hs, err := crypto.NewHandshake(crypto.Responder, s.staticKP)
	if err != nil {
		return nil, fmt.Errorf("noise: new handshake: %w", err)
	}

	// Read message 1
	msg1, err := readHandshakeMsg(conn)
	if err != nil {
		return nil, fmt.Errorf("noise: read msg1: %w", err)
	}
	if err := hs.ReadMessage1(msg1); err != nil {
		return nil, fmt.Errorf("noise: process msg1: %w", err)
	}

	// Write message 2
	msg2, err := hs.WriteMessage2()
	if err != nil {
		return nil, fmt.Errorf("noise: write msg2: %w", err)
	}
	if err := writeHandshakeMsg(conn, msg2); err != nil {
		return nil, fmt.Errorf("noise: send msg2: %w", err)
	}

	// Read message 3
	msg3, err := readHandshakeMsg(conn)
	if err != nil {
		return nil, fmt.Errorf("noise: read msg3: %w", err)
	}
	session, err := hs.ReadMessage3(msg3)
	if err != nil {
		return nil, fmt.Errorf("noise: process msg3: %w", err)
	}

	return session, nil
}

// isKeyAllowed returns true if the key is permitted or no allowlist is configured.
func (s *Server) isKeyAllowed(key [32]byte) bool {
	if len(s.allowedKeys) == 0 {
		return true
	}
	_, ok := s.allowedKeys[key]
	return ok
}

// nextSessionID returns the next monotonically increasing session ID.
func (s *Server) nextSessionID() uint64 {
	s.nextIDMu.Lock()
	defer s.nextIDMu.Unlock()
	id := s.nextID
	s.nextID++
	return id
}

// readHandshakeMsg reads a length-prefixed handshake message (2-byte big-endian length).
func readHandshakeMsg(conn net.Conn) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read handshake length: %w", err)
	}
	length := binary.BigEndian.Uint16(lenBuf[:])
	if length == 0 || int(length) > noiseHandshakeMsgMaxSize {
		return nil, fmt.Errorf("handshake message size %d out of range", length)
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, fmt.Errorf("read handshake payload: %w", err)
	}
	return msg, nil
}

// writeHandshakeMsg writes a length-prefixed handshake message (2-byte big-endian length).
// Header and payload are combined into a single slice so the kernel sends them
// in one TCP segment instead of two, halving the handshake RTTs.
func writeHandshakeMsg(conn net.Conn, msg []byte) error {
	if len(msg) > noiseHandshakeMsgMaxSize {
		return fmt.Errorf("handshake message too large: %d", len(msg))
	}
	frame := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(msg)))
	copy(frame[2:], msg)
	if _, err := conn.Write(frame); err != nil {
		return fmt.Errorf("write handshake frame: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// noiseConn — encrypts/decrypts data using a Noise Session
// ---------------------------------------------------------------------------

// maxNoiseFrame is the largest ciphertext we will ever read in one frame:
// 65535 payload + 16-byte ChaCha20-Poly1305 AEAD tag.
const maxNoiseFrame = 65535 + 16

// streamReadBufPool pools the 64 KB read buffers used in handleDataStream.
// Each VPN session requires one buffer for its lifetime (~65536 bytes).
// Pooling eliminates the GC pressure of allocating and freeing these large
// slices when sessions connect/disconnect frequently (e.g. mobile clients).
// PERF IMPROVEMENT 2: pool 64 KB stream read buffers to reduce GC churn.
var streamReadBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 65536)
		return &b
	},
}

// noiseWritePool pools the length-prefixed frame buffers used in
// noiseConn.Write, eliminating one make() per transmitted packet.
// Capacity: 2 (length) + 7 (mux hdr) + 1460 (MTU) + 16 (AEAD tag) = 1485.
// Rounded up to 1536 (power-of-2 friendly) to avoid reallocation for
// slightly oversized packets.
var noiseWritePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 1536)
		return &b
	},
}

// noiseConn wraps a net.Conn with Noise session encryption.
type noiseConn struct {
	conn    net.Conn
	session *crypto.Session
	readBuf []byte
	// recvBuf is a fixed-size scratch buffer reused for every Read call,
	// eliminating per-packet heap allocations (≈800 allocs/s at 10 Mbps).
	recvBuf [maxNoiseFrame]byte
	// decryptBuf is a pre-allocated destination buffer for AEAD decryption,
	// eliminating the make() call inside aead.Open on every received packet.
	decryptBuf [65535]byte
}

// newNoiseConn creates a noiseConn wrapping conn with the given session.
func newNoiseConn(conn net.Conn, session *crypto.Session) *noiseConn {
	return &noiseConn{conn: conn, session: session}
}

// Write encrypts p and writes it with a 2-byte big-endian length prefix.
// Length prefix and ciphertext are combined into one slice so that ObfsConn
// wraps them in a single TLS record. This halves the number of TLS records
// the Python client must read per message, doubling download throughput.
//
// Optimisation: EncryptTo writes ciphertext directly into the pool frame
// buffer at offset 2, eliminating both the intermediate ciphertext allocation
// and the copy. Saves 2 allocations + 1 copy per packet.
func (nc *noiseConn) Write(p []byte) (int, error) {
	// Borrow a frame buffer from the pool.
	ctLen := len(p) + 16 // plaintext + AEAD tag
	need := 2 + ctLen
	bp := noiseWritePool.Get().(*[]byte)
	if cap(*bp) < need {
		*bp = make([]byte, need)
	}
	frame := (*bp)[:need]

	// Encrypt directly into frame[2:], skipping the length prefix.
	ciphertext, err := nc.session.SendCipher.EncryptTo(frame[2:2], p, nil)
	if err != nil {
		noiseWritePool.Put(bp)
		return 0, fmt.Errorf("noiseConn encrypt: %w", err)
	}
	binary.BigEndian.PutUint16(frame[:2], uint16(len(ciphertext)))

	_, err = nc.conn.Write(frame[:2+len(ciphertext)])
	noiseWritePool.Put(bp)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read decrypts the next frame into p.
func (nc *noiseConn) Read(p []byte) (int, error) {
	// Drain buffered remainder first.
	if len(nc.readBuf) > 0 {
		n := copy(p, nc.readBuf)
		nc.readBuf = nc.readBuf[n:]
		return n, nil
	}

	// Read 2-byte length prefix into the start of the reusable buffer so we
	// avoid a separate stack allocation.
	if _, err := io.ReadFull(nc.conn, nc.recvBuf[:2]); err != nil {
		return 0, err
	}
	frameLen := int(binary.BigEndian.Uint16(nc.recvBuf[:2]))
	if frameLen > maxNoiseFrame {
		return 0, fmt.Errorf("noiseConn: frame too large (%d)", frameLen)
	}

	// Read the encrypted frame into the reusable buffer — zero allocation.
	if _, err := io.ReadFull(nc.conn, nc.recvBuf[:frameLen]); err != nil {
		return 0, err
	}

	// Decrypt into pre-allocated buffer — zero allocation per packet.
	plaintext, err := nc.session.RecvCipher.DecryptTo(nc.decryptBuf[:], nc.recvBuf[:frameLen], nil)
	if err != nil {
		return 0, fmt.Errorf("noiseConn decrypt: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		// Rare: caller's buffer smaller than one decrypted packet.
		nc.readBuf = append(nc.readBuf[:0], plaintext[n:]...)
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
// ipPool — allocates client IPs from a CIDR subnet
// ---------------------------------------------------------------------------

type ipPool struct {
	mu      sync.Mutex
	network *net.IPNet
	server  net.IP
	used    map[uint32]bool
}

// newIPPool parses cidr and returns an ipPool. The host address in cidr is the
// server IP and is pre-marked as used along with the network address.
func newIPPool(cidr string) (*ipPool, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("ipPool: parse CIDR %q: %w", cidr, err)
	}

	serverIP := ip.To4()
	if serverIP == nil {
		return nil, errors.New("ipPool: only IPv4 CIDRs are supported")
	}

	p := &ipPool{
		network: network,
		server:  cloneIP(serverIP),
		used:    make(map[uint32]bool),
	}

	// Pre-mark network address and server address as used.
	networkAddr := network.IP.To4()
	if networkAddr != nil {
		p.used[ipToUint32(networkAddr)] = true
	}
	p.used[ipToUint32(serverIP)] = true

	return p, nil
}

// allocate returns the next available IP in the subnet.
func (p *ipPool) allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Iterate subnet starting from network address + 1
	current := cloneIP(p.network.IP.To4())
	incrementIP(current)

	for p.network.Contains(current) {
		if isBroadcast(current, p.network) {
			break
		}
		key := ipToUint32(current)
		if !p.used[key] {
			p.used[key] = true
			return cloneIP(current), nil
		}
		incrementIP(current)
	}
	return nil, errors.New("ipPool: address space exhausted")
}

// release marks ip as available again.
func (p *ipPool) release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ip4 := ip.To4()
	if ip4 != nil {
		delete(p.used, ipToUint32(ip4))
	}
}

// serverIP returns the server's IP address in the subnet.
func (p *ipPool) serverIP() net.IP {
	return cloneIP(p.server)
}

// prefixLen returns the network prefix length.
func (p *ipPool) prefixLen() int {
	ones, _ := p.network.Mask.Size()
	return ones
}

// ipToUint32 converts a 4-byte IPv4 address to a uint32.
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

// cloneIP returns a 4-byte copy of ip.
func cloneIP(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	out := make(net.IP, 4)
	copy(out, ip4)
	return out
}

// incrementIP increments ip in place (big-endian).
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// isBroadcast returns true if ip is the broadcast address for network.
func isBroadcast(ip net.IP, network *net.IPNet) bool {
	ip4 := ip.To4()
	netIP := network.IP.To4()
	mask := network.Mask
	if ip4 == nil || netIP == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if ip4[i] != netIP[i]|^mask[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Key pair loading / generation
// ---------------------------------------------------------------------------

// loadOrGenerateKeyPair loads a hex-encoded private key from path, or generates
// and saves a new one if the file does not exist.
func loadOrGenerateKeyPair(path string, logger *slog.Logger) (*crypto.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("loadOrGenerateKeyPair: read %s: %w", path, err)
		}

		// Generate new key pair.
		kp, genErr := crypto.GenerateKeyPair()
		if genErr != nil {
			return nil, fmt.Errorf("loadOrGenerateKeyPair: generate: %w", genErr)
		}

		hexKey := hex.EncodeToString(kp.PrivateKey[:])
		if writeErr := os.WriteFile(path, []byte(hexKey), 0600); writeErr != nil {
			return nil, fmt.Errorf("loadOrGenerateKeyPair: write %s: %w", path, writeErr)
		}

		logger.Info("generated new key pair", "path", path, "public_key", hex.EncodeToString(kp.PublicKey[:]))
		return kp, nil
	}

	// Load existing private key.
	hexStr := strings.TrimSpace(string(data))
	privBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("loadOrGenerateKeyPair: decode hex from %s: %w", path, err)
	}
	if len(privBytes) != crypto.KeySize {
		return nil, fmt.Errorf("loadOrGenerateKeyPair: private key must be %d bytes, got %d", crypto.KeySize, len(privBytes))
	}

	kp := &crypto.KeyPair{}
	copy(kp.PrivateKey[:], privBytes)

	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("loadOrGenerateKeyPair: compute public key: %w", err)
	}
	copy(kp.PublicKey[:], pub)

	logger.Info("loaded key pair", "path", path, "public_key", hex.EncodeToString(kp.PublicKey[:]))
	return kp, nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func init() {
	// Increase GC target to 200% (default 100%). VPN server is latency-sensitive
	// and benefits more from fewer GC pauses than from lower memory usage.
	// This approximately halves GC frequency. The memory trade-off is acceptable:
	// even at 100 sessions the server uses <100 MB heap.
	if os.Getenv("GOGC") == "" {
		os.Setenv("GOGC", "200") //nolint:errcheck
	}
	// GOMEMLIMIT: let Go's soft memory limit auto-tune; don't set a hard limit
	// since the server runs dedicated.
}

func main() {
	cfg := DefaultConfig()
	apiCfg := api.DefaultConfig()

	flag.StringVar(&cfg.ListenAddr, "addr", cfg.ListenAddr, "listen address")
	flag.StringVar(&cfg.TunCIDR, "tun-cidr", cfg.TunCIDR, "TUN CIDR (e.g. 10.8.0.1/24)")
	flag.StringVar(&cfg.PrivKeyFile, "privkey", cfg.PrivKeyFile, "path to hex-encoded private key file")
	flag.StringVar(&apiCfg.ListenAddr, "api-addr", apiCfg.ListenAddr, "REST API listen address (empty to disable)")
	flag.StringVar(&apiCfg.APIToken, "api-token", "", "Bearer token for the REST API (empty disables auth)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	kp, err := loadOrGenerateKeyPair(cfg.PrivKeyFile, logger)
	if err != nil {
		logger.Error("failed to load key pair", "err", err)
		os.Exit(1)
	}

	// Apply kernel tuning (sysctl) before opening sockets.
	// Ensures rmem_max/wmem_max allow 16 MB buffers, enables BBR globally,
	// enables IP forwarding, and sets optimal TCP memory parameters.
	applySysctls()

	tun, err := OpenTun("vpn0")
	if err != nil {
		logger.Error("failed to open TUN device", "err", err)
		os.Exit(1)
	}
	defer tun.Close()

	if err := ConfigureTun("vpn0", cfg.TunCIDR); err != nil {
		// Non-fatal: the interface may already be configured (e.g. after restart),
		// or the admin may prefer to configure it manually via netsh / ip commands.
		logger.Warn("TUN configuration failed — interface may need manual setup", "err", err)
	}

	srv, err := NewServer(cfg, kp, tun, nil, logger)
	if err != nil {
		logger.Error("failed to create server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startAPIServer(ctx, apiCfg, srv, logger)

	if err := srv.Run(ctx); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

// startAPIServer launches the REST management API in a background goroutine.
// If cfg.ListenAddr is empty the API is not started.
func startAPIServer(ctx context.Context, cfg api.Config, srv *Server, logger *slog.Logger) {
	if cfg.ListenAddr == "" {
		return
	}
	// Create the push notification service and attach it to the server so that
	// session connect/disconnect events trigger push alerts.
	notifSvc := notify.NewNotificationService(logger)
	srv.notifSvc = notifSvc

	apiSrv := api.NewAPIServer(cfg, srv, logger)
	// Enable QR code generation using the server's public key and listen address.
	apiSrv.SetQRServer(srv)
	// Enable push notification subscription management via the REST API.
	apiSrv.SetNotificationService(notifSvc)

	go func() {
		<-ctx.Done()
		notifSvc.Stop()
	}()

	go func() {
		if err := apiSrv.Run(ctx); err != nil {
			logger.Error("api server error", "err", err)
		}
	}()
}
