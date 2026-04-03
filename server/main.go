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
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"


	"golang.org/x/crypto/curve25519"

	"github.com/cavad93/vpn/server/api"
	"github.com/cavad93/vpn/server/crypto"
	"github.com/cavad93/vpn/server/notify"
	"github.com/cavad93/vpn/server/perf"
	"github.com/cavad93/vpn/server/transport"
)

// Control message type constants.
const (
	ctlHello            = uint8(0x01) // client→server: request IP assignment
	ctlAssign           = uint8(0x02) // server→client: IP assignment response
	ctlError            = uint8(0xFF) // server→client: error
	ctlSecondary        = uint8(0x03) // client→server: attach secondary download connection
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

// streamBond distributes download traffic across multiple parallel TCP
// connections. Each connection has its own TCP congestion window; the
// aggregate throughput ≈ N × per-connection throughput. With 0.7% packet
// loss limiting each connection to ~1.7 Mbps, 8 connections yield ~14 Mbps.
type streamBond struct {
	mu   sync.Mutex
	list []*transport.Stream
	idx  int
}

func (sb *streamBond) add(s *transport.Stream) {
	sb.mu.Lock()
	sb.list = append(sb.list, s)
	sb.mu.Unlock()
}

func (sb *streamBond) remove(s *transport.Stream) {
	sb.mu.Lock()
	for i, st := range sb.list {
		if st == s {
			sb.list = append(sb.list[:i], sb.list[i+1:]...)
			break
		}
	}
	sb.mu.Unlock()
}

// next returns the next stream in round-robin order, or nil if empty.
func (sb *streamBond) next() *transport.Stream {
	sb.mu.Lock()
	n := len(sb.list)
	if n == 0 {
		sb.mu.Unlock()
		return nil
	}
	s := sb.list[sb.idx%n]
	sb.idx++
	sb.mu.Unlock()
	return s
}

// count returns the number of bonded streams.
func (sb *streamBond) count() int {
	sb.mu.Lock()
	n := len(sb.list)
	sb.mu.Unlock()
	return n
}

// clientSession holds per-client runtime state.
type clientSession struct {
	id           uint64
	remoteKey    [32]byte
	noiseSession *crypto.Session
	mux          *transport.Mux
	rawConn      net.Conn // underlying TCP connection for TCP_INFO polling
	assignedIP   net.IP
	bond         streamBond // round-robin across parallel download connections
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
	// Perf is the performance metrics collector. When non-nil, hot-path
	// instrumentation records latency histograms and packet counters.
	Perf *perf.Collector
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
		// Increase TCP socket buffers to match the bandwidth-delay product.
		// Russia↔Kazakhstan real RTT ≈ 919ms (measured, not the original 80ms
		// assumption). With 32 bond connections the per-connection share is:
		//   BDP = 100 Mbps × 0.919s / 32 ≈ 360 KB.
		// We use 4 MB (11× headroom) so that burst recovery after a loss event
		// doesn't starve the congestion window. Previously 16 MB caused latency
		// to spike (80ms → 321ms due to bufferbloat); 4 MB is the safe ceiling.
		// setForcedSocketBuffers uses SO_RCVBUFFORCE/SO_SNDBUFFORCE on Linux
		// (requires CAP_NET_ADMIN) to bypass net.core.rmem_max.
		if tc, ok := conn.(*net.TCPConn); ok {
			setForcedSocketBuffers(tc, 4<<20) // 4 MB per bond connection
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
// Supports both primary connections (new session + IP assignment) and
// secondary connections (attach additional download stream to existing session
// for multi-connection bonding).
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// TLS obfuscation handshake
	obfs := transport.NewObfsConn(conn)
	if err := obfs.ServerHandshake(); err != nil {
		s.logger.Warn("obfs handshake failed", "err", err)
		return
	}

	// Noise_XX handshake (with perf tracking)
	var hsStart time.Time
	if s.Perf != nil {
		hsStart = time.Now()
	}
	session, err := s.doNoiseHandshake(obfs)
	if err != nil {
		s.logger.Warn("noise handshake failed", "err", err)
		return
	}
	if s.Perf != nil {
		s.Perf.TrackLatency(perf.StageHandshake, time.Since(hsStart))
	}

	// Check if this key is allowed
	if !s.isKeyAllowed(session.RemoteStatic) {
		s.logger.Warn("key not allowed", "key", hex.EncodeToString(session.RemoteStatic[:]))
		return
	}

	// Wrap in encrypted noise conn
	nc := newNoiseConn(obfs, session)
	if s.Perf != nil {
		nc.withPerf(s.Perf)
	}

	// Create mux (server = not client)
	mux := transport.NewMux(nc, false)

	// Accept first stream to peek at connection type.
	firstStream, err := mux.AcceptStream(ctx)
	if err != nil {
		mux.Close()
		return
	}

	var typeBuf [1]byte
	if _, err := io.ReadFull(firstStream, typeBuf[:]); err != nil {
		firstStream.Close()
		mux.Close()
		return
	}

	switch typeBuf[0] {
	case ctlHello:
		s.runPrimaryConn(ctx, conn, session, firstStream, mux)
	case ctlSecondary:
		s.runSecondaryConn(ctx, session.RemoteStatic, firstStream, mux)
	default:
		s.logger.Warn("unknown ctl type", "type", typeBuf[0])
		firstStream.Close()
		mux.Close()
	}
}

// runPrimaryConn handles a primary VPN connection: creates a session,
// assigns an IP, and runs the data stream loop.
func (s *Server) runPrimaryConn(ctx context.Context, rawConn net.Conn, session *crypto.Session, ctlStream *transport.Stream, mux *transport.Mux) {
	connCtx, cancel := context.WithCancel(ctx)
	cs := &clientSession{
		id:           s.nextSessionID(),
		remoteKey:    session.RemoteStatic,
		noiseSession: session,
		mux:          mux,
		rawConn:      rawConn, // underlying TCP connection for TCP_INFO polling
		connectedAt:  time.Now(),
		cancel:       cancel,
	}

	// If this client key already has an active session, close it first.
	// This prevents IP pool exhaustion when a client reconnects without
	// cleanly closing the previous connection (e.g. Android app crash,
	// network switch, or routing loop causing rapid reconnects).
	s.mu.Lock()
	for id, existing := range s.sessions {
		if existing.remoteKey == session.RemoteStatic && id != cs.id {
			s.logger.Info("replacing existing session for same key",
				"old_id", id, "new_id", cs.id)
			existing.cancel()
		}
	}
	s.sessions[cs.id] = cs
	s.mu.Unlock()

	defer func() {
		cancel()
		mux.Close()
		if s.Perf != nil {
			s.Perf.ActiveSessions.Add(-1)
		}
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
		s.logger.Info("session closed", "id", cs.id, "bonds", cs.bond.count())
		if s.notifSvc != nil && assignedIP != "" {
			s.notifSvc.NotifySessionDisconnected(cs.id, assignedIP)
		}
	}()

	if s.Perf != nil {
		s.Perf.ActiveSessions.Add(1)
		s.Perf.TotalSessions.Add(1)
	}
	s.logger.Info("new session", "id", cs.id, "key", hex.EncodeToString(session.RemoteStatic[:]))

	// Handle IP assignment via the control stream (ctlHello already consumed).
	if err := s.handleControlStream(ctx, cs, ctlStream); err != nil {
		s.logger.Warn("control stream error", "id", cs.id, "err", err)
		return
	}

	// Accept data streams.
	for {
		stream, err := mux.AcceptStream(connCtx)
		if err != nil {
			return
		}
		go s.handleDataStream(connCtx, cs, stream)
	}
}

// runSecondaryConn handles a secondary (bonded) connection. It attaches
// a new data stream to an existing primary session, giving it an additional
// TCP connection with its own congestion window.
func (s *Server) runSecondaryConn(ctx context.Context, clientKey [32]byte, ctlStream *transport.Stream, mux *transport.Mux) {
	defer mux.Close()

	// Read 4-byte assigned IP from the secondary handshake.
	var ipBuf [4]byte
	if _, err := io.ReadFull(ctlStream, ipBuf[:]); err != nil {
		ctlStream.Close()
		return
	}

	// Find existing session by IP.
	packed := binary.BigEndian.Uint32(ipBuf[:])
	val, ok := s.ipIndex.Load(packed)
	if !ok {
		ctlStream.Write([]byte{ctlError}) //nolint:errcheck
		ctlStream.Close()
		s.logger.Warn("secondary: no session for IP", "ip", net.IP(ipBuf[:]).String())
		return
	}
	cs := val.(*clientSession)

	// Verify the Noise key matches the primary session's key.
	if cs.remoteKey != clientKey {
		ctlStream.Write([]byte{ctlError}) //nolint:errcheck
		ctlStream.Close()
		s.logger.Warn("secondary: key mismatch")
		return
	}

	// Acknowledge the secondary attachment.
	if _, err := ctlStream.Write([]byte{ctlAssign}); err != nil {
		ctlStream.Close()
		return
	}
	ctlStream.Close()

	s.logger.Info("secondary attached", "id", cs.id, "bonds", cs.bond.count()+1)

	// Accept the data stream from this secondary connection.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	dataStream, err := mux.AcceptStream(connCtx)
	if err != nil {
		return
	}
	s.handleDataStream(connCtx, cs, dataStream)
}

// handleControlStream processes the control stream for IP assignment.
// The ctlHello type byte has already been consumed by handleConn.
func (s *Server) handleControlStream(ctx context.Context, cs *clientSession, stream *transport.Stream) error {
	defer stream.Close()

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
	cs.bond.add(stream)

	defer func() {
		cs.bond.remove(stream)
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
	pc := s.Perf // local copy avoids nil check in hot loop when perf is nil

	// Poll TCP info every 5 seconds from the underlying TCP connection.
	// This updates RTT, retransmit and cwnd metrics visible in diagnostics.
	if pc != nil && cs.rawConn != nil {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		go func() {
			for {
				select {
				case <-ticker.C:
					pollTCPInfo(cs.rawConn, pc)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	for {
		var ingressStart time.Time
		if pc != nil {
			ingressStart = time.Now()
		}

		var muxReadStart time.Time
		if pc != nil {
			muxReadStart = time.Now()
		}
		n, err := stream.Read(buf)
		if pc != nil {
			pc.TrackLatency(perf.StageMuxRead, time.Since(muxReadStart))
			pc.TrackPacket(perf.StageMuxRead, n)
		}
		if err != nil {
			return
		}
		if n < 20 {
			// Too short to be a valid IPv4 packet
			continue
		}

		if pc != nil {
			t0 := time.Now()
			s.tun.Write(buf[:n]) //nolint:errcheck
			pc.TrackLatency(perf.StageTunWrite, time.Since(t0))
			pc.TrackPacket(perf.StageTunWrite, n)
			pc.TrackLatency(perf.StageFullIngress, time.Since(ingressStart))
			pc.TrackPacket(perf.StageFullIngress, n)
		} else {
			s.tun.Write(buf[:n]) //nolint:errcheck
		}
		cs.bytesIn.Add(uint64(n))
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
	pc := s.Perf // local copy for hot loop
	for {
		var t0 time.Time
		if pc != nil {
			t0 = time.Now()
		}
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
		if pc != nil {
			pc.TrackLatency(perf.StageTunRead, time.Since(t0))
			pc.TrackPacket(perf.StageTunRead, n)
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

		// Round-robin across bonded streams (multiple TCP connections).
		bond := &target.bond
		tried := bond.count()
		sent := false
		for i := 0; i < tried; i++ {
			ds := bond.next()
			if ds == nil {
				break
			}
			var muxWriteStart time.Time
			if pc != nil {
				muxWriteStart = time.Now()
			}
			if _, err := ds.Write(buf[:n]); err == nil {
				if pc != nil {
					pc.TrackLatency(perf.StageMuxWrite, time.Since(muxWriteStart))
					pc.TrackPacket(perf.StageMuxWrite, n)
				}
				target.bytesOut.Add(uint64(n))
				sent = true
				break
			}
		}
		if pc != nil {
			pc.TrackLatency(perf.StageFullEgress, time.Since(t0))
			pc.TrackPacket(perf.StageFullEgress, n)
		}
		_ = sent
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

// Size-class buffer pools for noiseConn.Write. Most VPN packets are ≤1500
// bytes (Ethernet MTU), so the small pool handles the common case with a
// tight 1536-byte buffer. Large packets (e.g. jumbo frames, control
// messages) use the large pool (68 KB) to avoid reallocation.
//
// Why two pools: a single 68 KB pool wastes memory for the 99% of packets
// that fit in 1.5 KB. Two size classes reduce steady-state memory by ~45×
// per pooled buffer while keeping the hot path allocation-free.
var noiseWritePoolSmall = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 1536) // 2 + 1460 + 16 + headroom
		return &b
	},
}
var noiseWritePoolLarge = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 65536+18) // 2 + 65535 + 16 + 1
		return &b
	},
}

const noiseSmallThreshold = 1536 // packets ≤ this use the small pool

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
	// perf is an optional perf collector for latency tracking.
	perf *perf.Collector
}

// newNoiseConn creates a noiseConn wrapping conn with the given session.
func newNoiseConn(conn net.Conn, session *crypto.Session) *noiseConn {
	return &noiseConn{conn: conn, session: session}
}

// withPerf attaches a perf Collector for latency tracking.
func (nc *noiseConn) withPerf(pc *perf.Collector) *noiseConn {
	nc.perf = pc
	return nc
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
	var t0 time.Time
	if nc.perf != nil {
		t0 = time.Now()
	}
	// Borrow a frame buffer from the appropriate size-class pool.
	ctLen := len(p) + 16 // plaintext + AEAD tag
	need := 2 + ctLen
	var pool *sync.Pool
	if need <= noiseSmallThreshold {
		pool = &noiseWritePoolSmall
	} else {
		pool = &noiseWritePoolLarge
	}
	bp := pool.Get().(*[]byte)
	if cap(*bp) < need {
		*bp = make([]byte, need)
	}
	frame := (*bp)[:need]

	// Encrypt directly into frame[2:], skipping the length prefix.
	ciphertext, err := nc.session.SendCipher.EncryptTo(frame[2:2], p, nil)
	if err != nil {
		pool.Put(bp)
		return 0, fmt.Errorf("noiseConn encrypt: %w", err)
	}
	if nc.perf != nil {
		nc.perf.TrackLatency(perf.StageNoiseEnc, time.Since(t0))
		nc.perf.TrackPacket(perf.StageNoiseEnc, len(p))
	}
	binary.BigEndian.PutUint16(frame[:2], uint16(len(ciphertext)))

	frameSize := 2 + len(ciphertext)
	var obfsStart time.Time
	if nc.perf != nil {
		obfsStart = time.Now()
	}
	_, err = nc.conn.Write(frame[:frameSize])
	pool.Put(bp)
	if nc.perf != nil {
		nc.perf.TrackLatency(perf.StageObfsWrite, time.Since(obfsStart))
		nc.perf.TrackPacket(perf.StageObfsWrite, frameSize)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read decrypts the next frame into p.
//
// Optimisation: reads the entire noise frame (2-byte length + ciphertext) from
// ObfsConn in a single Read call instead of two separate io.ReadFull calls.
// Since noiseConn.Write always sends [length‖ciphertext] as one ObfsConn.Write,
// each TLS record contains exactly one complete noise frame. A single Read into
// the 65 KB recvBuf triggers ObfsConn's zero-alloc fast path (read directly
// into the caller's buffer without intermediate make([]byte)), eliminating one
// heap allocation per received packet.
func (nc *noiseConn) Read(p []byte) (int, error) {
	// Drain buffered remainder first.
	if len(nc.readBuf) > 0 {
		n := copy(p, nc.readBuf)
		nc.readBuf = nc.readBuf[n:]
		return n, nil
	}

	// Read the complete noise frame from ObfsConn in one call.
	// ObfsConn returns exactly one TLS record payload per Read, and each
	// record contains one complete noise frame [2-byte len ‖ ciphertext].
	// Passing the full recvBuf (65 KB) triggers ObfsConn's zero-alloc fast
	// path: the TLS payload is read directly into recvBuf without make().
	var obfsReadStart time.Time
	if nc.perf != nil {
		obfsReadStart = time.Now()
	}
	n, err := nc.conn.Read(nc.recvBuf[:])
	var procStart time.Time
	if nc.perf != nil {
		procStart = time.Now()
		// obfs_read_wait: time blocked waiting for data from the network.
		// This is dominated by TCP RTT and retransmission timeouts — the
		// single largest contributor to full_ingress latency (404ms mean).
		nc.perf.TrackLatency(perf.StageObfsReadWait, procStart.Sub(obfsReadStart))
	}
	if err != nil {
		return 0, err
	}
	if n < 2 {
		return 0, fmt.Errorf("noiseConn: frame too short (%d bytes)", n)
	}

	frameLen := int(binary.BigEndian.Uint16(nc.recvBuf[:2]))
	if frameLen == 0 || frameLen > maxNoiseFrame {
		return 0, fmt.Errorf("noiseConn: frame size %d out of range", frameLen)
	}

	// Common case: the entire ciphertext arrived in the same TLS record.
	// Rare fallback: read remaining bytes if the TLS record was short.
	have := n - 2
	if have < frameLen {
		if _, err := io.ReadFull(nc.conn, nc.recvBuf[n:2+frameLen]); err != nil {
			return 0, err
		}
	}
	if nc.perf != nil {
		// obfs_read_proc: time after first Read returns until decrypt starts.
		// Covers TLS record parsing and the rare ReadFull fallback path.
		nc.perf.TrackLatency(perf.StageObfsReadProc, time.Since(procStart))
		// obfs_read (total) kept for backwards compatibility.
		nc.perf.TrackLatency(perf.StageObfsRead, time.Since(obfsReadStart))
		nc.perf.TrackPacket(perf.StageObfsRead, n)
	}

	// Decrypt into pre-allocated buffer — zero allocation per packet.
	var decStart time.Time
	if nc.perf != nil {
		decStart = time.Now()
	}
	plaintext, err := nc.session.RecvCipher.DecryptTo(nc.decryptBuf[:], nc.recvBuf[2:2+frameLen], nil)
	if err != nil {
		return 0, fmt.Errorf("noiseConn decrypt: %w", err)
	}
	if nc.perf != nil {
		nc.perf.TrackLatency(perf.StageNoiseDec, time.Since(decStart))
		nc.perf.TrackPacket(perf.StageNoiseDec, frameLen)
	}

	nc2 := copy(p, plaintext)
	if nc2 < len(plaintext) {
		// Rare: caller's buffer smaller than one decrypted packet.
		// Zero-copy: sub-slice of decryptBuf, safe because decryptBuf
		// is not overwritten until the next decrypt (readBuf is drained first).
		nc.readBuf = plaintext[nc2:]
	}
	return nc2, nil
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
	//
	// debug.SetGCPercent is used instead of os.Setenv("GOGC") because the runtime
	// reads GOGC before init() runs — Setenv would be too late.
	debug.SetGCPercent(200)
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
	// Attach the performance metrics collector.
	srv.Perf = perf.NewCollector()

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
	// Enable performance metrics endpoints.
	if srv.Perf != nil {
		apiSrv.SetPerfCollector(srv.Perf)
	}

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
