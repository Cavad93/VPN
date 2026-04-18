// Package main implements the VPN server.
package main

import (
	"context"
	"crypto/rand"
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
	ctlAssign           = uint8(0x02) // server→client: IPv4-only IP assignment response
	ctlError            = uint8(0xFF) // server→client: error
	ctlSecondary        = uint8(0x03) // client→server: attach secondary download connection
	ctlAssignDual       = uint8(0x05) // server→client: dual-stack (IPv4+IPv6) assignment
	ctlAssignPayloadLen = 9           // 4(ip) + 1(prefix_len) + 4(gateway)
	// ctlAssignDualPayloadLen: ip4(4)+pfx4(1)+gw4(4)+ip6(16)+pfx6(1)+gw6(16) = 42 bytes.
	ctlAssignDualPayloadLen = 42

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
	ListenAddr      string
	TunCIDR         string
	Tun6CIDR        string // optional IPv6 CIDR for dual-stack, e.g. "fc00::1/120"; empty = disabled
	PrivKeyFile     string
	Transport       string // "tcp" (default) or "udp" (user-space BBR)
	AllowedKeysFile string // path to persist the allowed-keys list across restarts

	// BBR initial bandwidth seed (UDP transport only).
	// When both are non-zero, SetInitialBandwidth is called on each new
	// UDP connection so BBR skips the slow Startup phase and jumps directly
	// to ProbeBW. Zero values disable seeding (BBR runs its normal Startup).
	//
	// Set to the expected bottleneck bandwidth and RTT for your deployment:
	//   -bbr-seed-bw 6 -bbr-seed-rtt 78   # SPb→Astana (6 Mbps, 78ms)
	//   -bbr-seed-bw 50 -bbr-seed-rtt 20  # domestic (50 Mbps, 20ms)
	//   -bbr-seed-bw 0                     # disable — use BBR Startup
	BBRSeedBW  int // bottleneck bandwidth in Mbps (0 = disabled)
	BBRSeedRTT int // expected RTT in milliseconds (0 = disabled)
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:      "0.0.0.0:443",
		TunCIDR:         "10.8.0.1/24",
		PrivKeyFile:     "server_privkey.hex",
		Transport:       "udp",
		AllowedKeysFile: "allowed_keys.txt",
		// Seed BBR at the typical international VPN path parameters.
		// Avoids slow Startup (10+ RTTs) on reconnect for the common case.
		// Override with -bbr-seed-bw / -bbr-seed-rtt for your deployment.
		BBRSeedBW:  6,  // 6 Mbps — measured SPb→Astana bottleneck
		BBRSeedRTT: 78, // 78ms  — measured SPb→Astana RTT
	}
}

// SessionStats is an alias for api.SessionInfo — exported for compatibility.
type SessionStats = api.SessionInfo

// dataWriter is the minimal interface for writing IP packets to a client.
// Both *transport.Stream (Noise+Mux) and *vlessWriter (VLESS+WS) implement it.
type dataWriter interface {
	Write(p []byte) (int, error)
	Close() error
}

// streamBond distributes download traffic across multiple parallel TCP
// connections. Each connection has its own TCP congestion window; the
// aggregate throughput ≈ N × per-connection throughput. With 0.7% packet
// loss limiting each connection to ~1.7 Mbps, 8 connections yield ~14 Mbps.
//
// Lock-free read path (COW pattern):
//   - listPtr holds an immutable snapshot of the current stream slice.
//   - add/remove allocate a new slice, copy, and store atomically under writeMu.
//   - next/nextWithCount/count load the pointer without any mutex — zero
//     contention on the routeFromTun hot path (~2630 packets/sec at 30 Mbps).
//   - idx is a monotonic atomic counter; uint64 overflow wraps to 0 — safe
//     because uint64(x) % n is always ≥ 0 for any x when n > 0.
type streamBond struct {
	listPtr atomic.Pointer[[]dataWriter] // COW snapshot; nil pointer == empty
	idx     atomic.Uint64               // round-robin counter; never reset
	writeMu sync.Mutex                  // serialises add/remove writers only
}

func (sb *streamBond) add(s dataWriter) {
	sb.writeMu.Lock()
	var old []dataWriter
	if p := sb.listPtr.Load(); p != nil {
		old = *p
	}
	newList := make([]dataWriter, len(old)+1)
	copy(newList, old)
	newList[len(old)] = s
	sb.listPtr.Store(&newList)
	sb.writeMu.Unlock()
}

func (sb *streamBond) remove(s dataWriter) {
	sb.writeMu.Lock()
	var old []dataWriter
	if p := sb.listPtr.Load(); p != nil {
		old = *p
	}
	newList := make([]dataWriter, 0, len(old))
	for _, st := range old {
		if st != s {
			newList = append(newList, st)
		}
	}
	sb.listPtr.Store(&newList)
	sb.writeMu.Unlock()
}

// next returns the next stream in round-robin order, or nil if empty.
// Lock-free: reads listPtr atomically and increments idx atomically.
func (sb *streamBond) next() dataWriter {
	p := sb.listPtr.Load()
	if p == nil {
		return nil
	}
	list := *p
	n := uint64(len(list))
	if n == 0 {
		return nil
	}
	return list[(sb.idx.Add(1)-1)%n]
}

// nextWithCount returns the next stream in round-robin order together with the
// current bond size in a single atomic snapshot.
//
// Hot-path optimisation for routeFromTun: the naive approach calls count() to
// bound the retry loop and then next() for each attempt — 2 lock/unlock cycles
// per packet in the common case (single bonded stream, write succeeds).
// nextWithCount provides both in one atomic load + one atomic increment,
// paying zero mutex cost per IP packet routed from TUN to client.
//
// Thread safety: the returned total may be stale if streams are added or
// removed concurrently. The caller handles this by checking ds == nil before
// each write attempt.
func (sb *streamBond) nextWithCount() (s dataWriter, total int) {
	p := sb.listPtr.Load()
	if p == nil {
		return nil, 0
	}
	list := *p
	total = len(list)
	if total == 0 {
		return nil, 0
	}
	idx := sb.idx.Add(1) - 1
	s = list[idx%uint64(total)]
	return s, total
}

// count returns the number of bonded streams. Lock-free.
func (sb *streamBond) count() int {
	p := sb.listPtr.Load()
	if p == nil {
		return 0
	}
	return len(*p)
}

// congestionProber is implemented by transport.Conn (UDP+BBR mode).
// routeFromTun checks it before forwarding inner IP packets so that
// ECN CE can be marked proactively, synchronising the inner TCP CC.
type congestionProber interface {
	Congested() bool
}

// clientSession holds per-client runtime state.
type clientSession struct {
	id           uint64
	remoteKey    [32]byte
	noiseSession *crypto.Session
	mux          *transport.Mux
	rawConn      net.Conn         // underlying TCP/UDP connection
	congestion   congestionProber // non-nil in UDP+BBR mode only
	assignedIP   net.IP
	assignedIP6  net.IP // nil when server is IPv4-only (no -tun6-cidr)
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
	// ip6Index maps [16]byte IPv6 destination address → *clientSession.
	// Only populated when pool6 != nil (Tun6CIDR is configured).
	// Same read-heavy access pattern as ipIndex — sync.Map is optimal.
	ip6Index    sync.Map
	allowedKeys map[[32]byte]struct{}
	tun         TunDevice
	pool        *ipPool
	pool6       *ip6Pool // nil when Tun6CIDR is not configured
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

	if cfg.Tun6CIDR != "" {
		p6, err := newIP6Pool(cfg.Tun6CIDR)
		if err != nil {
			return nil, fmt.Errorf("server: invalid Tun6CIDR: %w", err)
		}
		s.pool6 = p6
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
	if s.cfg.Transport == "udp" {
		return s.runUDP(ctx)
	}
	return s.runTCP(ctx)
}

// runTCP starts the server over TCP (kernel congestion control).
func (s *Server) runTCP(ctx context.Context) error {
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
	s.logger.Info("server listening", "transport", "tcp", "addr", s.cfg.ListenAddr)

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
		setConnTTL64(conn) // Anti-fingerprint: TTL=64 (Linux) instead of 128 (Windows)
		if tc, ok := conn.(*net.TCPConn); ok {
			setForcedSocketBuffers(tc, 4<<20) // 4 MB per bond connection
			tc.SetNoDelay(true)               // disable Nagle — VPN packets must not be coalesced
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(15 * time.Second)
		}
		go func(c net.Conn) {
			// Peek at the first byte to distinguish VPN clients from probes.
			// TLS ClientHello starts with 0x16; anything else gets an HTTP decoy.
			routed, ok := peekAndRoute(c)
			if !ok {
				return // decoy served + conn closed inside peekAndRoute
			}
			s.handleConn(ctx, routed)
		}(conn)
	}
}

// runUDP starts the server over UDP with user-space BBR congestion control.
// This bypasses the OS TCP stack entirely — BBR runs inside the application,
// making it work on any OS including Windows Server 2019 (which lacks BBR).
//
// A TCP listener is started on the same address so that TCP-only clients
// (e.g. Android) can connect using the same ObfsConn/Noise/Mux pipeline.
// TCP connections go through peekAndRoute (DPI decoy) before handleConn.
func (s *Server) runUDP(ctx context.Context) error {
	ln, err := transport.ListenUDP(s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("server: listen udp %s: %w", s.cfg.ListenAddr, err)
	}
	s.logger.Info("server listening", "transport", "udp+bbr", "addr", s.cfg.ListenAddr)

	// Also accept TCP on the same address so TCP-only clients (Android) work.
	tcpLn, tcpErr := net.Listen("tcp", s.cfg.ListenAddr)
	if tcpErr != nil {
		s.logger.Warn("TCP listener on UDP port failed — TCP clients will not be able to connect",
			"addr", s.cfg.ListenAddr, "err", tcpErr)
	} else {
		s.logger.Info("server listening (TCP fallback for mobile clients)", "transport", "tcp", "addr", s.cfg.ListenAddr)
		go func() {
			<-ctx.Done()
			tcpLn.Close()
		}()
		go func() {
			for {
				conn, err := tcpLn.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						s.logger.Warn("tcp accept error", "err", err)
						continue
					}
				}
				setConnTTL64(conn)
				if tc, ok := conn.(*net.TCPConn); ok {
					setForcedSocketBuffers(tc, 4<<20)
					tc.SetNoDelay(true)
					tc.SetKeepAlive(true)
					tc.SetKeepAlivePeriod(15 * time.Second)
				}
				go func(c net.Conn) {
					routed, ok := peekAndRoute(c)
					if !ok {
						return
					}
					s.handleConn(ctx, routed)
				}(conn)
			}
		}()
	}

	go s.routeFromTun(ctx)

	go func() {
		<-ctx.Done()
		ln.Close()
		s.tun.Close()
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Warn("accept error", "err", err)
				continue
			}
		}
		// Seed BBR with the configured bandwidth/RTT so new connections skip
		// the slow Startup phase (10+ RTTs of exponential probing) and jump
		// directly to ProbeBW. Both fields must be non-zero to enable seeding.
		// If the real bottleneck differs, BBR self-corrects within 1-2 RTTs:
		//   • seed too high → probe phase → loss → cwnd converges down
		//   • seed too low  → ProbeBW 5/4 gain → BtlBw discovered quickly
		// Seeding is disabled when BBRSeedBW==0 or BBRSeedRTT==0.
		if s.cfg.BBRSeedBW > 0 && s.cfg.BBRSeedRTT > 0 {
			bwBytesPerSec := int64(s.cfg.BBRSeedBW) * 1_000_000 / 8
			rtt := time.Duration(s.cfg.BBRSeedRTT) * time.Millisecond
			conn.SetInitialBandwidth(bwBytesPerSec, rtt)
		}
		go s.handleConn(ctx, conn) //nolint:errcheck
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
// When transitioning to allowlist mode, all currently connected sessions are
// grandfathered in so they are not locked out on their next reconnect.
func (s *Server) AddAllowedKey(key [32]byte) {
	s.mu.Lock()
	if s.allowedKeys == nil {
		// Transitioning from open-access to allowlist mode: grandfather all
		// currently connected sessions so they aren't locked out immediately.
		s.allowedKeys = make(map[[32]byte]struct{}, len(s.sessions)+1)
		for _, cs := range s.sessions {
			s.allowedKeys[cs.remoteKey] = struct{}{}
		}
	}
	s.allowedKeys[key] = struct{}{}
	s.mu.Unlock()
	s.saveAllowedKeys()
}

// RemoveAllowedKey removes key from the allowlist.
func (s *Server) RemoveAllowedKey(key [32]byte) {
	s.mu.Lock()
	delete(s.allowedKeys, key)
	s.mu.Unlock()
	s.saveAllowedKeys()
}

// saveAllowedKeys writes the current allowlist to AllowedKeysFile atomically.
// A nil or empty allowlist (open-access mode) removes the file.
func (s *Server) saveAllowedKeys() {
	if s.cfg.AllowedKeysFile == "" {
		return
	}
	s.mu.RLock()
	keys := make([][32]byte, 0, len(s.allowedKeys))
	for k := range s.allowedKeys {
		keys = append(keys, k)
	}
	s.mu.RUnlock()

	if len(keys) == 0 {
		// Empty allowlist means open-access — remove the file so the next
		// restart stays in open-access mode.
		_ = os.Remove(s.cfg.AllowedKeysFile)
		return
	}

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(hex.EncodeToString(k[:]))
		sb.WriteByte('\n')
	}

	// Atomic write: write to a temp file then rename.
	tmp := s.cfg.AllowedKeysFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0600); err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to save allowed_keys", "err", err)
		}
		return
	}
	if err := os.Rename(tmp, s.cfg.AllowedKeysFile); err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to rename allowed_keys file", "err", err)
		}
	}
}

// loadAllowedKeysFile reads an allowed_keys file (one hex key per line).
// Returns nil if the file does not exist (open-access mode).
func loadAllowedKeysFile(path string) ([][32]byte, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read allowed_keys file: %w", err)
	}
	var keys [][32]byte
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("invalid key in allowed_keys file: %q", line)
		}
		var k [32]byte
		copy(k[:], b)
		keys = append(keys, k)
	}
	return keys, nil
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

	// Wrap raw TCP conn with write-coalescing buffer.
	// Batches multiple small Noise messages into fewer TCP segments,
	// reducing per-packet TCP/IP overhead (~40 bytes/segment) by ~40%.
	bufConn := transport.NewBufConn(conn)

	// TLS obfuscation handshake.
	// Failures are logged at DEBUG to avoid exposing VPN presence during
	// mass scanning. A real HTTPS server would not log every bad TLS
	// handshake at WARN level — and neither should we.
	obfs := transport.NewObfsConn(bufConn)
	if err := obfs.ServerHandshake(); err != nil {
		// Mimic real TLS server: send plaintext Alert(fatal, decode_error=50)
		// when the ClientHello cannot be parsed. This is what nginx/Apache do.
		sendPlaintextTLSAlert(conn, 0x02, 50)
		s.logger.Debug("obfs handshake failed", "err", err)
		return
	}

	// Noise_XX handshake (with perf tracking)
	var hsStart time.Time
	if s.Perf != nil {
		hsStart = time.Now()
	}
	session, err := s.doNoiseHandshake(obfs)
	if err != nil {
		// Mimic real TLS 1.3 server error: send "encrypted" post-handshake
		// records (EncryptedExtensions + Certificate + Finished) + fatal alert.
		// Since ServerHello + CCS were already sent, a real TLS server would
		// send encrypted records next. Our random-filled app_data records are
		// indistinguishable from real AEAD ciphertext on the wire.
		// (TrojanProbe, ScienceDirect 2024: servers that close without post-SH
		// records are fingerprinted as proxy/VPN.)
		sendTLS13FallbackRecords(bufConn)
		bufConn.Flush()
		s.logger.Debug("noise handshake failed", "err", err)
		return
	}
	if s.Perf != nil {
		s.Perf.TrackLatency(perf.StageHandshake, time.Since(hsStart))
	}

	// Check if this key is allowed.
	// No TLS fallback here: if Noise completed, the client already proved
	// it can speak the VPN protocol (has a valid keypair). TLS fallback is
	// only useful when Noise FAILS, making the server look like a broken TLS
	// endpoint to probes that never get past the TLS handshake phase.
	if !s.isKeyAllowed(session.RemoteStatic) {
		s.logger.Debug("key not allowed", "key", hex.EncodeToString(session.RemoteStatic[:]))
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
	// In UDP+BBR mode rawConn is a *transport.Conn which implements congestionProber.
	// This lets routeFromTun mark ECN CE in inner IP packets when the pipe is near full,
	// synchronising the inner TCP's CC with our BBR — avoiding independent double-CC reactions.
	var cp congestionProber
	if c, ok := rawConn.(congestionProber); ok {
		cp = c
	}
	cs := &clientSession{
		id:           s.nextSessionID(),
		remoteKey:    session.RemoteStatic,
		noiseSession: session,
		mux:          mux,
		rawConn:      rawConn,
		congestion:   cp,
		connectedAt:  time.Now(),
		cancel:       cancel,
	}

	// Register the new session.
	// NOTE: we intentionally allow multiple concurrent sessions with the same
	// static key.  A user may legitimately run the same key on several devices
	// (e.g. MacBook and Android both imported the same QR code).  Cancelling
	// the old session would disconnect the other device unexpectedly.
	//
	// Dead sessions clean up automatically: the mux keepalive loop sends a
	// FramePing every 15 s; a write failure closes the session and releases
	// the IP back to the pool.  IP exhaustion is not a concern for personal
	// VPN use (/24 = 254 addresses).
	//
	// If per-device isolation is required, generate a separate QR code
	// (and therefore a unique key) for each device via /api/v1/qr/generate.
	s.mu.Lock()
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
		if cs.assignedIP6 != nil {
			s.ip6Index.Delete(ipToKey16(cs.assignedIP6))
			s.pool6.release(cs.assignedIP6)
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

	// Allocate IPv4 address.
	ip, err := s.pool.allocate()
	if err != nil {
		stream.Write([]byte{ctlError}) //nolint:errcheck
		return fmt.Errorf("ip allocation failed: %w", err)
	}
	cs.assignedIP = ip

	// Register in O(1) reverse IP index so routeFromTun avoids O(n) scan.
	packed := binary.BigEndian.Uint32(ip.To4())
	s.ipIndex.Store(packed, cs)

	// Optionally allocate an IPv6 address when dual-stack is configured.
	// A failure here is non-fatal: the client falls back to IPv4-only.
	var ip6 net.IP
	if s.pool6 != nil {
		if a, err2 := s.pool6.allocate(); err2 == nil {
			ip6 = a
			cs.assignedIP6 = ip6
			s.ip6Index.Store(ipToKey16(ip6), cs)
		} else {
			s.logger.Warn("IPv6 address allocation failed, falling back to IPv4-only", "err", err2)
		}
	}

	var resp []byte
	if ip6 != nil {
		// Dual-stack response: ctlAssignDual(1) + ip4(4) + pfx4(1) + gw4(4) + ip6(16) + pfx6(1) + gw6(16)
		resp = make([]byte, 1+ctlAssignDualPayloadLen)
		resp[0] = ctlAssignDual
		copy(resp[1:5], ip.To4())
		resp[5] = byte(s.pool.prefixLen())
		copy(resp[6:10], s.pool.serverIP().To4())
		copy(resp[10:26], ip6.To16())
		resp[26] = byte(s.pool6.prefixLen())
		copy(resp[27:43], s.pool6.serverIP().To16())
	} else {
		// IPv4-only response: ctlAssign(1) + ip4(4) + pfx4(1) + gw4(4)
		resp = make([]byte, 1+ctlAssignPayloadLen)
		resp[0] = ctlAssign
		copy(resp[1:5], ip.To4())
		resp[5] = byte(s.pool.prefixLen())
		copy(resp[6:10], s.pool.serverIP().To4())
	}

	if _, err := stream.Write(resp); err != nil {
		return fmt.Errorf("write assign response: %w", err)
	}

	if ip6 != nil {
		s.logger.Info("assigned IP", "id", cs.id, "ip4", ip.String(), "ip6", ip6.String())
	} else {
		s.logger.Info("assigned IP", "id", cs.id, "ip", ip.String())
	}

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

// markECNCE marks the ECN field of an inner IP packet (IPv4 or IPv6) as
// Congestion Experienced (CE=11).
//
// It only modifies packets that advertise ECN-capable transport (ECT(0)=10 or
// ECT(1)=01); Non-ECT packets (00) and already-CE packets (11) are left
// unchanged.
//
// Purpose: Double-CC mitigation — when our BBR pipe is near-full
// (Congested()==true), marking CE in the inner IP header signals inner senders
// to reduce their rate, synchronising them with our BBR:
//
//   - Inner TCP senders: CE triggers RFC 3168 ECN-Echo in the next TCP ACK;
//     the TCP sender halves cwnd (just like a loss event) without actual loss.
//
//   - Inner QUIC senders (RFC 9000 §13.4): QUIC reads ECN bits from the IP
//     header via IP_RECVTOS / IPV6_RECVTCLASS.  When the CE counter in QUIC
//     ACK frames increases, the QUIC sender's congestion controller reduces its
//     rate.  This covers all QUIC/HTTP-3 traffic (YouTube, Google, Cloudflare)
//     running over both IPv4/UDP and IPv6/UDP without any additional handling —
//     markECNCE only touches the IP-layer ECN bits and leaves the UDP header
//     and QUIC payload completely unmodified.
//
// Implementation is transport-protocol-agnostic: only the two ECN bits in the
// IP header are changed; all bytes beyond the IP header are untouched.
//
// IPv4 header byte layout:
//
//	byte[0]   — version(4b) + IHL(4b)
//	byte[1]   — DSCP(6b) + ECN(2b): ECN bits 1-0; CE = 11
//	bytes[10-11] — header checksum (ones-complement, recomputed after marking)
//
// IPv6 header byte layout (RFC 8200 §3):
//
//	byte[0]   — version(4b, =6) + Traffic Class bits[7:4]
//	byte[1]   — Traffic Class bits[3:0] + Flow Label bits[19:16]
//	             TC = DSCP(6b) + ECN(2b); ECN bits are byte[1] bits[5:4]
//	             No header checksum → no recomputation needed.
func markECNCE(buf []byte, n int) {
	if n < 1 {
		return
	}
	switch buf[0] >> 4 {
	case 4:
		markECNCEv4(buf, n)
	case 6:
		markECNCEv6(buf, n)
	}
}

// markECNCEv4 is the IPv4-specific helper for markECNCE.
func markECNCEv4(buf []byte, n int) {
	if n < 20 {
		return // too short for IPv4 header
	}
	ecn := buf[1] & 0x03
	if ecn == 0x00 || ecn == 0x03 {
		return // Not-ECT or already CE: nothing to do
	}
	// ECT(0)=0x02 or ECT(1)=0x01 → set CE=0x03
	buf[1] = (buf[1] &^ 0x03) | 0x03

	// Recompute IPv4 header checksum over the variable-length header (IHL×4 bytes).
	// Full recomputation is simpler and safer than incremental RFC 1624 here:
	// the header is ≤60 bytes (≤15 16-bit words) so the loop is cheap.
	ihl := int(buf[0]&0x0F) * 4
	if ihl < 20 || ihl > n {
		return
	}
	buf[10] = 0
	buf[11] = 0
	var sum uint32
	for i := 0; i+1 < ihl; i += 2 {
		sum += uint32(buf[i])<<8 | uint32(buf[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	csum := ^uint16(sum)
	buf[10] = byte(csum >> 8)
	buf[11] = byte(csum)
}

// markECNCEv6 is the IPv6-specific helper for markECNCE.
//
// IPv6 Traffic Class layout within the first two header bytes:
//
//	byte[0] bits[3:0] = TC bits[7:4]  (DSCP high nibble)
//	byte[1] bits[7:4] = TC bits[3:0]  (DSCP low 2b + ECN 2b)
//	byte[1] bits[5:4] = ECN bits[1:0]
//
// Marking CE sets those two bits to 11 and leaves all other bits untouched.
// IPv6 has no header checksum, so no recalculation is required.
func markECNCEv6(buf []byte, n int) {
	if n < 40 {
		return // minimum IPv6 header is 40 bytes
	}
	// ECN occupies bits[5:4] of byte[1] (= TC bits[1:0]).
	ecn := (buf[1] >> 4) & 0x03
	if ecn == 0x00 || ecn == 0x03 {
		return // Not-ECT or already CE: nothing to do
	}
	// Set ECN=CE=11 by setting bits[5:4] of byte[1]; preserve DSCP and Flow Label.
	buf[1] = (buf[1] &^ 0x30) | 0x30
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

		// Determine IP version and look up the destination client session.
		// IPv4: header ≥ 20 bytes, dst at buf[16:20] (uint32 key in ipIndex).
		// IPv6: header ≥ 40 bytes, dst at buf[24:40] ([16]byte key in ip6Index).
		var target *clientSession
		switch buf[0] >> 4 {
		case 4:
			dstKey := binary.BigEndian.Uint32(buf[16:20])
			val, ok := s.ipIndex.Load(dstKey)
			if !ok {
				continue
			}
			target = val.(*clientSession)
		case 6:
			if n < 40 {
				continue
			}
			var dstKey [16]byte
			copy(dstKey[:], buf[24:40])
			val, ok := s.ip6Index.Load(dstKey)
			if !ok {
				continue
			}
			target = val.(*clientSession)
		default:
			continue
		}

		// Double-CC mitigation: if the outer VPN pipe is near-full (UDP+BBR mode),
		// mark ECN CE in the inner IP header so that the inner TCP sender reduces its
		// rate through RFC 3168 ECN-Echo instead of waiting for packet loss detection.
		// Only affects ECT-capable packets; Non-ECT and already-CE are unchanged.
		if target.congestion != nil && target.congestion.Congested() {
			markECNCE(buf, n)
		}

		// Round-robin across bonded streams (multiple TCP connections).
		// nextWithCount is used for the first attempt: it returns the next stream
		// AND the current bond size in a single mutex acquisition, saving one
		// lock/unlock cycle per packet vs the previous count()+next() pattern.
		bond := &target.bond
		ds, tried := bond.nextWithCount()
		sent := false
		for i := 0; ; i++ {
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
			// Write failed — try the next bonded stream (up to tried−1 more times).
			if i+1 >= tried {
				break
			}
			ds = bond.next()
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

// noiseReadTimeout is the maximum idle time before a noiseConn read is
// timed out and the connection is declared dead.
// Value = 8 × muxKeepaliveInterval (15s) → tolerates 7 dropped pings.
const noiseReadTimeout = 120 * time.Second

// noiseDeadlineIntervalNs controls how often noiseConn lazily refreshes
// the read deadline (stored in nanoseconds for atomic access from tests).
// Default: 60s — the effective dead-connection timeout is
// noiseReadTimeout − noiseDeadlineInterval = 60s minimum, still 4× the
// keepalive interval. Reducing this from per-packet to per-60s eliminates
// ~2630 SetReadDeadline runtime-poller calls/sec at 30 Mbps.
var noiseDeadlineIntervalNs atomic.Int64

func init() { noiseDeadlineIntervalNs.Store(int64(60 * time.Second)) }

func noiseDeadlineInterval() time.Duration {
	return time.Duration(noiseDeadlineIntervalNs.Load())
}

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
	// deadlineSetAt records when the read deadline was last refreshed.
	// Zero value → never set; triggers an immediate refresh on first Read.
	// The lazy refresh (once per noiseDeadlineInterval) eliminates
	// ~2630 SetReadDeadline calls/sec at 30 Mbps vs the prior per-packet approach.
	deadlineSetAt time.Time
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
	//
	// Timer ordering: obfs_read (outer) starts FIRST, then obfs_read_wait
	// (inner) starts SECOND. This prevents the timer inversion bug where
	// the subtimer could exceed its container.
	//
	// Read deadline: lazily refreshed once per noiseDeadlineInterval (60s)
	// rather than on every packet. At 30 Mbps (≈2630 reads/sec) this reduces
	// SetReadDeadline runtime-poller calls from 2630/sec to ≤1/60sec —
	// a ~150,000× reduction. The effective dead-connection timeout remains
	// noiseReadTimeout (120s); the minimum observable window shrinks to
	// noiseReadTimeout−noiseDeadlineInterval = 60s (still 4× keepalive).
	// The mux keepalive (FramePing every 15s) triggers a Read every 15s on
	// idle connections, so the 60s check fires at most once per 4 pings.
	//
	// `now` is reused as obfsReadStart for perf tracking — eliminates a
	// redundant time.Now() call on the perf-enabled hot path.
	now := time.Now()
	if now.Sub(nc.deadlineSetAt) >= noiseDeadlineInterval() {
		nc.conn.SetReadDeadline(now.Add(noiseReadTimeout)) //nolint:errcheck
		nc.deadlineSetAt = now
	}
	var obfsReadStart, afterRead time.Time
	if nc.perf != nil {
		obfsReadStart = now // reuse — same instant, saves one time.Now()
	}
	n, err := nc.conn.Read(nc.recvBuf[:])
	if nc.perf != nil {
		afterRead = time.Now()
		// obfs_read_wait: time blocked waiting for data from the network.
		// Recorded on ALL paths (including error) to keep counts in sync
		// with obfs_read — fixes the count orphan bug where handshake
		// error paths recorded wait but not the outer timer.
		nc.perf.TrackLatency(perf.StageObfsReadWait, afterRead.Sub(obfsReadStart))
	}
	if err != nil {
		if nc.perf != nil {
			// Record outer timer on error path too — fixes count orphan.
			nc.perf.TrackLatency(perf.StageObfsRead, time.Since(obfsReadStart))
		}
		return 0, err
	}
	if n < 2 {
		if nc.perf != nil {
			nc.perf.TrackLatency(perf.StageObfsRead, time.Since(obfsReadStart))
		}
		return 0, fmt.Errorf("noiseConn: frame too short (%d bytes)", n)
	}

	frameLen := int(binary.BigEndian.Uint16(nc.recvBuf[:2]))
	if frameLen == 0 || frameLen > maxNoiseFrame {
		if nc.perf != nil {
			nc.perf.TrackLatency(perf.StageObfsRead, time.Since(obfsReadStart))
		}
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
		// obfs_read_proc: time spent parsing/validating frame header and
		// potentially reading remaining bytes (io.ReadFull). Measured from
		// the moment conn.Read returned to now.
		nc.perf.TrackLatency(perf.StageObfsReadProc, time.Since(afterRead))
		// obfs_read (total) — always recorded, count matches obfs_read_wait.
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
// ip6Pool — IPv6 address allocator
// ---------------------------------------------------------------------------

// ip6Pool allocates client IPv6 addresses from a ULA CIDR subnet.
// The host address in the CIDR is the server address and is pre-marked as used.
// Only pure IPv6 CIDRs are accepted; use newIPPool for IPv4.
type ip6Pool struct {
	mu      sync.Mutex
	network *net.IPNet
	server  net.IP          // 16-byte IPv6
	used    map[[16]byte]bool
}

// newIP6Pool parses cidr (must be an IPv6 CIDR, e.g. "fc00::1/120") and
// returns an ip6Pool. The host address in cidr becomes the server address and
// is pre-marked as used along with the network address.
func newIP6Pool(cidr string) (*ip6Pool, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("ip6Pool: parse CIDR %q: %w", cidr, err)
	}
	// Reject IPv4 addresses (including IPv4-mapped IPv6).
	if ip.To4() != nil {
		return nil, errors.New("ip6Pool: only IPv6 CIDRs are supported")
	}
	serverIP := ip.To16()
	if serverIP == nil {
		return nil, errors.New("ip6Pool: invalid IPv6 address")
	}
	p := &ip6Pool{
		network: network,
		server:  cloneIP6(serverIP),
		used:    make(map[[16]byte]bool),
	}
	// Pre-mark network address and server address as used.
	p.used[ipToKey16(network.IP)] = true
	p.used[ipToKey16(serverIP)] = true
	return p, nil
}

// allocate returns the next available IPv6 address in the subnet.
func (p *ip6Pool) allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Start from network address + 1.
	current := cloneIP6(p.network.IP)
	incrementIP(current) // incrementIP works for any slice length

	for p.network.Contains(current) {
		key := ipToKey16(current)
		if !p.used[key] {
			p.used[key] = true
			return cloneIP6(current), nil
		}
		incrementIP(current)
	}
	return nil, errors.New("ip6Pool: address space exhausted")
}

// release marks ip as available again.
func (p *ip6Pool) release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Guard: only release genuine IPv6 (not IPv4-mapped).
	if ip.To4() == nil {
		if ip6 := ip.To16(); ip6 != nil {
			delete(p.used, ipToKey16(ip6))
		}
	}
}

// serverIP returns the server's IPv6 address in the subnet.
func (p *ip6Pool) serverIP() net.IP { return cloneIP6(p.server) }

// prefixLen returns the network prefix length.
func (p *ip6Pool) prefixLen() int {
	ones, _ := p.network.Mask.Size()
	return ones
}

// ipToKey16 converts an IPv6 address to a comparable [16]byte map key.
func ipToKey16(ip net.IP) [16]byte {
	var key [16]byte
	if ip6 := ip.To16(); ip6 != nil {
		copy(key[:], ip6)
	}
	return key
}

// cloneIP6 returns a 16-byte copy of an IPv6 address.
func cloneIP6(ip net.IP) net.IP {
	ip6 := ip.To16()
	if ip6 == nil {
		return nil
	}
	out := make(net.IP, 16)
	copy(out, ip6)
	return out
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

	var vlessAddr, vlessCert, vlessKey, vlessPath, vlessSNI string
	var anthropicKey string
	var relayTo string
	var knockKeyHex string
	var relayMetricsAddr string
	var diagnosticsFile string
	var coverAddr string
	var openAccess bool
	flag.StringVar(&cfg.ListenAddr, "addr", cfg.ListenAddr, "listen address")
	flag.StringVar(&cfg.TunCIDR, "tun-cidr", cfg.TunCIDR, "TUN CIDR (e.g. 10.8.0.1/24)")
	flag.StringVar(&cfg.Tun6CIDR, "tun6-cidr", cfg.Tun6CIDR, "TUN IPv6 CIDR for dual-stack clients (e.g. fc00::1/120; empty to disable)")
	flag.StringVar(&cfg.PrivKeyFile, "privkey", cfg.PrivKeyFile, "path to hex-encoded private key file")
	flag.StringVar(&cfg.Transport, "transport", cfg.Transport, "transport protocol: tcp (kernel CC) or udp (user-space BBR)")
	flag.StringVar(&cfg.AllowedKeysFile, "allowed-keys-file", cfg.AllowedKeysFile, "path to file with allowed client public keys (one hex key per line); persists across restarts")
	flag.BoolVar(&openAccess, "open", false, "allow any client key — ignore allowed_keys.txt (use with shared QR)")
	flag.StringVar(&apiCfg.ListenAddr, "api-addr", apiCfg.ListenAddr, "REST API listen address (empty to disable)")
	flag.StringVar(&apiCfg.APIToken, "api-token", "", "Bearer token for the REST API (empty = auto-generate a secure random token on startup)")
	flag.StringVar(&vlessAddr, "vless-addr", "", "VLESS+WS+TLS listen address (e.g. 0.0.0.0:443)")
	flag.StringVar(&vlessCert, "vless-cert", "cert.pem", "TLS certificate file for VLESS")
	flag.StringVar(&vlessKey, "vless-key", "key.pem", "TLS private key file for VLESS")
	flag.StringVar(&vlessPath, "vless-path", "/tunnel", "WebSocket path for VLESS")
	flag.StringVar(&vlessSNI, "vless-sni", "", "hostname for the auto-generated TLS cert CN/SAN (empty = random CDN domain for anti-fingerprinting)")
	flag.StringVar(&anthropicKey, "anthropic-key", "", "Anthropic API key for telemetry analysis (or ANTHROPIC_API_KEY env)")
	flag.StringVar(&relayTo, "relay-to", "", "relay VPN traffic to this upstream address (e.g. 193.124.93.240:38947); disables local VPN termination")
	flag.StringVar(&knockKeyHex, "knock-key", "", "hex-encoded 32-byte PSK for relay port knocking (Reality-style HMAC in session_id); client must use the same key")
	flag.StringVar(&relayMetricsAddr, "relay-metrics-addr", ":9092", "relay metrics HTTP server address (per-segment throughput for AI diagnostics; empty to disable)")
	flag.StringVar(&diagnosticsFile, "diagnostics-file", "", "path to append telemetry reports as JSONL (e.g. /var/log/cavadvpn/diagnostics.jsonl)")
	flag.StringVar(&coverAddr, "cover-addr", "", "listen address for plain HTTP cover website (e.g. :80); serves the cooking blog to censorship scanners checking port 80")
	flag.IntVar(&cfg.BBRSeedBW, "bbr-seed-bw", cfg.BBRSeedBW, "BBR initial bandwidth seed in Mbps for UDP transport (0 = use BBR Startup phase; set to your bottleneck bandwidth for faster connection ramp-up)")
	flag.IntVar(&cfg.BBRSeedRTT, "bbr-seed-rtt", cfg.BBRSeedRTT, "BBR initial RTT seed in milliseconds for UDP transport (0 = use BBR Startup phase; set to your path RTT for faster connection ramp-up)")
	flag.Parse()

	// Anthropic API key: flag takes precedence, then environment variable.
	if anthropicKey == "" {
		anthropicKey = os.Getenv("ANTHROPIC_API_KEY")
	}

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
	// Verify BBR is actually loaded — a missing tcp_bbr module silently
	// falls back to CUBIC, causing 10× worse throughput on lossy links.
	verifyBBR(logger)

	// ── Relay mode ────────────────────────────────────────────────────────────
	// When -relay-to is set the process acts as a transparent TCP relay:
	// it does NOT open a TUN device or run any VPN logic locally.
	// Active-probe protection (peek-and-route / decoy) is still applied so the
	// SPb relay is indistinguishable from a normal HTTPS server to scanners.
	if relayTo != "" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		// Parse knock key if provided.
		var knockKey *transport.KnockPSK
		if knockKeyHex != "" {
			kb, err := hex.DecodeString(knockKeyHex)
			if err != nil || len(kb) != 32 {
				logger.Error("invalid -knock-key: must be 64 hex characters (32 bytes)")
				os.Exit(1)
			}
			var k transport.KnockPSK
			copy(k[:], kb)
			knockKey = &k
			logger.Info("port knocking enabled (Reality-style session_id HMAC)")
		}

		logger.Info("starting in relay mode", "listen", cfg.ListenAddr, "upstream", relayTo)
		// HTTP cover site on port 80 (optional).
		// Censorship systems (ТСПУ/GFW) routinely check port 80 to classify
		// IP addresses. A cooking blog on :80 makes the relay look like a
		// normal web server to any scanner.
		if coverAddr != "" {
			go func() {
				logger.Info("cover HTTP listener starting", "addr", coverAddr)
				if err := serveCoverHTTP(coverAddr, nil); err != nil {
					logger.Warn("cover HTTP listener failed", "addr", coverAddr, "err", err)
				}
			}()
		}
		// Start per-segment metrics server (used by AI diagnostics to identify bottleneck).
		if relayMetricsAddr != "" {
			go startRelayMetricsServer(relayMetricsAddr, logger)
		}
		// TCP relay: handles CavadVPN TCP transport + decoy for scanners.
		go func() {
			if err := runRelay(ctx, cfg.ListenAddr, relayTo, knockKey, logger); err != nil {
				logger.Error("TCP relay error", "err", err)
			}
		}()
		// UDP relay: handles CavadVPN UDP+BBR transport (default client transport).
		if err := runUDPRelay(ctx, cfg.ListenAddr, relayTo, logger); err != nil {
			logger.Error("UDP relay error", "err", err)
			os.Exit(1)
		}
		return
	}
	// ── End relay mode ────────────────────────────────────────────────────────

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

	if cfg.Tun6CIDR != "" {
		if err := ConfigureTun6("vpn0", cfg.Tun6CIDR); err != nil {
			logger.Warn("TUN IPv6 configuration failed — dual-stack clients will not route IPv6", "err", err)
		} else {
			logger.Info("TUN IPv6 configured", "cidr6", cfg.Tun6CIDR)
		}
	}

	// Load the persisted allowed-keys list (if any).
	// -open flag bypasses the file entirely (allow any client key).
	var persistedKeys [][32]byte
	if openAccess {
		logger.Info("open-access mode — any client key accepted (shared QR)")
	} else {
		var err error
		persistedKeys, err = loadAllowedKeysFile(cfg.AllowedKeysFile)
		if err != nil {
			logger.Warn("failed to load allowed_keys file — starting in open-access mode", "err", err)
			persistedKeys = nil
		} else if len(persistedKeys) > 0 {
			logger.Info("loaded allowed_keys", "path", cfg.AllowedKeysFile, "count", len(persistedKeys))
		}
	}

	srv, err := NewServer(cfg, kp, tun, persistedKeys, logger)
	if err != nil {
		logger.Error("failed to create server", "err", err)
		os.Exit(1)
	}
	// Attach the performance metrics collector.
	srv.Perf = perf.NewCollector()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	apiSrv := startAPIServer(ctx, apiCfg, srv, logger, anthropicKey, diagnosticsFile)

	// HTTP cover site on port 80 (optional).
	// Same as in relay mode: a cooking blog on :80 makes the server appear
	// as a normal web host to censorship scanners.
	if coverAddr != "" {
		go func() {
			logger.Info("cover HTTP listener starting", "addr", coverAddr)
			if err := serveCoverHTTP(coverAddr, nil); err != nil {
				logger.Warn("cover HTTP listener failed", "addr", coverAddr, "err", err)
			}
		}()
	}

	// Start VLESS+WS+TLS listener if configured.
	if vlessAddr != "" {
		uuid, err := loadOrGenerateVLESSUUID(vlessUUIDFile, logger)
		if err != nil {
			logger.Error("failed to load VLESS UUID", "err", err)
			os.Exit(1)
		}
		vlessCfg := VLESSConfig{
			ListenAddr:  vlessAddr,
			UUID:        uuid,
			WSPath:      vlessPath,
			TLSCert:     vlessCert,
			TLSKey:      vlessKey,
			TLSHostname: vlessSNI,
		}
		// Print VLESS links for easy import into V2Ray clients.
		host, port := splitVLESSHostPort(vlessAddr)
		tcpLink, wsLink := generateVLESSLinks(uuid, host, port, vlessPath)

		// Register VLESS link in the REST API (use TCP link as primary).
		if apiSrv != nil {
			apiSrv.SetVLESSInfo(api.VLESSInfo{
				Link: tcpLink,
				UUID: transport.FormatUUID(uuid),
				Host: host,
				Port: port,
				Path: vlessPath,
			})
		}
		logger.Info("VLESS TCP link", "link", tcpLink)
		logger.Info("VLESS WS link", "link", wsLink)
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════")
		fmt.Println("  VLESS links for V2Ray client (iPhone/Android):")
		fmt.Println()
		fmt.Println("  TCP (recommended):")
		fmt.Println(" ", tcpLink)
		fmt.Println()
		fmt.Println("  WebSocket:")
		fmt.Println(" ", wsLink)
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════")
		fmt.Println()

		go func() {
			if err := srv.RunVLESS(ctx, vlessCfg); err != nil {
				logger.Error("VLESS server error", "err", err)
			}
		}()
	}

	if err := srv.Run(ctx); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

// startAPIServer launches the REST management API in a background goroutine.
// If cfg.ListenAddr is empty the API is not started.
func startAPIServer(ctx context.Context, cfg api.Config, srv *Server, logger *slog.Logger, anthropicKey, diagnosticsFile string) *api.APIServer {
	if cfg.ListenAddr == "" {
		return nil
	}

	// Security: API token is mandatory. If the operator did not supply one via
	// -api-token, generate a cryptographically-random token and print it once.
	// This ensures the management API is never accessible without authentication
	// — even on loopback — preventing privilege escalation via local processes.
	if cfg.APIToken == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			logger.Error("failed to generate API token", "err", err)
			os.Exit(1)
		}
		cfg.APIToken = hex.EncodeToString(b)
		logger.Warn("╔══════════════════════════════════════════════════════════╗")
		logger.Warn("║  No -api-token supplied. Auto-generated a secure token.  ║")
		logger.Warn("║  Use this token for all REST API requests:                ║")
		logger.Warn("║                                                           ║")
		logger.Warn("║  API TOKEN: "+cfg.APIToken+"  ║")
		logger.Warn("║                                                           ║")
		logger.Warn("║  Set -api-token=<above> to keep the same token on restart.║")
		logger.Warn("╚══════════════════════════════════════════════════════════╝")
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

	// Enable telemetry collection and AI-powered analysis.
	telemetryStore := api.NewTelemetryStore(10000)
	var analyzer *api.TelemetryAnalyzer
	if anthropicKey != "" {
		analyzer = api.NewTelemetryAnalyzer(telemetryStore, api.SonnetAnalyze, anthropicKey, time.Hour)
		// Feed server-side perf data into analysis.
		if srv.Perf != nil {
			perfRef := srv.Perf
			analyzer.GetServerPerf = func() *api.ServerPerfSummary {
				snap := perfRef.Snapshot()
				s := api.SummarizePerf(snap)
				return &s
			}
		}
		analyzer.GetServerMetrics = func() *api.ServerMetrics {
			m := api.CollectServerMetrics()
			return &m
		}
		analyzer.Start()
		logger.Info("telemetry AI analysis enabled (hourly)")
	} else {
		logger.Info("telemetry collection enabled (no AI analysis — set -anthropic-key or ANTHROPIC_API_KEY)")
	}
	apiSrv.SetTelemetryStore(telemetryStore, analyzer)
	if diagnosticsFile != "" {
		apiSrv.SetDiagnosticsFile(diagnosticsFile)
		logger.Info("diagnostics file enabled", "path", diagnosticsFile)
	}

	go func() {
		<-ctx.Done()
		notifSvc.Stop()
		if analyzer != nil {
			analyzer.Stop()
		}
	}()

	go func() {
		if err := apiSrv.Run(ctx); err != nil {
			logger.Error("api server error", "err", err)
		}
	}()

	return apiSrv
}
