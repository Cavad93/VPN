// relay.go — transparent TCP relay with active-probe protection.
//
// When the server is started with -relay-to <host:port>, it operates in relay
// mode: instead of terminating the VPN protocol locally, it forwards the raw
// byte stream to the upstream VPN server.  The decoy protection from decoy.go
// is applied first, so port scanners and DPI probes see the same nginx-like
// HTTP 400 response as they would from a full VPN server.
//
// Traffic flow:
//
//	MacBook ──[TLS+Noise+Mux]──► SPb relay:443
//	    peek first byte (0x16?)
//	    YES → dial Astana:38947, pipe bytes bidirectionally
//	    NO  → serve HTTP decoy, close
//	                                  SPb relay ──[raw TCP]──► Astana:38947
//	                                                              VPN terminates here
//
// The relay is completely protocol-agnostic: it does not decrypt, re-encrypt,
// or modify any bytes.  All Noise_XX / Mux / BBR negotiation happens end-to-end
// between the MacBook client and the Astana server.
package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cavad93/vpn/server/transport"
)

// relayDialTimeoutNs stores the upstream dial timeout in nanoseconds.
// Atomic to prevent data races between relayOne goroutines and tests that
// temporarily override the value (same pattern as decoyReadDeadlineNs).
var relayDialTimeoutNs atomic.Int64

// relayPipeTimeoutNs stores the idle pipe timeout in nanoseconds.
// Atomic for the same reason — tests override it to shorten the wait.
//
// IMPORTANT: this is an IDLE timeout, not an absolute deadline.  The deadline
// is reset before every Read and Write via idleTimeoutConn, so active
// connections stay alive indefinitely.  Previously this was implemented as a
// one-shot SetDeadline which killed active connections after exactly 5 minutes
// regardless of traffic (see Cloudflare blog "The complete guide to Go
// net/http timeouts" — deadlines are absolute, you must reset them per-op).
var relayPipeTimeoutNs atomic.Int64

func init() {
	relayDialTimeoutNs.Store(int64(10 * time.Second))
	relayPipeTimeoutNs.Store(int64(5 * time.Minute))
}

func relayDialTimeout() time.Duration     { return time.Duration(relayDialTimeoutNs.Load()) }
func setRelayDialTimeout(d time.Duration) { relayDialTimeoutNs.Store(int64(d)) }
func relayPipeTimeout() time.Duration     { return time.Duration(relayPipeTimeoutNs.Load()) }
func setRelayPipeTimeout(d time.Duration) { relayPipeTimeoutNs.Store(int64(d)) }

// idleTimeoutConn wraps a net.Conn and resets the read/write deadline before
// every I/O operation, turning a Go absolute deadline into an idle timeout.
//
// Each direction gets its own deadline: Read resets ReadDeadline, Write resets
// WriteDeadline.  This allows bidirectional io.Copy goroutines to independently
// detect idle: if the *reading* side of a pipe goes silent for relayPipeTimeout
// the Read returns a timeout error, while the Write side (driven by the other
// pipe) may still be active.
//
// This pattern is standard in Go relay/proxy code — see Trojan-Go, Caddy,
// and Cloudflare's recommendation to call SetDeadline before every op.
type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleTimeoutConn) Read(b []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.timeout)) //nolint:errcheck
	return c.Conn.Read(b)
}

func (c *idleTimeoutConn) Write(b []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)) //nolint:errcheck
	return c.Conn.Write(b)
}

// runRelay listens on listenAddr for incoming connections, applies
// peek-and-route (active-probe protection), and transparently forwards
// VPN connections to relayTarget. If kv is non-nil, the relay additionally
// verifies a Reality-style HMAC tag in the ClientHello's session_id field —
// connections without a valid knock are served the cover website or closed
// silently (see peekAndRouteKnock). kv.Verify is zero-alloc (HMAC pooled).
//
// It never returns while ctx is alive.
func runRelay(ctx context.Context, listenAddr, relayTarget string, kv *transport.KnockVerifier, logger *slog.Logger) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	// Same TCP socket options as runTCP for consistency.
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		setListenerDeferAccept(tcpLn, 5)
		setListenerTFO(tcpLn)
	}

	logger.Info("relay listening",
		"listen", listenAddr,
		"upstream", relayTarget,
	)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Warn("relay: accept error", "err", err)
				continue
			}
		}
		setConnTTL64(conn) // Anti-fingerprint: TTL=64 on Windows
		if tc, ok := conn.(*net.TCPConn); ok {
			setForcedSocketBuffers(tc, 4<<20)
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(15 * time.Second)
		}
		go relayOne(conn, relayTarget, kv, logger)
	}
}

// relayOne handles a single incoming connection:
//  1. Peek and verify knock (active-probe protection via peekAndRouteKnock).
//  2. Dial the upstream server.
//  3. Pipe bytes in both directions until either side closes.
func relayOne(client net.Conn, target string, kv *transport.KnockVerifier, logger *slog.Logger) {
	// Active-probe protection: non-VPN / bad knock → decoy response, VPN → proceed.
	routed, ok := peekAndRouteKnock(client, kv)
	if !ok {
		return // decoy served and conn closed inside peekAndRouteKnock
	}

	// Connect to upstream (Astana VPN server).
	upstream, err := net.DialTimeout("tcp", target, relayDialTimeout())
	if err != nil {
		logger.Warn("relay: dial upstream failed",
			"target", target,
			"client", routed.RemoteAddr(),
			"err", err,
		)
		routed.Close()
		return
	}
	if tc, ok := upstream.(*net.TCPConn); ok {
		setForcedSocketBuffers(tc, 4<<20)
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
	}

	logger.Info("relay: connection established",
		"client", routed.RemoteAddr(),
		"upstream", target,
	)

	// Wrap connections with idle timeout if configured.
	// Each Read/Write resets its own deadline — active connections survive
	// indefinitely, but connections idle for relayPipeTimeout() are killed.
	var routedIO, upstreamIO net.Conn = routed, upstream
	if pt := relayPipeTimeout(); pt > 0 {
		routedIO = &idleTimeoutConn{Conn: routed, timeout: pt}
		upstreamIO = &idleTimeoutConn{Conn: upstream, timeout: pt}
	}

	// Bidirectional pipe: client ↔ upstream.
	// Use ioCopyBufPool (32 KiB) so that each direction avoids a per-connection
	// heap allocation that would otherwise live for the relay session lifetime.
	// done is borrowed from relayChanPool to avoid the make(chan struct{}, 2)
	// heap allocation on every accepted TCP connection.
	done := relayChanPool.Get().(chan struct{})
	pipe := func(dst, src net.Conn) {
		pb := ioCopyBufPool.Get().(*[]byte)
		io.CopyBuffer(dst, src, *pb) //nolint:errcheck
		ioCopyBufPool.Put(pb)
		// Signal the other goroutine that this direction is done.
		dst.Close()
		src.Close()
		done <- struct{}{}
	}

	go pipe(upstreamIO, routedIO)
	go pipe(routedIO, upstreamIO)

	// Wait for both directions to finish. After both receives the channel is
	// empty (each goroutine sends exactly once into a capacity-2 channel).
	<-done
	<-done
	relayChanPool.Put(done) // return clean channel to pool

	logger.Info("relay: connection closed", "client", routed.RemoteAddr())
}

// ── UDP relay ──────────────────────────────────────────────────────────────────
//
// runUDPRelay listens for UDP datagrams on listenAddr and forwards them to
// relayTarget.  Each unique (client IP:port) gets its own upstream UDP socket
// so that replies are routed back to the correct client.
//
// Unlike the TCP relay there is no per-connection peek-and-route: UDP is
// connectionless so HTTP decoy pages are meaningless.  Random scanners very
// rarely probe UDP ports, and if they do they receive silence (no response),
// which is indistinguishable from a closed port.
//
// Sessions are cleaned up after udpSessionTimeout of inactivity.

// udpSessionTimeout is generous (10 min) to survive macOS WiFi power saving
// which can pause UDP traffic for 30-60s during idle periods.
const udpSessionTimeout = 10 * time.Minute

// udpBufSize is the receive buffer size — max UDP datagram.
const udpBufSize = 65536

// relayAddrKey is a comparable struct used as a map key for UDP relay sessions.
// It replaces clientAddr.String() to eliminate the heap-allocated string on
// every incoming UDP packet — the same technique applied to the UDP transport
// in transport.udpAddrKey (Run 14).
//
// IPv4 addresses are normalised to IPv4-in-IPv6 form so that the 4-byte and
// 16-byte representations of the same address compare equal — required on
// dual-stack sockets where the kernel may return either form.
type relayAddrKey struct {
	ip   [16]byte // IPv4-in-IPv6 or IPv6; no pointer → zero-alloc as map key
	port int
	zone string // IPv6 link-local zone; always "" for IPv4
}

// makeRelayAddrKey builds a relayAddrKey from a net.Addr returned by
// net.PacketConn.ReadFrom. On a UDP socket the addr is always *net.UDPAddr;
// the non-UDPAddr branch is a safety fallback for test code.
func makeRelayAddrKey(addr net.Addr) relayAddrKey {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		// Fallback for non-UDP addresses (only in tests). Store the string
		// representation in zone so different addresses still produce distinct keys.
		return relayAddrKey{zone: addr.String()}
	}
	var key relayAddrKey
	key.port = ua.Port
	key.zone = ua.Zone
	switch len(ua.IP) {
	case 4:
		// Normalise IPv4 to IPv4-in-IPv6 (::ffff:x.x.x.x) so that 4-byte and
		// 16-byte representations of the same IPv4 address produce the same key.
		key.ip[10] = 0xff
		key.ip[11] = 0xff
		copy(key.ip[12:], ua.IP)
	case 16:
		copy(key.ip[:], ua.IP)
	}
	return key
}

// udpRelayPktPool pools udpBufSize-byte receive buffers for the
// ReadFrom → sendCh → upstream-writer pipeline in runUDPRelay.
//
// Without pooling: ReadFrom calls make([]byte, n) on every incoming UDP packet.
// At 30 Mbps / 1430-byte packets (≈2630 pkt/sec) per client this is
// ~2630 allocs/sec/client = ~3.7 MB/sec heap pressure per client.
//
// Each pool entry is a *[]byte whose slice length is set to the actual
// packet size before being sent through sendCh, so the consumer can call
// Write(*pb) with the correct length. Before returning to the pool the
// slice is reset to full capacity: *pb = (*pb)[:cap(*pb)].
// relayChanPool pools the bidirectional-pipe done channels used in relayOne.
// Each TCP relay connection needs exactly one chan struct{} with capacity 2:
// two goroutines (one per direction) each send one value, relayOne receives both.
// After both receives the channel is empty and safe to return to the pool.
//
// At 1000 concurrent relay connections this saves ~1000 make(chan struct{}, 2)
// allocations per second (each channel is ≈96 bytes of heap + runtime overhead).
var relayChanPool = sync.Pool{
	New: func() any {
		return make(chan struct{}, 2)
	},
}

var udpRelayPktPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpBufSize)
		return &b
	},
}

// udpSession tracks one client ↔ upstream mapping.
type udpSession struct {
	upstream net.Conn
	// sendCh carries pooled packet buffers from ReadFrom to the upstream
	// writer goroutine. Using *[]byte (pool token) instead of []byte
	// eliminates make([]byte, n) on every incoming UDP packet.
	sendCh   chan *[]byte
	lastSeen time.Time
}

func runUDPRelay(ctx context.Context, listenAddr, relayTarget string, logger *slog.Logger) error {
	local, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}
	// Expand UDP receive buffer so bursts don't drop datagrams before ReadFrom picks them up.
	if uc, ok := local.(*net.UDPConn); ok {
		uc.SetReadBuffer(4 << 20)  //nolint:errcheck // 4 MB
		uc.SetWriteBuffer(4 << 20) //nolint:errcheck // 4 MB
	}
	logger.Info("udp relay listening", "listen", listenAddr, "upstream", relayTarget)

	go func() {
		<-ctx.Done()
		local.Close()
	}()

	var mu sync.Mutex
	sessions := make(map[relayAddrKey]*udpSession)

	// Periodic cleanup of idle sessions.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				for k, s := range sessions {
					if time.Since(s.lastSeen) > udpSessionTimeout {
						s.upstream.Close()
						close(s.sendCh)
						delete(sessions, k)
						globalRelayMetrics.activeSessions.Add(-1)
					}
				}
				mu.Unlock()
			}
		}
	}()

	// Single receive loop — one goroutine owns ReadFrom (safe on all platforms).
	// The key fix vs the original: upstream Write is now done in a per-session
	// goroutine via sendCh, so ReadFrom never blocks waiting for SPb→Astana delivery.
	buf := make([]byte, udpBufSize)
	for {
		n, clientAddr, err := local.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Warn("udp relay: read error", "err", err)
				continue
			}
		}

		// Segment A: count bytes received from VPN clients (MacBook → SPb).
		globalRelayMetrics.clientRxBytes.Add(int64(n))

		// Borrow a pool buffer, set its length to n, copy the packet data.
		// This replaces make([]byte, n) + copy which was called on every packet.
		pb := udpRelayPktPool.Get().(*[]byte)
		*pb = (*pb)[:n]
		copy(*pb, buf[:n])

		key := makeRelayAddrKey(clientAddr)

		mu.Lock()
		sess, ok := sessions[key]
		if !ok {
			up, err := net.Dial("udp", relayTarget)
			if err != nil {
				mu.Unlock()
				// Return the pool buffer before continuing (packet dropped).
				*pb = (*pb)[:cap(*pb)]
				udpRelayPktPool.Put(pb)
				logger.Warn("udp relay: dial upstream failed", "target", relayTarget, "err", err)
				continue
			}
			if uc, ok := up.(*net.UDPConn); ok {
				uc.SetReadBuffer(4 << 20)  //nolint:errcheck
				uc.SetWriteBuffer(4 << 20) //nolint:errcheck
			}
			// sendCh carries pooled *[]byte tokens; capacity 512 packets.
			ch := make(chan *[]byte, 512)
			sess = &udpSession{upstream: up, sendCh: ch, lastSeen: time.Now()}
			sessions[key] = sess

			// Upstream writer goroutine: drains sendCh → upstream, returns
			// each buffer to udpRelayPktPool after the write completes.
			go func(up net.Conn, ch <-chan *[]byte) {
				for pb := range ch {
					up.Write(*pb) //nolint:errcheck
					// Segment B: count bytes forwarded to Astana.
					globalRelayMetrics.upstreamTxBytes.Add(int64(len(*pb)))
					// Restore full capacity before returning to pool.
					*pb = (*pb)[:cap(*pb)]
					udpRelayPktPool.Put(pb)
				}
			}(up, ch)

			// Upstream → client goroutine: one per session.
			// rbuf is borrowed from the pool for the session lifetime
			// and returned when the upstream closes.
			go func(up net.Conn, dst net.Addr) {
				rbp := udpRelayPktPool.Get().(*[]byte)
				*rbp = (*rbp)[:udpBufSize]
				rbuf := *rbp
				defer func() {
					*rbp = (*rbp)[:cap(*rbp)]
					udpRelayPktPool.Put(rbp)
				}()
				for {
					m, err := up.Read(rbuf)
					if err != nil {
						return
					}
					// Segment B: count bytes received from Astana.
					globalRelayMetrics.upstreamRxBytes.Add(int64(m))
					local.WriteTo(rbuf[:m], dst) //nolint:errcheck
					// Segment A (reverse): count bytes delivered to the client.
					globalRelayMetrics.clientTxBytes.Add(int64(m))
				}
			}(up, clientAddr)

			globalRelayMetrics.activeSessions.Add(1)
		}
		sess.lastSeen = time.Now()
		mu.Unlock()

		// Non-blocking enqueue: if channel is full, return the buffer to the
		// pool (packet dropped) rather than blocking ReadFrom for all clients.
		// BBR/ReliableUDP on the client will retransmit.
		select {
		case sess.sendCh <- pb:
		default:
			*pb = (*pb)[:cap(*pb)]
			udpRelayPktPool.Put(pb)
			globalRelayMetrics.clientDrops.Add(1)
			logger.Warn("udp relay: send queue full, dropping packet", "client", key)
		}
	}
}
