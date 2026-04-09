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
	"time"

	"github.com/cavad93/vpn/server/transport"
)

// relayDialTimeout is how long the relay waits for the upstream connection.
// If Astana is unreachable within this window the client connection is closed.
var relayDialTimeout = 10 * time.Second

// relayPipeTimeout is the idle timeout for relay pipes.  A connection that
// transfers no bytes for this duration in either direction is considered dead.
// Set to 0 to disable (no timeout).
//
// IMPORTANT: this is an IDLE timeout, not an absolute deadline.  The deadline
// is reset before every Read and Write via idleTimeoutConn, so active
// connections stay alive indefinitely.  Previously this was implemented as a
// one-shot SetDeadline which killed active connections after exactly 5 minutes
// regardless of traffic (see Cloudflare blog "The complete guide to Go
// net/http timeouts" — deadlines are absolute, you must reset them per-op).
var relayPipeTimeout = 5 * time.Minute

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
// VPN connections to relayTarget. If knockKey is non-nil, the relay
// additionally verifies a Reality-style HMAC tag in the ClientHello's
// session_id field — connections without a valid knock are served the
// cover website or closed silently (see peekAndRouteKnock).
//
// It never returns while ctx is alive.
func runRelay(ctx context.Context, listenAddr, relayTarget string, knockKey *transport.KnockPSK, logger *slog.Logger) error {
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
		// Apply the same TCP socket tuning as the full VPN server.
		if tc, ok := conn.(*net.TCPConn); ok {
			setForcedSocketBuffers(tc, 4<<20)
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(15 * time.Second)
		}
		go relayOne(conn, relayTarget, knockKey, logger)
	}
}

// relayOne handles a single incoming connection:
//  1. Peek and verify knock (active-probe protection via peekAndRouteKnock).
//  2. Dial the upstream server.
//  3. Pipe bytes in both directions until either side closes.
func relayOne(client net.Conn, target string, knockKey *transport.KnockPSK, logger *slog.Logger) {
	// Active-probe protection: non-VPN / bad knock → decoy response, VPN → proceed.
	routed, ok := peekAndRouteKnock(client, knockKey)
	if !ok {
		return // decoy served and conn closed inside peekAndRouteKnock
	}

	// Connect to upstream (Astana VPN server).
	upstream, err := net.DialTimeout("tcp", target, relayDialTimeout)
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
	// indefinitely, but connections idle for relayPipeTimeout are killed.
	var routedIO, upstreamIO net.Conn = routed, upstream
	if relayPipeTimeout > 0 {
		routedIO = &idleTimeoutConn{Conn: routed, timeout: relayPipeTimeout}
		upstreamIO = &idleTimeoutConn{Conn: upstream, timeout: relayPipeTimeout}
	}

	// Bidirectional pipe: client ↔ upstream.
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src) //nolint:errcheck
		// Signal the other goroutine that this direction is done.
		dst.Close()
		src.Close()
		done <- struct{}{}
	}

	go pipe(upstreamIO, routedIO)
	go pipe(routedIO, upstreamIO)

	// Wait for both directions to finish.
	<-done
	<-done

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

const udpSessionTimeout = 5 * time.Minute

// udpBufSize is the receive buffer size — max UDP datagram.
const udpBufSize = 65536

// udpSession tracks one client ↔ upstream mapping.
type udpSession struct {
	upstream net.Conn
	sendCh   chan []byte // async write queue: decouples ReadFrom from upstream Write
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
	sessions := make(map[string]*udpSession)

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

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		key := clientAddr.String()

		mu.Lock()
		sess, ok := sessions[key]
		if !ok {
			up, err := net.Dial("udp", relayTarget)
			if err != nil {
				mu.Unlock()
				logger.Warn("udp relay: dial upstream failed", "target", relayTarget, "err", err)
				continue
			}
			if uc, ok := up.(*net.UDPConn); ok {
				uc.SetReadBuffer(4 << 20)  //nolint:errcheck
				uc.SetWriteBuffer(4 << 20) //nolint:errcheck
			}
			// sendCh buffers up to 512 packets so ReadFrom never stalls on write.
			ch := make(chan []byte, 512)
			sess = &udpSession{upstream: up, sendCh: ch, lastSeen: time.Now()}
			sessions[key] = sess

			// Upstream writer goroutine: drains sendCh → upstream.
			// Runs independently of ReadFrom; UDP writes are near-instant.
			go func(up net.Conn, ch <-chan []byte) {
				for pkt := range ch {
					up.Write(pkt) //nolint:errcheck
					// Segment B: count bytes forwarded to Astana.
					globalRelayMetrics.upstreamTxBytes.Add(int64(len(pkt)))
				}
			}(up, ch)

			// Upstream → client goroutine: one per session.
			go func(up net.Conn, dst net.Addr) {
				rbuf := make([]byte, udpBufSize)
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

		// Non-blocking enqueue: if channel is full, drop the packet.
		// BBR/ReliableUDP on the client will retransmit; occasional drops
		// here are better than blocking ReadFrom for all clients.
		select {
		case sess.sendCh <- pkt:
		default:
			globalRelayMetrics.clientDrops.Add(1)
			logger.Warn("udp relay: send queue full, dropping packet", "client", key)
		}
	}
}
