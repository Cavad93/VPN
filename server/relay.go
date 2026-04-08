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
//	    YES → dial Astana:8443, pipe bytes bidirectionally
//	    NO  → serve HTTP decoy, close
//	                                  SPb relay ──[raw TCP]──► Astana:8443
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
)

// relayDialTimeout is how long the relay waits for the upstream connection.
// If Astana is unreachable within this window the client connection is closed.
var relayDialTimeout = 10 * time.Second

// relayPipeTimeout is the read/write deadline applied to idle relay pipes.
// A connection that transfers no bytes for this duration is considered dead.
// Set to 0 to disable (no timeout).
var relayPipeTimeout = 5 * time.Minute

// runRelay listens on listenAddr for incoming connections, applies
// peek-and-route (active-probe protection), and transparently forwards
// VPN connections to relayTarget.
//
// It never returns while ctx is alive.
func runRelay(ctx context.Context, listenAddr, relayTarget string, logger *slog.Logger) error {
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
		go relayOne(conn, relayTarget, logger)
	}
}

// relayOne handles a single incoming connection:
//  1. Peek the first byte (active-probe protection via peekAndRoute).
//  2. Dial the upstream server.
//  3. Pipe bytes in both directions until either side closes.
func relayOne(client net.Conn, target string, logger *slog.Logger) {
	// Active-probe protection: non-VPN → decoy response, VPN → proceed.
	routed, ok := peekAndRoute(client)
	if !ok {
		return // decoy served and conn closed inside peekAndRoute
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

	// Apply idle timeout if configured.
	applyRelayDeadline := func(c net.Conn) {
		if relayPipeTimeout > 0 {
			c.SetDeadline(time.Now().Add(relayPipeTimeout)) //nolint:errcheck
		}
	}
	applyRelayDeadline(routed)
	applyRelayDeadline(upstream)

	// Bidirectional pipe: client ↔ upstream.
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src) //nolint:errcheck
		// Signal the other goroutine that this direction is done.
		dst.Close()
		src.Close()
		done <- struct{}{}
	}

	go pipe(upstream, routed)
	go pipe(routed, upstream)

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

// udpBufSize is the per-goroutine read buffer.  65536 = max UDP datagram.
const udpBufSize = 65536

// udpRelayWorkers is the number of parallel goroutines draining the receive
// socket.  Multiple readers on the same PacketConn are safe on Linux/macOS/
// Windows — the kernel delivers each datagram to exactly one ReadFrom call.
// 4 workers saturate a ~100 Mbps link even on a slow relay VM; more workers
// add lock contention without benefit.
const udpRelayWorkers = 4

// udpPktPool recycles datagram buffers to avoid per-packet heap allocations.
// Each buffer is exactly udpBufSize bytes; workers borrow, copy payload into a
// trimmed slice, then return the original buffer.
var udpPktPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpBufSize)
		return &b
	},
}

// udpSession tracks one client ↔ upstream mapping.
type udpSession struct {
	upstream  net.Conn
	sendCh    chan []byte // buffered channel; upstream writer goroutine drains it
	lastSeen  time.Time
}

func runUDPRelay(ctx context.Context, listenAddr, relayTarget string, logger *slog.Logger) error {
	local, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
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
					}
				}
				mu.Unlock()
			}
		}
	}()

	// worker handles one receive loop iteration: read a datagram, look up or
	// create a session, and dispatch the packet without blocking other workers.
	worker := func() {
		for {
			// Borrow a buffer from the pool — zero allocation per packet.
			bp := udpPktPool.Get().(*[]byte)
			buf := *bp

			n, clientAddr, err := local.ReadFrom(buf)
			if err != nil {
				udpPktPool.Put(bp)
				select {
				case <-ctx.Done():
					return
				default:
					logger.Warn("udp relay: read error", "err", err)
					continue
				}
			}

			// Copy payload into a trimmed slice; return the pool buffer immediately
			// so other workers can reuse it without waiting for upstream delivery.
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			udpPktPool.Put(bp)

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
				// sendCh buffers up to 256 packets so ReadFrom never blocks on
				// a slow upstream write.  The upstream writer goroutine drains it.
				ch := make(chan []byte, 256)
				sess = &udpSession{upstream: up, sendCh: ch, lastSeen: time.Now()}
				sessions[key] = sess

				// Goroutine: client → upstream (async writer, never blocks ReadFrom).
				go func(up net.Conn, ch <-chan []byte) {
					for pkt := range ch {
						up.Write(pkt) //nolint:errcheck
					}
				}(up, ch)

				// Goroutine: upstream → client (one goroutine per session).
				go func(up net.Conn, dst net.Addr) {
					bp := udpPktPool.Get().(*[]byte)
					rbuf := *bp
					defer udpPktPool.Put(bp)
					for {
						m, err := up.Read(rbuf)
						if err != nil {
							return
						}
						// WriteTo on a PacketConn is goroutine-safe; multiple
						// upstream→client goroutines can call it concurrently.
						local.WriteTo(rbuf[:m], dst) //nolint:errcheck
					}
				}(up, clientAddr)
			}
			sess.lastSeen = time.Now()
			mu.Unlock()

			// Non-blocking send: if the channel is full the packet is dropped
			// (BBR/ReliableUDP on the client will retransmit).
			select {
			case sess.sendCh <- pkt:
			default:
				logger.Warn("udp relay: send channel full, dropping packet", "client", key)
			}
		}
	}

	// Start parallel workers.  All share the same PacketConn; the kernel
	// delivers each datagram to exactly one ReadFrom call (no duplication).
	for i := 0; i < udpRelayWorkers; i++ {
		go worker()
	}

	// Block until context is cancelled.
	<-ctx.Done()
	return nil
}
