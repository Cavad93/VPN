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
