package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// startEchoServer starts a TCP server that echoes back everything it receives.
// Returns the address it is listening on and a cancel func.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) //nolint:errcheck
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startRelayWithUpstream starts a TCP relay pointing at upstream and returns its addr.
func startRelayWithUpstream(t *testing.T, upstream string) string {
	t.Helper()
	// Use port 0 so the OS picks a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go runRelay(ctx, addr, upstream, logger) //nolint:errcheck

	// Give the relay goroutine a moment to bind.
	time.Sleep(20 * time.Millisecond)
	return addr
}

// startUDPRelayWithUpstream starts a UDP relay and returns (listenAddr, echoAddr).
func startUDPEchoServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, udpBufSize)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			conn.WriteTo(buf[:n], addr) //nolint:errcheck
		}
	}()
	return conn.LocalAddr().String()
}

func startUDPRelay(t *testing.T, upstream string) string {
	t.Helper()
	// Pre-bind to get a free port.
	tmp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind udp: %v", err)
	}
	addr := tmp.LocalAddr().String()
	tmp.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go runUDPRelay(ctx, addr, upstream, logger) //nolint:errcheck

	time.Sleep(20 * time.Millisecond)
	return addr
}

// TestRelayForwardsVPNConnection verifies that a connection starting with 0x16
// is transparently forwarded to the upstream server.
func TestRelayForwardsVPNConnection(t *testing.T) {
	echo := startEchoServer(t)
	relay := startRelayWithUpstream(t, echo)

	conn, err := net.DialTimeout("tcp", relay, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	// Send TLS ClientHello first byte + payload.
	payload := append([]byte{0x16}, []byte("hello relay world")...)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Echo server echoes everything back — we should receive the same bytes.
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}
}

// TestRelayServesDecoyForNonVPNProbe verifies that a connection NOT starting
// with 0x16 receives the HTTP decoy response.
func TestRelayServesDecoyForNonVPNProbe(t *testing.T) {
	echo := startEchoServer(t)
	relay := startRelayWithUpstream(t, echo)

	conn, err := net.DialTimeout("tcp", relay, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	// HTTP scanner probe (first byte 'G' = 0x47).
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) //nolint:errcheck

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		msg := err.Error()
		if !strings.Contains(msg, "closed") && !strings.Contains(msg, "reset") {
			t.Fatalf("unexpected read error: %v", err)
		}
	}

	if !bytes.Contains(resp, []byte("HTTP/1.1 400 Bad Request")) {
		t.Fatalf("expected decoy 400 response, got: %q", resp)
	}
	if !bytes.Contains(resp, []byte("nginx/1.24.0")) {
		t.Fatalf("expected nginx Server header in decoy, got: %q", resp)
	}
}

// TestRelayClosesConnectionWhenUpstreamUnreachable verifies that the relay
// gracefully closes the client connection when the upstream is unavailable.
func TestRelayClosesConnectionWhenUpstreamUnreachable(t *testing.T) {
	// Use a port that nothing is listening on.
	relay := startRelayWithUpstream(t, "127.0.0.1:1") // port 1 is always closed

	orig := relayDialTimeout
	relayDialTimeout = 200 * time.Millisecond
	t.Cleanup(func() { relayDialTimeout = orig })

	conn, err := net.DialTimeout("tcp", relay, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	// Send VPN-like first byte so it passes decoy check.
	conn.Write([]byte{0x16}) //nolint:errcheck

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("expected closed connection from relay on unreachable upstream, got n=%d err=%v", n, err)
	}
}

// TestUDPRelayForwardsPackets verifies that UDP packets are forwarded to upstream
// and replies are routed back to the original client.
func TestUDPRelayForwardsPackets(t *testing.T) {
	echo := startUDPEchoServer(t)
	relay := startUDPRelay(t, echo)

	conn, err := net.Dial("udp", relay)
	if err != nil {
		t.Fatalf("dial udp relay: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello udp relay")
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
}

// TestUDPRelayMultipleClients verifies that two different clients get independent
// sessions and replies are routed back to the correct sender.
func TestUDPRelayMultipleClients(t *testing.T) {
	echo := startUDPEchoServer(t)
	relay := startUDPRelay(t, echo)

	send := func(msg string) string {
		conn, err := net.Dial("udp", relay)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(msg)) //nolint:errcheck
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		return string(buf[:n])
	}

	if got := send("client-A"); got != "client-A" {
		t.Errorf("client A: got %q", got)
	}
	if got := send("client-B"); got != "client-B" {
		t.Errorf("client B: got %q", got)
	}
}

// TestRelayNonVPNBytesNeverReachUpstream verifies that the upstream echo server
// does NOT receive anything when the client sends a non-VPN probe: the relay
// must intercept and serve the decoy without forwarding to the upstream.
func TestRelayNonVPNBytesNeverReachUpstream(t *testing.T) {
	// Use an upstream that records whether it received a connection.
	connected := make(chan struct{}, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		connected <- struct{}{}
		c.Close()
	}()

	relay := startRelayWithUpstream(t, ln.Addr().String())

	conn, err := net.DialTimeout("tcp", relay, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	// Non-VPN probe.
	conn.Write([]byte{0x00}) //nolint:errcheck

	// Give the relay time to handle the connection.
	time.Sleep(200 * time.Millisecond)

	select {
	case <-connected:
		t.Fatal("upstream received a connection from a non-VPN probe — relay failed to intercept")
	default:
		// Good: upstream was not contacted.
	}
}
