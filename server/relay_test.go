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
	go runRelay(ctx, addr, upstream, nil, logger) //nolint:errcheck

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

	// The cover website should serve Pork Kitchen content (not a raw 400).
	if !bytes.Contains(resp, []byte("Pork Kitchen")) {
		t.Fatalf("expected cover website 'Pork Kitchen' in response, got: %q", resp)
	}
	if bytes.Contains(resp, []byte("Server: nginx")) {
		t.Fatalf("should NOT have nginx Server header (JA3S mismatch), got: %q", resp)
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

// TestIdleTimeoutConnResetsDeadlinePerOp verifies that idleTimeoutConn resets
// the deadline before every Read/Write, so an active connection survives
// beyond the timeout period (previously it was killed by the absolute deadline).
func TestIdleTimeoutConnResetsDeadlinePerOp(t *testing.T) {
	// Short idle timeout for the test.
	timeout := 100 * time.Millisecond

	// Create a pipe — we control both ends.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wrapped := &idleTimeoutConn{Conn: client, timeout: timeout}

	// Writer goroutine: send data every 50ms (well within the 100ms idle timeout)
	// for a total of 400ms (4× the timeout). If the old absolute-deadline code
	// were used, the connection would die after 100ms.
	errCh := make(chan error, 1)
	go func() {
		for i := 0; i < 8; i++ {
			time.Sleep(50 * time.Millisecond)
			if _, err := wrapped.Write([]byte{byte(i)}); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	// Reader goroutine on the server end.
	go func() {
		buf := make([]byte, 1)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("write failed (idle timeout killed active connection): %v", err)
		}
		// Success: all 8 writes completed across 400ms with a 100ms idle timeout.
	case <-time.After(2 * time.Second):
		t.Fatal("test timed out")
	}
}

// TestIdleTimeoutConnKillsIdleConnection verifies that an idle connection
// is properly terminated after the timeout elapses.
func TestIdleTimeoutConnKillsIdleConnection(t *testing.T) {
	timeout := 200 * time.Millisecond

	// Use a real TCP connection (net.Pipe is synchronous, Write blocks until Read).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept in background.
	serverCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serverCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := <-serverCh
	defer server.Close()

	wrapped := &idleTimeoutConn{Conn: client, timeout: timeout}

	// Do one write to verify the connection works.
	if _, err := wrapped.Write([]byte{0x42}); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	buf := make([]byte, 1)
	server.Read(buf) //nolint:errcheck

	// Now try to read from the wrapped conn — it should timeout after ~200ms
	// because no data arrives and the idle timeout expires.
	readErr := make(chan error, 1)
	go func() {
		_, err := wrapped.Read(buf)
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected timeout error on idle connection, got nil")
		}
		if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
			t.Fatalf("expected timeout/deadline error, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read did not timeout — idle timeout not working")
	}
}

// TestRelayActiveConnectionSurvivesPastTimeout verifies that an end-to-end
// relay connection with continuous traffic survives beyond relayPipeTimeout.
// This is a regression test for the absolute-deadline bug.
//
// We use 500ms idle timeout and send data every 100ms for 2 seconds (4× the
// timeout). With the old absolute-deadline code, the connection would die
// after 500ms regardless of activity. With idleTimeoutConn, each Read/Write
// resets the deadline so the connection survives.
func TestRelayActiveConnectionSurvivesPastTimeout(t *testing.T) {
	// Set a short pipe timeout for the test — long enough for the relay to
	// set up (dial echo, start pipes) but short enough to detect the old bug
	// within a reasonable test duration.
	orig := relayPipeTimeout
	relayPipeTimeout = 500 * time.Millisecond
	t.Cleanup(func() { relayPipeTimeout = orig })

	echo := startEchoServer(t)
	relay := startRelayWithUpstream(t, echo)

	conn, err := net.DialTimeout("tcp", relay, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	// Send TLS-like first byte so it passes the VPN check.
	if _, err := conn.Write([]byte{0x16}); err != nil {
		t.Fatalf("write VPN byte: %v", err)
	}
	// Read back the echoed byte — the relay must forward it to echo and back.
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read initial echo: %v", err)
	}

	// Now send data every 100ms for 2 seconds (4× the 500ms idle timeout).
	// Under the old absolute-deadline code, this would fail after ~500ms.
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		msg := []byte{byte(i + 1)}
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write %d failed (active conn killed by absolute deadline?): %v", i, err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read echo %d failed: %v", i, err)
		}
		if buf[0] != msg[0] {
			t.Fatalf("echo mismatch at %d: got %d want %d", i, buf[0], msg[0])
		}
	}
	// Success: 2 seconds of active traffic with 500ms idle timeout — connection survived.
}
