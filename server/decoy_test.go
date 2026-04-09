package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// --- test helpers -----------------------------------------------------------

// newLocalTCPPair dials a loopback listener and returns the two ends as
// (clientConn, serverConn).  The listener is closed immediately after Accept.
// Both conns are registered for cleanup on t.
func newLocalTCPPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(acceptCh)
			return
		}
		acceptCh <- c
	}()
	cConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}
	ln.Close()
	sConn := <-acceptCh
	if sConn == nil {
		cConn.Close()
		t.Fatal("server accept returned nil")
	}
	t.Cleanup(func() { cConn.Close(); sConn.Close() })
	return cConn, sConn
}

// pipeConn returns a net.Pipe pair for tests that only need one-directional
// I/O at a time (no concurrent read+write on the same side).
func pipeConn(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

// --- peekConn tests ---------------------------------------------------------

func TestPeekConnReplaysByte(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	// Server side: wrap in peekConn with peeked byte 0x16.
	pc := &peekConn{Conn: sConn, peeked: 0x16}

	// Client: send 3 more bytes.
	go func() {
		cConn.Write([]byte{0x03, 0x03, 0x01}) //nolint:errcheck
		cConn.Close()
	}()

	// First Read must start with the peeked byte.
	buf := make([]byte, 4)
	sConn.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := pc.Read(buf)
	if n == 0 {
		t.Fatal("expected at least 1 byte")
	}
	if buf[0] != 0x16 {
		t.Fatalf("first byte: got 0x%02x, want 0x16", buf[0])
	}
}

func TestPeekConnOneByte(t *testing.T) {
	_, sConn := pipeConn(t)
	pc := &peekConn{Conn: sConn, peeked: 0x42}

	buf := make([]byte, 1)
	n, err := pc.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 byte, got %d", n)
	}
	if buf[0] != 0x42 {
		t.Fatalf("got 0x%02x, want 0x42", buf[0])
	}
}

func TestPeekConnZeroLenBuffer(t *testing.T) {
	_, sConn := pipeConn(t)
	pc := &peekConn{Conn: sConn, peeked: 0x16}

	n, err := pc.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("zero-len read: got n=%d err=%v", n, err)
	}
	// Peeked byte must still be available after the no-op read.
	if pc.used {
		t.Fatal("zero-len Read should not consume the peeked byte")
	}
}

func TestPeekConnUsedFlagAfterFirstRead(t *testing.T) {
	_, sConn := pipeConn(t)
	pc := &peekConn{Conn: sConn, peeked: 0xAB}

	buf := make([]byte, 1)
	pc.Read(buf) //nolint:errcheck

	if !pc.used {
		t.Fatal("used flag must be true after first real Read")
	}
}

func TestPeekConnSubsequentReadsGoThroughConn(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	go func() {
		cConn.Write([]byte{0x01, 0x02}) //nolint:errcheck
		cConn.Close()
	}()

	pc := &peekConn{Conn: sConn, peeked: 0xFF}

	// Consume peeked byte.
	first := make([]byte, 1)
	pc.Read(first) //nolint:errcheck

	// Second read must get real wire data.
	second := make([]byte, 2)
	sConn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := pc.Read(second)
	if err != nil && err != io.EOF {
		t.Fatalf("second read err: %v", err)
	}
	if n > 0 && second[0] != 0x01 {
		t.Fatalf("expected 0x01 from wire, got 0x%02x", second[0])
	}
}

// --- peekAndRoute tests -----------------------------------------------------

func TestPeekAndRouteVPNClientPassesThrough(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	// Client sends TLS ClientHello first byte (0x16) followed by more data.
	go func() {
		cConn.Write([]byte{0x16, 0x03, 0x03, 0x00}) //nolint:errcheck
	}()

	routed, ok := peekAndRoute(sConn)
	if !ok {
		t.Fatal("expected VPN path (ok=true)")
	}
	if routed == nil {
		t.Fatal("expected non-nil routed conn")
	}

	// First byte must be replayed.
	buf := make([]byte, 1)
	routed.SetReadDeadline(time.Now().Add(time.Second))
	n, err := routed.Read(buf)
	if err != nil {
		t.Fatalf("read from routed conn: %v", err)
	}
	if n != 1 || buf[0] != 0x16 {
		t.Fatalf("first byte replayed: got 0x%02x (n=%d)", buf[0], n)
	}
}

func TestPeekAndRouteHTTPScannerGetsCookingBlog(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	// Client sends an HTTP GET (first byte 'G' = 0x47).
	go func() {
		cConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) //nolint:errcheck
	}()

	routed, ok := peekAndRoute(sConn)
	if ok || routed != nil {
		t.Fatal("expected fallback path (ok=false, routed=nil)")
	}

	// Client must receive the fallback cooking blog then EOF.
	cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := io.ReadAll(cConn)
	if err != nil && err != io.EOF {
		msg := err.Error()
		if !strings.Contains(msg, "closed") &&
			!strings.Contains(msg, "reset by peer") &&
			!strings.Contains(msg, "connection reset") {
			t.Fatalf("unexpected error reading fallback response: %v", err)
		}
	}

	// Fallback serves the cooking blog (200 OK) instead of old 400 decoy.
	if !bytes.Contains(resp, []byte("HTTP/1.1 200")) {
		t.Fatalf("expected 200 OK in fallback, got: %q", resp)
	}
	if !bytes.Contains(resp, []byte("nginx/1.24.0")) {
		t.Fatalf("expected nginx Server header, got: %q", resp)
	}
	// Verify actual blog content is present.
	if !bytes.Contains(resp, []byte("Домашняя кухня")) {
		t.Fatalf("expected cooking blog content, got: %q", resp)
	}
}

func TestPeekAndRouteRawTCPScannerGetsDecoy(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	// Scanner sends a raw non-TLS byte (e.g., null probe).
	go func() {
		cConn.Write([]byte{0x00}) //nolint:errcheck
	}()

	routed, ok := peekAndRoute(sConn)
	if ok || routed != nil {
		t.Fatal("expected decoy path for non-TLS first byte")
	}

	cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, _ := io.ReadAll(cConn)
	if !bytes.Contains(resp, []byte("400 Bad Request")) {
		t.Fatalf("expected 400 decoy response, got: %q", resp)
	}
}

func TestPeekAndRouteSilentlyClosesOnTimeout(t *testing.T) {
	// Override the read deadline to something short so the test finishes fast.
	orig := decoyReadDeadline()
	setDecoyReadDeadline(50 * time.Millisecond)
	t.Cleanup(func() { setDecoyReadDeadline(orig) })

	cConn, sConn := newLocalTCPPair(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Server side: client never sends data → deadline fires.
		routed, ok := peekAndRoute(sConn)
		if ok || routed != nil {
			t.Errorf("expected decoy path on timeout")
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("peekAndRoute did not return after timeout")
	}

	// cConn should be closed — Read returns an error or EOF.
	cConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, err := cConn.Read(make([]byte, 1))
	if n != 0 && err == nil {
		t.Fatal("expected 0 bytes / error after server closed the connection")
	}
}

func TestPeekAndRouteByte0x16IsOnlyVPNPath(t *testing.T) {
	// Override deadline so sub-tests run quickly.
	orig := decoyReadDeadline()
	setDecoyReadDeadline(50 * time.Millisecond)
	t.Cleanup(func() { setDecoyReadDeadline(orig) })

	nonVPNBytes := []byte{0x00, 0x01, 0x14, 0x15, 0x17, 0x47 /*'G'*/, 0xFF}

	for _, b := range nonVPNBytes {
		b := b
		t.Run(fmt.Sprintf("0x%02x", b), func(t *testing.T) {
			cConn, sConn := newLocalTCPPair(t)
			go func() {
				cConn.Write([]byte{b}) //nolint:errcheck
				// Close write side so serveFallback's http.ReadRequest
				// gets EOF quickly for HTTP-method bytes like 'G'.
				if tc, ok := cConn.(*net.TCPConn); ok {
					tc.CloseWrite() //nolint:errcheck
				}
			}()
			routed, ok := peekAndRoute(sConn)
			if ok || routed != nil {
				t.Fatalf("byte 0x%02x should trigger fallback path, got VPN path", b)
			}
		})
	}
}

// --- serveFallback tests are in fallback_test.go ---
