package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cavad93/vpn/server/transport"
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

func TestPeekAndRouteHTTPScannerGetsCoverSite(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	// Client sends an HTTP GET (first byte 'G' = 0x47).
	go func() {
		cConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")) //nolint:errcheck
	}()

	routed, ok := peekAndRoute(sConn)
	if ok || routed != nil {
		t.Fatal("expected cover site path (ok=false, routed=nil)")
	}

	// Client must receive the cover website (Pork Kitchen) response then EOF.
	cConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := io.ReadAll(cConn)
	if err != nil && err != io.EOF {
		msg := err.Error()
		if !strings.Contains(msg, "closed") &&
			!strings.Contains(msg, "reset by peer") &&
			!strings.Contains(msg, "connection reset") {
			t.Fatalf("unexpected error reading cover response: %v", err)
		}
	}

	// The cover site should contain the cooking blog content.
	if !bytes.Contains(resp, []byte("Pork Kitchen")) {
		t.Fatalf("expected cover website 'Pork Kitchen' in response, got: %q", truncate(resp, 300))
	}
	// Must have nginx Server header for scanner fingerprinting.
	if !bytes.Contains(resp, []byte("nginx/1.24.0")) {
		t.Fatalf("expected nginx Server header in cover response, got: %q", truncate(resp, 300))
	}
}

func TestPeekAndRouteRawTCPScannerGetsClosed(t *testing.T) {
	// Short cover site deadline so the test doesn't wait 10 s for invalid HTTP.
	origCover := coverSiteDeadline()
	setCoverSiteDeadline(200 * time.Millisecond)
	t.Cleanup(func() { setCoverSiteDeadline(origCover) })

	cConn, sConn := newLocalTCPPair(t)

	// Scanner sends a raw non-TLS, non-HTTP byte (null probe).
	// This won't parse as HTTP, so http.ReadRequest will fail.
	go func() {
		cConn.Write([]byte{0x00}) //nolint:errcheck
	}()

	routed, ok := peekAndRoute(sConn)
	if ok || routed != nil {
		t.Fatal("expected cover site path for non-TLS first byte")
	}

	// Connection should be closed by the server side.
	cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, _ := io.ReadAll(cConn)
	// May get HTTP 400 from http.Server for malformed request, or empty.
	// Either way, we should NOT get a VPN error message.
	if bytes.Contains(resp, []byte("obfs")) || bytes.Contains(resp, []byte("noise")) {
		t.Fatalf("response should not contain VPN protocol errors, got: %q", resp)
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
	// Override deadlines so sub-tests run quickly.
	orig := decoyReadDeadline()
	setDecoyReadDeadline(50 * time.Millisecond)
	t.Cleanup(func() { setDecoyReadDeadline(orig) })
	origCover := coverSiteDeadline()
	setCoverSiteDeadline(200 * time.Millisecond)
	t.Cleanup(func() { setCoverSiteDeadline(origCover) })

	nonVPNBytes := []byte{0x00, 0x01, 0x14, 0x15, 0x17, 0x47 /*'G'*/, 0xFF}

	for _, b := range nonVPNBytes {
		b := b
		t.Run(fmt.Sprintf("0x%02x", b), func(t *testing.T) {
			cConn, sConn := newLocalTCPPair(t)
			go func() { cConn.Write([]byte{b}) }() //nolint:errcheck
			routed, ok := peekAndRoute(sConn)
			if ok || routed != nil {
				t.Fatalf("byte 0x%02x should trigger cover site path, got VPN path", b)
			}
		})
	}
}

// --- serveCoverSiteFromPeeked test -----------------------------------------

func TestServeCoverSiteFromPeekedReplaysFirstByte(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	// Simulate: first byte 'G' was already consumed, rest of HTTP request follows.
	go func() {
		// Only send the rest of the request (first 'G' was "peeked").
		cConn.Write([]byte("ET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")) //nolint:errcheck
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		serveCoverSiteFromPeeked(sConn, 'G')
	}()

	cConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(cConn)

	<-done

	if !bytes.Contains(resp, []byte("Pork Kitchen")) {
		t.Fatalf("expected cover website content after byte replay, got: %q", truncate(resp, 300))
	}
}

// --- prefixConn tests -------------------------------------------------------

func TestPrefixConnReplaysMultipleBytes(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	prefix := []byte{0x16, 0x03, 0x01, 0x00, 0x4D}
	pc := &prefixConn{Conn: sConn, prefix: prefix}

	// Client sends additional data after what was "peeked".
	go func() {
		cConn.Write([]byte{0x01, 0x02, 0x03}) //nolint:errcheck
		cConn.Close()
	}()

	// Read enough to cover prefix + wire data.
	buf := make([]byte, 8)
	sConn.SetReadDeadline(time.Now().Add(time.Second))
	total := 0
	for total < 8 {
		n, err := pc.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}

	if total != 8 {
		t.Fatalf("expected 8 bytes, got %d", total)
	}
	// First 5 bytes should be the prefix.
	if !bytes.Equal(buf[:5], prefix) {
		t.Fatalf("prefix mismatch: got %x, want %x", buf[:5], prefix)
	}
	// Next 3 bytes should be from the wire.
	if !bytes.Equal(buf[5:8], []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("wire data mismatch: got %x", buf[5:8])
	}
}

func TestPrefixConnSmallReads(t *testing.T) {
	_, sConn := pipeConn(t)
	prefix := []byte{0xAA, 0xBB, 0xCC}
	pc := &prefixConn{Conn: sConn, prefix: prefix}

	// Read 1 byte at a time from the prefix.
	for i, expected := range prefix {
		buf := make([]byte, 1)
		n, err := pc.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if n != 1 || buf[0] != expected {
			t.Fatalf("read %d: got 0x%02x, want 0x%02x", i, buf[0], expected)
		}
	}
}

// --- peekAndRouteKnock tests ------------------------------------------------

func TestPeekAndRouteKnockNilKeyDelegatesToPeekAndRoute(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	// Send TLS first byte.
	go func() {
		cConn.Write([]byte{0x16, 0x03, 0x03}) //nolint:errcheck
	}()

	// nil knockKey → behaves like peekAndRoute.
	routed, ok := peekAndRouteKnock(sConn, nil)
	if !ok {
		t.Fatal("expected VPN path with nil knock key")
	}
	if routed == nil {
		t.Fatal("expected non-nil routed conn")
	}
	// Verify first byte is replayed.
	buf := make([]byte, 1)
	routed.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := routed.Read(buf)
	if n != 1 || buf[0] != 0x16 {
		t.Fatalf("expected replayed 0x16, got 0x%02x", buf[0])
	}
}

// buildWireClientHello builds a complete TLS ClientHello with knock for testing.
func buildWireClientHello(psk transport.KnockPSK) []byte {
	var random [32]byte
	rand.Read(random[:])
	sessionID := transport.ComputeKnockTag(psk, random)

	body := make([]byte, 0, 77)
	body = append(body, 0x03, 0x03)
	body = append(body, random[:]...)
	body = append(body, 0x20)
	body = append(body, sessionID[:]...)
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
	body = append(body, 0x01, 0x00)

	hsLen := len(body)
	hs := make([]byte, 4+hsLen)
	hs[0] = 0x01
	hs[1] = byte(hsLen >> 16)
	hs[2] = byte(hsLen >> 8)
	hs[3] = byte(hsLen)
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	rec[3] = byte(len(hs) >> 8)
	rec[4] = byte(len(hs))
	copy(rec[5:], hs)

	return rec
}

func TestPeekAndRouteKnockValidKnock(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	var psk transport.KnockPSK
	rand.Read(psk[:])
	hello := buildWireClientHello(psk)

	// Also send some trailing data after the hello header.
	go func() {
		cConn.Write(hello)       //nolint:errcheck
		cConn.Write([]byte{0xFF}) //nolint:errcheck
	}()

	routed, ok := peekAndRouteKnock(sConn, &psk)
	if !ok {
		t.Fatal("expected VPN path for valid knock")
	}
	if routed == nil {
		t.Fatal("expected non-nil routed conn")
	}

	// The routed conn should replay the full header.
	buf := make([]byte, len(hello)+1)
	routed.SetReadDeadline(time.Now().Add(time.Second))
	total := 0
	for total < len(hello)+1 {
		n, err := routed.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}
	if total < len(hello) {
		t.Fatalf("expected at least %d bytes (hello), got %d", len(hello), total)
	}
	if !bytes.Equal(buf[:len(hello)], hello) {
		t.Fatal("replayed bytes don't match original hello")
	}
}

func TestPeekAndRouteKnockInvalidKnock_TLS(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	var psk transport.KnockPSK
	rand.Read(psk[:])

	// Build a hello with a DIFFERENT PSK.
	var wrongPSK transport.KnockPSK
	rand.Read(wrongPSK[:])
	hello := buildWireClientHello(wrongPSK)

	go func() {
		cConn.Write(hello) //nolint:errcheck
	}()

	// Verify with the correct PSK — should fail.
	routed, ok := peekAndRouteKnock(sConn, &psk)
	if ok || routed != nil {
		t.Fatal("expected reject for invalid knock (wrong PSK)")
	}

	// Connection should be closed.
	cConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := cConn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected connection to be closed after invalid knock")
	}
}

func TestPeekAndRouteKnockHTTPGetsCoverSite(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	var psk transport.KnockPSK
	rand.Read(psk[:])

	// Send a full HTTP request (enough to exceed 76 bytes).
	httpReq := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
	go func() {
		cConn.Write([]byte(httpReq)) //nolint:errcheck
	}()

	routed, ok := peekAndRouteKnock(sConn, &psk)
	if ok || routed != nil {
		t.Fatal("expected cover site path for HTTP request")
	}

	// Read cover site response.
	cConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(cConn)
	if !bytes.Contains(resp, []byte("Pork Kitchen")) {
		t.Fatalf("expected cover website for HTTP scanner, got: %q", truncate(resp, 300))
	}
}

func TestPeekAndRouteKnockTimeoutSilentClose(t *testing.T) {
	orig := decoyReadDeadline()
	setDecoyReadDeadline(50 * time.Millisecond)
	t.Cleanup(func() { setDecoyReadDeadline(orig) })

	cConn, sConn := newLocalTCPPair(t)

	var psk transport.KnockPSK
	rand.Read(psk[:])

	done := make(chan struct{})
	go func() {
		defer close(done)
		routed, ok := peekAndRouteKnock(sConn, &psk)
		if ok || routed != nil {
			t.Errorf("expected reject on timeout")
		}
	}()

	// Client sends nothing — timeout fires.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("peekAndRouteKnock did not return after timeout")
	}

	// Connection should be closed.
	cConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, err := cConn.Read(make([]byte, 1))
	if n != 0 && err == nil {
		t.Fatal("expected closed connection after timeout")
	}
}

// --- sendTLS13FallbackRecords tests -----------------------------------------

func TestSendTLS13FallbackRecordsWritesValidTLSRecords(t *testing.T) {
	var buf bytes.Buffer
	sendTLS13FallbackRecords(&buf)

	data := buf.Bytes()
	if len(data) < 100 {
		t.Fatalf("expected substantial TLS fallback data, got %d bytes", len(data))
	}

	// Parse the output: should be exactly 5 TLS application_data records.
	offset := 0
	recordCount := 0
	for offset < len(data) {
		if offset+5 > len(data) {
			t.Fatalf("truncated record header at offset %d", offset)
		}
		contentType := data[offset]
		if contentType != 0x17 {
			t.Fatalf("record %d: expected app_data (0x17), got 0x%02x at offset %d",
				recordCount, contentType, offset)
		}
		// Version should be TLS 1.2 (0x03 0x03)
		if data[offset+1] != 0x03 || data[offset+2] != 0x03 {
			t.Fatalf("record %d: unexpected version %02x%02x",
				recordCount, data[offset+1], data[offset+2])
		}
		length := int(data[offset+3])<<8 | int(data[offset+4])
		if length == 0 || length > 16383 {
			t.Fatalf("record %d: invalid length %d", recordCount, length)
		}
		offset += 5 + length
		recordCount++
	}

	if recordCount != 5 {
		t.Fatalf("expected 5 TLS records, got %d", recordCount)
	}
}

func TestSendTLS13FallbackRecordsSizeDistribution(t *testing.T) {
	// Run multiple times to check randomness in sizes.
	for i := 0; i < 5; i++ {
		var buf bytes.Buffer
		sendTLS13FallbackRecords(&buf)

		data := buf.Bytes()
		offset := 0
		var sizes []int
		for offset < len(data) {
			length := int(data[offset+3])<<8 | int(data[offset+4])
			sizes = append(sizes, length)
			offset += 5 + length
		}

		if len(sizes) != 5 {
			t.Fatalf("iter %d: expected 5 records, got %d", i, len(sizes))
		}
		// EncryptedExtensions: 280-429
		if sizes[0] < 280 || sizes[0] > 429 {
			t.Errorf("iter %d: EncryptedExtensions size %d out of range [280, 429]", i, sizes[0])
		}
		// Certificate: 1050-1999
		if sizes[1] < 1050 || sizes[1] > 1999 {
			t.Errorf("iter %d: Certificate size %d out of range [1050, 1999]", i, sizes[1])
		}
		// CertificateVerify: 115-194
		if sizes[2] < 115 || sizes[2] > 194 {
			t.Errorf("iter %d: CertificateVerify size %d out of range [115, 194]", i, sizes[2])
		}
		// Finished: 52-71
		if sizes[3] < 52 || sizes[3] > 71 {
			t.Errorf("iter %d: Finished size %d out of range [52, 71]", i, sizes[3])
		}
		// Alert: 19-30
		if sizes[4] < 19 || sizes[4] > 30 {
			t.Errorf("iter %d: Alert size %d out of range [19, 30]", i, sizes[4])
		}
	}
}

func TestSendPlaintextTLSAlertFormat(t *testing.T) {
	var buf bytes.Buffer
	sendPlaintextTLSAlert(&buf, 0x02, 50) // fatal + decode_error

	data := buf.Bytes()
	expected := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50}
	if !bytes.Equal(data, expected) {
		t.Fatalf("TLS alert format mismatch:\n  got:  %x\n  want: %x", data, expected)
	}
}

func TestSendPlaintextTLSAlertDifferentCodes(t *testing.T) {
	tests := []struct {
		name  string
		level byte
		desc  byte
	}{
		{"fatal_handshake_failure", 0x02, 40},
		{"fatal_decode_error", 0x02, 50},
		{"fatal_internal_error", 0x02, 80},
		{"warning_close_notify", 0x01, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			sendPlaintextTLSAlert(&buf, tt.level, tt.desc)
			data := buf.Bytes()
			if len(data) != 7 {
				t.Fatalf("expected 7 bytes, got %d", len(data))
			}
			if data[0] != 0x15 {
				t.Fatalf("content_type: got 0x%02x, want 0x15", data[0])
			}
			if data[5] != tt.level {
				t.Fatalf("level: got 0x%02x, want 0x%02x", data[5], tt.level)
			}
			if data[6] != tt.desc {
				t.Fatalf("desc: got 0x%02x, want 0x%02x", data[6], tt.desc)
			}
		})
	}
}

func TestCryptoRandIntn(t *testing.T) {
	// Verify range [0, n) for various n values.
	for _, n := range []int{1, 10, 100, 256, 1000} {
		for i := 0; i < 100; i++ {
			v := cryptoRandIntn(n)
			if v < 0 || v >= n {
				t.Fatalf("cryptoRandIntn(%d) = %d, out of range", n, v)
			}
		}
	}
	// Edge case: n=0.
	if v := cryptoRandIntn(0); v != 0 {
		t.Fatalf("cryptoRandIntn(0) = %d, want 0", v)
	}
}
