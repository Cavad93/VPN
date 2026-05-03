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

	orig := relayDialTimeout()
	setRelayDialTimeout(200 * time.Millisecond)
	t.Cleanup(func() { setRelayDialTimeout(orig) })

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
	orig := relayPipeTimeout()
	setRelayPipeTimeout(500 * time.Millisecond)
	t.Cleanup(func() { setRelayPipeTimeout(orig) })

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

// ---------------------------------------------------------------------------
// Tests for makeRelayAddrKey — zero-alloc UDP session map key
// ---------------------------------------------------------------------------

// TestMakeRelayAddrKey_IPv4 verifies that a 4-byte IPv4 UDPAddr produces the
// expected IPv4-in-IPv6 representation and the correct port.
func TestMakeRelayAddrKey_IPv4(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 51000}
	key := makeRelayAddrKey(addr)

	if key.port != 51000 {
		t.Fatalf("port: got %d, want 51000", key.port)
	}
	// Bytes 10-11 must be 0xff (IPv4-in-IPv6 marker).
	if key.ip[10] != 0xff || key.ip[11] != 0xff {
		t.Fatalf("IPv4-in-IPv6 marker missing: ip[10:12] = %v", key.ip[10:12])
	}
	if key.ip[12] != 1 || key.ip[13] != 2 || key.ip[14] != 3 || key.ip[15] != 4 {
		t.Fatalf("IPv4 octets wrong: ip[12:16] = %v", key.ip[12:16])
	}
	if key.zone != "" {
		t.Fatalf("zone should be empty for IPv4, got %q", key.zone)
	}
}

// TestMakeRelayAddrKey_IPv4MappedIPv6 verifies that a 16-byte IPv4-mapped IPv6
// address (::ffff:1.2.3.4) produces the SAME key as the 4-byte IPv4 form.
// This is the normalization test — dual-stack sockets may return either form.
func TestMakeRelayAddrKey_IPv4MappedIPv6(t *testing.T) {
	addr4 := &net.UDPAddr{IP: net.IP{1, 2, 3, 4}, Port: 51000}
	addr16 := &net.UDPAddr{
		IP:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4},
		Port: 51000,
	}
	key4 := makeRelayAddrKey(addr4)
	key16 := makeRelayAddrKey(addr16)

	if key4 != key16 {
		t.Fatalf("IPv4 and IPv4-mapped-IPv6 keys differ:\n  4-byte: %v\n  16-byte: %v", key4, key16)
	}
}

// TestMakeRelayAddrKey_IPv6 verifies that a native IPv6 address is stored
// correctly and that the zone field is preserved.
func TestMakeRelayAddrKey_IPv6(t *testing.T) {
	ip6 := net.ParseIP("2001:db8::1")
	addr := &net.UDPAddr{IP: ip6, Port: 12345, Zone: "eth0"}
	key := makeRelayAddrKey(addr)

	if key.port != 12345 {
		t.Fatalf("port: got %d, want 12345", key.port)
	}
	if key.zone != "eth0" {
		t.Fatalf("zone: got %q, want %q", key.zone, "eth0")
	}
	var want [16]byte
	copy(want[:], ip6.To16())
	if key.ip != want {
		t.Fatalf("IPv6 ip field wrong:\n  got:  %v\n  want: %v", key.ip, want)
	}
}

// TestMakeRelayAddrKey_DifferentPortsDifferentKeys verifies that two addresses
// with the same IP but different ports produce distinct keys.
func TestMakeRelayAddrKey_DifferentPortsDifferentKeys(t *testing.T) {
	base := net.IP{10, 0, 0, 1}
	key1 := makeRelayAddrKey(&net.UDPAddr{IP: base, Port: 1111})
	key2 := makeRelayAddrKey(&net.UDPAddr{IP: base, Port: 2222})
	if key1 == key2 {
		t.Fatal("different ports should produce different keys")
	}
}

// TestMakeRelayAddrKey_DifferentIPsDifferentKeys verifies that two addresses
// with different IPs but the same port produce distinct keys.
func TestMakeRelayAddrKey_DifferentIPsDifferentKeys(t *testing.T) {
	key1 := makeRelayAddrKey(&net.UDPAddr{IP: net.IP{10, 0, 0, 1}, Port: 5000})
	key2 := makeRelayAddrKey(&net.UDPAddr{IP: net.IP{10, 0, 0, 2}, Port: 5000})
	if key1 == key2 {
		t.Fatal("different IPs should produce different keys")
	}
}

// TestMakeRelayAddrKey_NonUDPFallback verifies that a non-UDPAddr type does
// not panic and returns a key whose zone field contains the string representation.
func TestMakeRelayAddrKey_NonUDPFallback(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IP{1, 2, 3, 4}, Port: 80}
	key := makeRelayAddrKey(addr)
	if key.zone == "" {
		t.Fatal("non-UDPAddr fallback should populate zone with String() representation")
	}
	if key.port != 0 {
		t.Fatalf("non-UDPAddr fallback should have port=0, got %d", key.port)
	}
}

// ---------------------------------------------------------------------------
// udpRelayPktPool tests
// ---------------------------------------------------------------------------

// TestUDPRelayPktPool_GetPut verifies the pool contract: Get returns a
// udpBufSize-capacity buffer; Put returns it for reuse.
func TestUDPRelayPktPool_GetPut(t *testing.T) {
	pb := udpRelayPktPool.Get().(*[]byte)
	if cap(*pb) != udpBufSize {
		t.Fatalf("pool buffer cap = %d, want %d", cap(*pb), udpBufSize)
	}
	udpRelayPktPool.Put(pb)
}

// TestUDPRelayPktPool_ResliceAndRestore verifies the reslice-and-restore
// pattern used in runUDPRelay: set length to n, use, restore to cap.
func TestUDPRelayPktPool_ResliceAndRestore(t *testing.T) {
	pb := udpRelayPktPool.Get().(*[]byte)

	n := 42
	*pb = (*pb)[:n]
	copy(*pb, bytes.Repeat([]byte{0xAB}, n))

	if len(*pb) != n {
		t.Fatalf("after reslice: len=%d, want %d", len(*pb), n)
	}
	// Restore full capacity before Put (mimics upstream writer goroutine).
	*pb = (*pb)[:cap(*pb)]
	if len(*pb) != udpBufSize {
		t.Fatalf("after restore: len=%d, want %d", len(*pb), udpBufSize)
	}
	udpRelayPktPool.Put(pb)
}

// TestUDPRelayPktPool_DataIntegrity verifies that packet data survives the
// Get→reslice→copy→Write(*pb) round-trip without corruption.
func TestUDPRelayPktPool_DataIntegrity(t *testing.T) {
	payload := []byte("hello pool 12345")
	n := len(payload)

	pb := udpRelayPktPool.Get().(*[]byte)
	*pb = (*pb)[:n]
	copy(*pb, payload)

	if !bytes.Equal(*pb, payload) {
		t.Fatalf("data mismatch after copy: got %q want %q", *pb, payload)
	}

	*pb = (*pb)[:cap(*pb)]
	udpRelayPktPool.Put(pb)
}

// TestUDPRelayDroppedPacketReturnsToPool verifies the drop path: when the
// sendCh is full, the pool buffer must be returned (not leaked).
// We verify this indirectly by checking no panic occurs and the pool
// is still functional after the return.
func TestUDPRelayDroppedPacketReturnsToPool(t *testing.T) {
	pb := udpRelayPktPool.Get().(*[]byte)
	n := 100
	*pb = (*pb)[:n]
	// Simulate the drop path: channel full → return to pool.
	*pb = (*pb)[:cap(*pb)]
	udpRelayPktPool.Put(pb)

	// Pool must still be usable.
	pb2 := udpRelayPktPool.Get().(*[]byte)
	if cap(*pb2) != udpBufSize {
		t.Fatalf("pool unusable after drop-path Put: cap=%d", cap(*pb2))
	}
	udpRelayPktPool.Put(pb2)
}

// TestUDPRelayEndToEnd_PoolIntegration verifies that the end-to-end relay
// (including the pool path) forwards variable-size packets correctly.
func TestUDPRelayEndToEnd_PoolIntegration(t *testing.T) {
	echo := startUDPEchoServer(t)
	relay := startUDPRelay(t, echo)

	conn, err := net.Dial("udp", relay)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Send packets of different sizes to exercise pool reslicing.
	for _, size := range []int{1, 100, 1430, 4096} {
		payload := bytes.Repeat([]byte{byte(size & 0xFF)}, size)
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write size=%d: %v", size, err)
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read size=%d: %v", size, err)
		}
		if !bytes.Equal(buf, payload) {
			t.Fatalf("size=%d: echo mismatch", size)
		}
	}
}
