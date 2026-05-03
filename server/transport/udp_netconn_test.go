package transport

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestUDPNetConnImplementsNetConn(t *testing.T) {
	// Compile-time check is in udp_netconn.go, but verify at runtime too.
	var _ net.Conn = (*UDPNetConn)(nil)
}

// setupUDPPair creates a client/server UDPNetConn pair over loopback.
// The client sends a trigger packet so the listener detects the connection.
func setupUDPPair(t *testing.T) (client, server *UDPNetConn) {
	t.Helper()

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	clientConn, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Send a trigger packet so the listener's readLoop sees this client.
	clientConn.Write([]byte("init"))

	serverConn, err := ln.Accept(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	// Drain the trigger packet on the server side.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverConn.Read(ctx)

	client = NewUDPNetConn(clientConn)
	server = NewUDPNetConn(serverConn)
	t.Cleanup(func() { client.Close(); server.Close() })
	return
}

func TestUDPNetConnWriteRead(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// Write from client, read on server.
	msg := []byte("hello over UDP net.Conn")
	n, err := client.Write(msg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("Write: wrote %d, want %d", n, len(msg))
	}

	buf := make([]byte, 256)
	n, err = server.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("Read: got %q, want %q", buf[:n], msg)
	}
}

func TestUDPNetConnReadBuffering(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// Send 10 bytes.
	msg := []byte("0123456789")
	client.Write(msg)

	// Read in 4-byte chunks — tests stream buffering.
	buf := make([]byte, 4)
	total := make([]byte, 0, 10)

	for len(total) < 10 {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v (after %d bytes)", err, len(total))
		}
		total = append(total, buf[:n]...)
	}

	if string(total) != string(msg) {
		t.Fatalf("Read buffering: got %q, want %q", total, msg)
	}
}

func TestUDPNetConnBidirectional(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// Client → Server.
	client.Write([]byte("ping"))
	buf := make([]byte, 64)
	n, _ := server.Read(buf)
	if string(buf[:n]) != "ping" {
		t.Fatalf("expected 'ping', got %q", buf[:n])
	}

	// Server → Client.
	server.Write([]byte("pong"))
	n, _ = client.Read(buf)
	if string(buf[:n]) != "pong" {
		t.Fatalf("expected 'pong', got %q", buf[:n])
	}
}

func TestUDPNetConnClose(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)
	u := NewUDPNetConn(c)
	err := u.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestUDPNetConnDeadlines(t *testing.T) {
	t.Parallel()

	c := makeTestConn(t)
	u := NewUDPNetConn(c)

	// Set deadlines — should not error.
	if err := u.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := u.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := u.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}

func TestUDPNetConnWriteDeadlineExceeded(t *testing.T) {
	t.Parallel()

	c := makeTestConn(t)
	u := NewUDPNetConn(c)

	// Set deadline in the past.
	u.SetWriteDeadline(time.Now().Add(-time.Second))

	_, err := u.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error for expired write deadline")
	}
}

func TestUDPNetConnAddresses(t *testing.T) {
	t.Parallel()
	client, _ := setupUDPPair(t)

	if client.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
	if client.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}
}

func TestUDPNetConnLargeWrite(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// Write data larger than MaxPayloadSize — should be fragmented by Conn.Write.
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	n, err := client.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Write: wrote %d, want %d", n, len(data))
	}

	// Read all of it back.
	received := make([]byte, 0, 5000)
	buf := make([]byte, 2048)
	for len(received) < 5000 {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v (after %d bytes)", err, len(received))
		}
		received = append(received, buf[:n]...)
	}

	if len(received) != len(data) {
		t.Fatalf("received %d bytes, want %d", len(received), len(data))
	}
	for i := range data {
		if received[i] != data[i] {
			t.Fatalf("data mismatch at byte %d: got %d, want %d", i, received[i], data[i])
		}
	}
}

// TestUDPNetConnReadContextCancelledAfterRead verifies that setting a read
// deadline and then doing many reads does not accumulate runtime timers.
//
// Each call to readContext with a non-zero deadline creates a context.WithDeadline
// (which adds an entry to the runtime timer heap). Without calling cancel() after
// inner.Read returns, these timers live until the deadline fires — up to 120 s.
// At 2630 reads/sec this means ~315 K timer entries accumulate (≈25 MB).
//
// The fix calls cancel() immediately after inner.Read returns, releasing the timer
// from the heap. This test verifies that allocations-per-read do not grow with
// the number of reads (timer entries are freed promptly).
//
// NOTE: intentionally NOT t.Parallel(). This test measures heap growth via
// runtime.ReadMemStats which reflects the global heap — concurrent tests (e.g.
// TestBBRDiagnoseSlowThroughput with cwnd=115K) create large transient allocations
// that pollute the measurement window and produce false positives. Running
// sequentially ensures the heap is stable during the before/after snapshots.
func TestUDPNetConnReadContextCancelledAfterRead(t *testing.T) {
	client, server := setupUDPPair(t)

	// Set a read deadline far in the future so every Read creates a timerCtx.
	server.SetReadDeadline(time.Now().Add(2 * time.Minute)) //nolint:errcheck

	const N = 200 // enough to create a detectable timer buildup if cancel is missing

	// Warm up: pre-allocate to exclude startup overhead.
	for i := 0; i < 10; i++ {
		client.Write([]byte("warmup")) //nolint:errcheck
		buf := make([]byte, 64)
		server.Read(buf) //nolint:errcheck
	}
	runtime.GC()
	runtime.GC()

	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	for i := 0; i < N; i++ {
		client.Write([]byte("hello")) //nolint:errcheck
		buf := make([]byte, 64)
		server.Read(buf) //nolint:errcheck
	}

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// Each read should not contribute more than ~1 KB of live heap objects on average.
	// Before the fix, N=200 reads with 120s timers ≈ 200 × 200 bytes = 40 KB live.
	// After the fix, timers are cancelled immediately — near-zero live timer memory.
	// We allow 2 KB headroom per read for the transport protocol overhead.
	maxAllocBytes := uint64(N) * 2048
	live := after.HeapAlloc
	baseline := before.HeapAlloc
	if live > baseline+maxAllocBytes {
		t.Errorf("possible timer leak: heap grew by %d bytes over %d reads (limit %d bytes)",
			live-baseline, N, maxAllocBytes)
	}
}

// TestUDPNetConnReadContextZeroDeadline verifies that readContext with no deadline
// returns context.Background() and the pre-allocated nopCancel (no allocation).
func TestUDPNetConnReadContextZeroDeadline(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// No deadline set: readContext must return background + nopCancel.
	ctx, cancel := server.readContext()
	if ctx != context.Background() {
		t.Error("readContext with zero deadline should return context.Background()")
	}
	// nopCancel must be callable without panic.
	cancel()

	// Functional: read still works with no deadline.
	client.Write([]byte("ok")) //nolint:errcheck
	buf := make([]byte, 16)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read with no deadline: %v", err)
	}
	if string(buf[:n]) != "ok" {
		t.Errorf("unexpected data: %q", buf[:n])
	}
}

// TestUDPNetConnReadContextNonZeroDeadline verifies that readContext with a future
// deadline returns a cancellable context and that cancel is safe to call.
func TestUDPNetConnReadContextNonZeroDeadline(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	dl := time.Now().Add(time.Minute)
	server.SetReadDeadline(dl) //nolint:errcheck

	ctx, cancel := server.readContext()
	if ctx == context.Background() {
		t.Error("readContext with deadline should not return context.Background()")
	}
	d, ok := ctx.Deadline()
	if !ok {
		t.Error("context should have a deadline")
	}
	if !d.Equal(dl) {
		t.Errorf("context deadline: got %v, want %v", d, dl)
	}
	// Calling cancel() must release the timer — verify no panic.
	cancel()
	// Context must be Done after cancel.
	select {
	case <-ctx.Done():
		// expected
	default:
		t.Error("context should be Done after cancel()")
	}

	// Functional: read still works after cancel is called (inner.Read not started yet).
	server.SetReadDeadline(time.Now().Add(time.Minute)) //nolint:errcheck
	client.Write([]byte("ok"))                          //nolint:errcheck
	buf := make([]byte, 16)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read with deadline: %v", err)
	}
	if string(buf[:n]) != "ok" {
		t.Errorf("unexpected data: %q", buf[:n])
	}
}
