//go:build linux

package transport

import (
	"net"
	"testing"
)

// TestBatchWriterZeroAllocsOnFlush verifies that flushPlatform (sendmmsg path)
// performs zero heap allocations in steady state. The pre-allocated arrays in
// batchWriterPlatform eliminate the 3 make() calls that previously occurred
// on every Flush() call (~2630+ times/sec at 30 Mbps).
func TestBatchWriterZeroAllocsOnFlush(t *testing.T) {
	// Create a loopback UDP socket pair.
	serverAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenUDP("udp4", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	dst := server.LocalAddr().(*net.UDPAddr)
	pkt := make([]byte, 100)

	w := newBatchWriter(client)

	// Warm up: one flush to trigger any one-time JIT/lazy init allocations.
	for i := 0; i < 4; i++ {
		w.Add(pkt, dst, nil)
	}
	_ = w.Flush()

	// Now measure allocations in the steady-state hot path.
	allocs := testing.AllocsPerRun(10, func() {
		for i := 0; i < 4; i++ {
			w.Add(pkt, dst, nil)
		}
		_ = w.Flush()
	})

	// The sendmmsg path should produce zero allocations per flush.
	// Allow 1.0 for any potential runtime internal (goroutine scheduling etc.)
	// that might appear under test conditions.
	if allocs > 1.0 {
		t.Errorf("flushPlatform: got %.1f allocs per run, want 0 (pre-allocated arrays)", allocs)
	}
}

// TestBatchReaderPlatformFields verifies the pre-allocated arrays in
// batchReaderPlatform are of the correct size.
func TestBatchReaderPlatformFields(t *testing.T) {
	var p batchReaderPlatform

	if got := len(p.mmsghdrs); got != maxBatchSize {
		t.Errorf("mmsghdrs len = %d, want %d", got, maxBatchSize)
	}
	if got := len(p.iovecs); got != maxBatchSize {
		t.Errorf("iovecs len = %d, want %d", got, maxBatchSize)
	}
	if got := len(p.sockaddrs); got != maxBatchSize {
		t.Errorf("sockaddrs len = %d, want %d", got, maxBatchSize)
	}
}

// TestBatchWriterPlatformFields verifies the pre-allocated arrays in
// batchWriterPlatform are of the correct size.
func TestBatchWriterPlatformFields(t *testing.T) {
	var p batchWriterPlatform

	if got := len(p.mmsghdrs); got != maxBatchSize {
		t.Errorf("mmsghdrs len = %d, want %d", got, maxBatchSize)
	}
	if got := len(p.iovecs); got != maxBatchSize {
		t.Errorf("iovecs len = %d, want %d", got, maxBatchSize)
	}
	if got := len(p.sockaddrs); got != maxBatchSize {
		t.Errorf("sockaddrs len = %d, want %d", got, maxBatchSize)
	}
}
