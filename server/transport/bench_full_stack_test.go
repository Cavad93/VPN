package transport

// Full-stack VPN throughput benchmark.
//
// Run:
//   cd server && go test ./transport/ -run "TestBench" -v -timeout 60s

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeTCPPair(t testing.TB) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var sConn net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sConn, _ = ln.Accept()
	}()
	cConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if sConn == nil {
		t.Fatal("server conn nil")
	}
	return cConn, sConn
}

// TestBenchRawTCP — baseline: raw TCP loopback throughput.
func TestBenchRawTCP(t *testing.T) {
	const totalBytes int64 = 50_000_000
	client, server := makeTCPPair(t)
	defer client.Close()
	defer server.Close()

	var received int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for received < totalBytes {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(&received, int64(n))
		}
	}()

	data := make([]byte, 1400)
	rand.Read(data)
	start := time.Now()
	var sent int64
	for sent < totalBytes {
		n, err := client.Write(data)
		if err != nil {
			t.Fatal(err)
		}
		sent += int64(n)
	}
	wg.Wait()
	elapsed := time.Since(start)
	mbps := float64(atomic.LoadInt64(&received)) * 8 / elapsed.Seconds() / 1e6

	t.Logf("Raw TCP:  %.0f Mbps  (%d MB in %v)", mbps, totalBytes/1e6, elapsed.Round(time.Millisecond))
}

// TestBenchFramedTCP — 2-byte length-prefixed framing over TCP.
func TestBenchFramedTCP(t *testing.T) {
	const totalBytes int64 = 50_000_000
	const pktSize = 1400

	client, server := makeTCPPair(t)
	defer client.Close()
	defer server.Close()

	var received int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var hdr [2]byte
		for received < totalBytes {
			if _, err := io.ReadFull(server, hdr[:]); err != nil {
				return
			}
			frameLen := int(binary.BigEndian.Uint16(hdr[:]))
			buf := make([]byte, frameLen)
			if _, err := io.ReadFull(server, buf); err != nil {
				return
			}
			atomic.AddInt64(&received, int64(frameLen))
		}
	}()

	data := make([]byte, pktSize)
	rand.Read(data)
	frame := make([]byte, 2+pktSize)
	binary.BigEndian.PutUint16(frame[:2], uint16(pktSize))
	copy(frame[2:], data)

	start := time.Now()
	var sent int64
	for sent < totalBytes {
		if _, err := client.Write(frame); err != nil {
			t.Fatal(err)
		}
		sent += pktSize
	}
	wg.Wait()
	elapsed := time.Since(start)
	mbps := float64(atomic.LoadInt64(&received)) * 8 / elapsed.Seconds() / 1e6

	t.Logf("Framed TCP (Noise-like):  %.0f Mbps  (%d MB in %v)", mbps, totalBytes/1e6, elapsed.Round(time.Millisecond))
}

// TestBenchMuxTCP — full Mux + framing over TCP loopback.
func TestBenchMuxTCP(t *testing.T) {
	const totalBytes int64 = 50_000_000
	const pktSize = 1400
	const targetMbps = 7.64

	client, server := makeTCPPair(t)
	defer client.Close()
	defer server.Close()

	if tc, ok := client.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	if tc, ok := server.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	// Wrap: TCP → testNoiseConn (framing) → Mux → Stream
	cNoise := &testFramer{conn: client}
	sNoise := &testFramer{conn: server}

	cMux := NewMux(cNoise, true)
	sMux := NewMux(sNoise, false)

	// Handshake: client opens stream, server accepts.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	var sStream *Stream
	go func() {
		var err error
		sStream, err = sMux.AcceptStream(ctx)
		errCh <- err
	}()
	cStream, err := cMux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	var received int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for atomic.LoadInt64(&received) < totalBytes {
			n, err := sStream.Read(buf)
			if err != nil {
				t.Logf("read error after %d bytes: %v", atomic.LoadInt64(&received), err)
				return
			}
			atomic.AddInt64(&received, int64(n))
		}
	}()

	data := make([]byte, pktSize)
	rand.Read(data)
	start := time.Now()
	var sent int64
	for sent < totalBytes {
		n, err := cStream.Write(data)
		if err != nil {
			t.Fatalf("write error at %d bytes: %v", sent, err)
		}
		sent += int64(n)
	}
	wg.Wait()
	cMux.Close()
	sMux.Close()
	elapsed := time.Since(start)
	rcv := atomic.LoadInt64(&received)
	mbps := float64(rcv) * 8 / elapsed.Seconds() / 1e6

	t.Logf("═══════════════════════════════════════════════════")
	t.Logf("  Mux+Framing over TCP:  %.0f Mbps", mbps)
	t.Logf("  Data: %d MB, Elapsed: %v", rcv/1e6, elapsed.Round(time.Millisecond))
	t.Logf("  Target: %.1f Mbps  →  headroom: %.0f×", targetMbps, mbps/targetMbps)
	t.Logf("═══════════════════════════════════════════════════")

	if mbps > targetMbps*2 {
		t.Logf("✓ Server processing NOT a bottleneck (%.0f× headroom)", mbps/targetMbps)
	} else {
		t.Errorf("✗ Server processing may be a bottleneck (only %.1f× headroom)", mbps/targetMbps)
	}
}

// testFramer — 2-byte length-prefixed framing (same wire as noiseConn).
type testFramer struct {
	conn    net.Conn
	readBuf []byte
}

func (f *testFramer) Write(p []byte) (int, error) {
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
	copy(frame[2:], p)
	_, err := f.conn.Write(frame)
	return len(p), err
}

func (f *testFramer) Read(p []byte) (int, error) {
	if len(f.readBuf) > 0 {
		n := copy(p, f.readBuf)
		f.readBuf = f.readBuf[n:]
		return n, nil
	}
	var hdr [2]byte
	if _, err := io.ReadFull(f.conn, hdr[:]); err != nil {
		return 0, err
	}
	fl := int(binary.BigEndian.Uint16(hdr[:]))
	if fl == 0 {
		return 0, fmt.Errorf("zero frame")
	}
	buf := make([]byte, fl)
	if _, err := io.ReadFull(f.conn, buf); err != nil {
		return 0, err
	}
	n := copy(p, buf)
	if n < len(buf) {
		f.readBuf = buf[n:]
	}
	return n, nil
}

func (f *testFramer) Close() error                       { return f.conn.Close() }
func (f *testFramer) LocalAddr() net.Addr                { return f.conn.LocalAddr() }
func (f *testFramer) RemoteAddr() net.Addr               { return f.conn.RemoteAddr() }
func (f *testFramer) SetDeadline(t time.Time) error      { return f.conn.SetDeadline(t) }
func (f *testFramer) SetReadDeadline(t time.Time) error  { return f.conn.SetReadDeadline(t) }
func (f *testFramer) SetWriteDeadline(t time.Time) error { return f.conn.SetWriteDeadline(t) }
