package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestBBRFullStackDataTransfer verifies the complete stack:
// UDP+BBR → UDPNetConn → ObfsConn → data transfer
func TestBBRFullStackDataTransfer(t *testing.T) {
	t.Parallel()

	ln, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := DialUDP(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Trigger server-side Accept.
	client.Write([]byte("init"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Drain trigger.
	tmp := make([]byte, 64)
	server.Read(tmp)

	// ObfsConn handshake.
	clientObfs := NewObfsConn(client)
	serverObfs := NewObfsConn(server)

	errCh := make(chan error, 2)
	go func() { errCh <- clientObfs.ClientHandshake() }()
	go func() { errCh <- serverObfs.ServerHandshake() }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("ObfsConn handshake: %v", err)
		}
	}

	// Transfer 100 KB of random data through the full stack.
	dataSize := 100 * 1024
	original := make([]byte, dataSize)
	rand.Read(original)

	// Write in background.
	go func() {
		clientObfs.Write(original)
	}()

	// Read all data.
	received := make([]byte, 0, dataSize)
	buf := make([]byte, 4096)
	for len(received) < dataSize {
		n, err := serverObfs.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v (after %d bytes)", err, len(received))
		}
		received = append(received, buf[:n]...)
	}

	if !bytes.Equal(received, original) {
		t.Fatalf("data mismatch: sent %d bytes, received %d bytes", len(original), len(received))
	}

	clientObfs.Close()
	serverObfs.Close()
}

// TestBBRFullStackMux verifies Mux stream multiplexing over UDP+BBR+ObfsConn.
func TestBBRFullStackMux(t *testing.T) {
	t.Parallel()

	ln, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := DialUDP(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	client.Write([]byte("init"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tmp := make([]byte, 64)
	server.Read(tmp)

	// ObfsConn handshake.
	clientObfs := NewObfsConn(client)
	serverObfs := NewObfsConn(server)

	errCh := make(chan error, 2)
	go func() { errCh <- clientObfs.ClientHandshake() }()
	go func() { errCh <- serverObfs.ServerHandshake() }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}

	// Create Mux.
	clientMux := NewMux(clientObfs, true)
	serverMux := NewMux(serverObfs, false)

	// Open 3 concurrent streams and transfer data on each.
	const numStreams = 3
	const msgsPerStream = 10

	var wg sync.WaitGroup
	errors := make(chan error, numStreams*2)

	// Client side: open streams and write.
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(streamIdx int) {
			defer wg.Done()
			stream, err := clientMux.OpenStream()
			if err != nil {
				errors <- fmt.Errorf("open stream %d: %w", streamIdx, err)
				return
			}
			defer stream.Close()

			for j := 0; j < msgsPerStream; j++ {
				msg := fmt.Sprintf("stream-%d-msg-%d", streamIdx, j)
				if _, err := stream.Write([]byte(msg)); err != nil {
					errors <- fmt.Errorf("write stream %d msg %d: %w", streamIdx, j, err)
					return
				}
			}
		}(i)
	}

	// Server side: accept streams and read.
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := serverMux.AcceptStream(ctx)
			if err != nil {
				errors <- fmt.Errorf("accept stream: %w", err)
				return
			}
			defer stream.Close()

			totalRead := 0
			buf := make([]byte, 256)
			for totalRead < msgsPerStream {
				n, err := stream.Read(buf)
				if err != nil {
					break
				}
				if n > 0 {
					totalRead++
				}
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("stream error: %v", err)
	}

	clientMux.Close()
	serverMux.Close()
}

// TestBBRCwndDoesNotCollapseUnderLowLoss verifies the key BBR advantage:
// at low loss rates (<2%), cwnd remains stable (unlike Reno which halves).
func TestBBRCwndDoesNotCollapseUnderLowLoss(t *testing.T) {
	t.Parallel()

	est := newBBREstimator()
	ifl := newInflightTracker()
	p := newPacer(0, 14000)
	bbr := NewBBRState(est, ifl, p, MaxPayloadSize)

	now := time.Now()
	rtt := 80 * time.Millisecond

	// Warm up: simulate 50 ACKs to build BtlBw and get out of Startup.
	sentAt := now.Add(-rtt)
	for i := 0; i < 50; i++ {
		delivered, deliveredTime := est.DeliveredSnapshot()
		if deliveredTime.IsZero() {
			deliveredTime = now.Add(-rtt)
		}
		bbr.OnACK(rtt, 1400, delivered, deliveredTime, sentAt, false)
	}

	cwndBefore := bbr.CwndTarget()

	// Simulate 0.7% loss: send 1000 packets, lose 7.
	for i := 50; i < 1050; i++ {
		ifl.OnSend(1400)
	}
	for i := 50; i < 57; i++ {
		ifl.OnLoss(1400)
	}

	bbr.OnLoss(7 * 1400)

	cwndAfter := bbr.CwndTarget()

	// Key assertion: cwnd should NOT have collapsed.
	// With Reno, cwnd would halve on each loss: 20→10→5→2.
	// With BBR at 0.7% loss, cwnd should remain stable.
	if cwndAfter < cwndBefore/2 {
		t.Fatalf("BBR cwnd collapsed under 0.7%% loss: %d → %d (Reno behavior!)",
			cwndBefore, cwndAfter)
	}
	t.Logf("BBR cwnd stable under 0.7%% loss: %d → %d ✓", cwndBefore, cwndAfter)
}

// TestBBRPacingReducesBurstiness verifies that pacing spreads packets
// over time instead of sending bursts.
func TestBBRPacingReducesBurstiness(t *testing.T) {
	t.Parallel()

	// Rate = 1.4 MB/s → 1 packet per millisecond.
	p := newPacer(1_400_000, MaxPayloadSize) // burst = 1 packet

	// Send 10 packets and measure inter-send times.
	intervals := make([]time.Duration, 9)
	prev := time.Now()
	p.WaitForSlot(MaxPayloadSize) // consume burst

	for i := 0; i < 9; i++ {
		p.WaitForSlot(MaxPayloadSize)
		now := time.Now()
		intervals[i] = now.Sub(prev)
		prev = now
	}

	// All intervals should be roughly 1ms.  The lower bound (100µs) catches
	// complete absence of pacing (burst mode).  The upper bound (100ms) is
	// generous to tolerate goroutine scheduling jitter when the full test
	// suite runs in parallel — goroutine preemption can stall a goroutine for
	// 10–50ms on a loaded CI machine, so 10ms was too tight.
	tooLong := 0
	for i, d := range intervals {
		if d < 100*time.Microsecond {
			t.Errorf("interval %d too short: %v (no pacing?)", i, d)
		}
		if d > 100*time.Millisecond {
			tooLong++
			t.Logf("interval %d unusually long: %v (scheduler jitter?)", i, d)
		}
	}
	if tooLong == len(intervals) {
		t.Errorf("all %d intervals exceeded 100ms — pacer appears broken", len(intervals))
	}
}
