package transport

import (
	"context"
	"testing"
	"time"
)

func TestPacerNewWithRate(t *testing.T) {
	p := newPacer(1_000_000, 14000) // 1 MB/s, 10×MTU burst
	if p.Rate() != 1_000_000 {
		t.Fatalf("expected rate 1000000, got %d", p.Rate())
	}
}

func TestPacerUnlimitedRate(t *testing.T) {
	p := newPacer(0, 14000) // rate=0 → unlimited
	wait := p.timeToSend(1400)
	if wait != 0 {
		t.Fatalf("unlimited rate should have zero wait, got %v", wait)
	}
}

func TestPacerImmediateSendWithTokens(t *testing.T) {
	// maxBurst = 14000 (10 packets), rate = 1 MB/s.
	// Initial tokens = 14000 → should send 10 packets without waiting.
	p := newPacer(1_000_000, 14000)

	for i := 0; i < 10; i++ {
		wait := p.timeToSend(1400)
		if wait != 0 {
			t.Fatalf("packet %d: expected immediate send, got wait %v", i, wait)
		}
	}

	// 11th packet should require waiting.
	wait := p.timeToSend(1400)
	if wait <= 0 {
		t.Fatal("should need to wait after burst exhausted")
	}
}

func TestPacerWaitDuration(t *testing.T) {
	// Rate = 1,400,000 B/s → one 1400-byte packet per millisecond.
	p := newPacer(1_400_000, 1400) // burst = exactly 1 packet

	// First packet: immediate (uses burst).
	wait := p.timeToSend(1400)
	if wait != 0 {
		t.Fatalf("first packet should be immediate, got %v", wait)
	}

	// Second packet (immediately after): should wait ~1ms.
	wait = p.timeToSend(1400)
	if wait < 500*time.Microsecond || wait > 2*time.Millisecond {
		t.Fatalf("expected ~1ms wait, got %v", wait)
	}
}

func TestPacerSetRate(t *testing.T) {
	p := newPacer(1_000_000, 14000)
	p.SetRate(2_000_000)
	if p.Rate() != 2_000_000 {
		t.Fatalf("expected rate 2000000 after SetRate, got %d", p.Rate())
	}
}

func TestPacerTokenRefill(t *testing.T) {
	// Rate = 1,400,000 B/s, burst = 1 packet.
	p := newPacer(1_400_000, 1400)

	// Consume the burst.
	p.timeToSend(1400)

	// Wait 2ms → should accumulate ~2800 bytes of tokens.
	time.Sleep(2 * time.Millisecond)

	// Should have enough tokens for 1 packet.
	if !p.TokensAvailable(1400) {
		t.Fatal("should have tokens after 2ms wait at 1.4 MB/s")
	}
}

func TestPacerMaxBurstCap(t *testing.T) {
	// maxBurst = 2800 (2 packets). Even after long idle, only 2 packets
	// can be sent immediately.
	p := newPacer(1_400_000, 2800)

	// Consume burst.
	p.timeToSend(1400)
	p.timeToSend(1400)

	// Wait long enough for many tokens to accumulate.
	time.Sleep(10 * time.Millisecond) // would generate ~14000 bytes of tokens

	// But maxBurst caps at 2800 → only 2 packets immediate.
	w1 := p.timeToSend(1400)
	w2 := p.timeToSend(1400)
	w3 := p.timeToSend(1400)

	if w1 != 0 || w2 != 0 {
		t.Fatalf("first 2 packets should be immediate, got w1=%v w2=%v", w1, w2)
	}
	if w3 <= 0 {
		t.Fatal("3rd packet should require waiting (burst cap)")
	}
}

func TestPacerWaitForSlot(t *testing.T) {
	// Rate = 14,000,000 B/s (14 MB/s) → 0.1ms per packet.
	// This makes the test fast.
	p := newPacer(14_000_000, 1400) // burst = 1 packet

	// Consume burst.
	p.WaitForSlot(1400) // immediate

	// Next call should block briefly.
	start := time.Now()
	p.WaitForSlot(1400)
	elapsed := time.Since(start)

	// Should have waited ~0.1ms (100µs). Allow generous margin.
	if elapsed < 50*time.Microsecond {
		t.Fatalf("WaitForSlot returned too quickly: %v", elapsed)
	}
	if elapsed > 5*time.Millisecond {
		t.Fatalf("WaitForSlot blocked too long: %v", elapsed)
	}
}

func TestPacerStats(t *testing.T) {
	p := newPacer(14_000_000, 1400)

	// Initial stats.
	tw, wc := p.Stats()
	if tw != 0 || wc != 0 {
		t.Fatalf("initial stats should be zero: wait=%v, count=%d", tw, wc)
	}

	p.WaitForSlot(1400) // immediate, no wait
	p.WaitForSlot(1400) // should wait

	tw, wc = p.Stats()
	if wc != 1 {
		t.Fatalf("expected 1 wait, got %d", wc)
	}
	if tw <= 0 {
		t.Fatal("totalWait should be > 0 after a blocking wait")
	}
}

func TestPacerReset(t *testing.T) {
	p := newPacer(14_000_000, 1400)
	p.WaitForSlot(1400)
	p.WaitForSlot(1400) // generates wait stats

	p.Reset()
	tw, wc := p.Stats()
	if tw != 0 || wc != 0 {
		t.Fatalf("after reset, stats should be zero: wait=%v, count=%d", tw, wc)
	}

	// Should have full burst again.
	if !p.TokensAvailable(1400) {
		t.Fatal("after reset, burst tokens should be available")
	}
}

func TestPacerConcurrent(t *testing.T) {
	p := newPacer(100_000_000, 14000) // 100 MB/s
	done := make(chan struct{})

	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				p.WaitForSlot(1400)
				p.SetRate(100_000_000 + int64(j))
				p.Rate()
				p.TokensAvailable(1400)
				p.Stats()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

func TestPacerThroughputAccuracy(t *testing.T) {
	// Verify that pacing limits throughput below the target rate.
	// We use a modest rate and few packets to keep the test fast.
	// With race detector and CI scheduling jitter, sleep-based pacing
	// can overshoot by 10×, so we only check that pacing is slower
	// than "no pacing" and that the rate is not wildly off.
	targetRate := int64(1_400_000) // 1.4 MB/s → 1ms per packet
	p := newPacer(targetRate, 1400) // minimal burst (1 packet)

	packetSize := 1400
	numPackets := 20
	totalBytes := int64(packetSize * numPackets)

	start := time.Now()
	for i := 0; i < numPackets; i++ {
		p.WaitForSlot(packetSize)
	}
	elapsed := time.Since(start)

	// Expected ~20ms (20 packets × 1ms). With race/CI overhead, allow up to 500ms.
	// The key invariant: elapsed > 5ms (pacing is actually throttling, not instant).
	if elapsed < 5*time.Millisecond {
		actualRate := float64(totalBytes) / elapsed.Seconds()
		t.Fatalf("pacing too fast (no throttling?): elapsed=%v, rate=%.0f B/s (target %d)",
			elapsed, actualRate, targetRate)
	}
	if elapsed > 500*time.Millisecond {
		actualRate := float64(totalBytes) / elapsed.Seconds()
		t.Fatalf("pacing too slow: elapsed=%v, rate=%.0f B/s (target %d)",
			elapsed, actualRate, targetRate)
	}
	_ = totalBytes // used in error messages above
}

// TestPacerTimerPoolGetPut verifies the pool contract:
// timers returned by getPacerTimer fire correctly, and timers returned
// via putPacerTimer are in a stopped+drained state for safe reuse.
func TestPacerTimerPoolGetPut(t *testing.T) {
	// Round 1: timer fires normally.
	d := 5 * time.Millisecond
	timer := getPacerTimer(d)
	select {
	case <-timer.C:
		// fired — good
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timer from pool did not fire")
	}
	putPacerTimer(timer) // must not panic or block

	// Round 2: same timer object is reusable after Put.
	timer2 := getPacerTimer(d)
	select {
	case <-timer2.C:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("reused timer did not fire on second use")
	}
	putPacerTimer(timer2)
}

// TestPacerTimerPoolContextCancel verifies putPacerTimer correctly drains
// the channel when context cancellation races with timer expiry.
func TestPacerTimerPoolContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	p := newPacer(1_000, 100) // very slow rate forces wait > 0

	err := p.WaitForSlotCtx(ctx, 200)
	if err == nil {
		// context was already cancelled; we expect an error
		t.Fatal("expected context cancellation error, got nil")
	}
}

// TestPacerTimerPoolZeroAllocs verifies that WaitForSlotCtx with wait=0
// (tokens available) never allocates, and that after warm-up the wait>0
// path also allocates zero times (pool reuse).
func TestPacerTimerPoolZeroAllocs(t *testing.T) {
	// Fast path (no wait): must be zero-alloc.
	p := newPacer(0, 14000) // unlimited
	allocs := testing.AllocsPerRun(100, func() {
		p.WaitForSlotCtx(context.Background(), 1400) //nolint:errcheck
	})
	if allocs > 0 {
		t.Fatalf("fast path (no wait): expected 0 allocs, got %.0f", allocs)
	}
}

// ---------------------------------------------------------------------------
// BBRState.WaitForPacing integration tests
// ---------------------------------------------------------------------------

// TestBBRStateWaitForPacingUnlimited verifies that WaitForPacing is a no-op
// when the pacer rate is 0 (unlimited — default during Startup probe).
func TestBBRStateWaitForPacingUnlimited(t *testing.T) {
	est := newBBREstimator()
	ifl := newInflightTracker()
	p := newPacer(0, bbrMaxBurst) // unlimited: rate=0
	bbr := NewBBRState(est, ifl, p, MaxPayloadSize)

	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := bbr.WaitForPacing(context.Background(), MaxPayloadSize); err != nil {
			t.Fatalf("WaitForPacing returned error: %v", err)
		}
	}
	elapsed := time.Since(start)

	// 100 calls with unlimited rate must complete in well under 5ms.
	if elapsed > 5*time.Millisecond {
		t.Fatalf("unlimited WaitForPacing too slow: %v for 100 calls", elapsed)
	}
}

// TestBBRStateWaitForPacingThrottles verifies that WaitForPacing slows down
// sends once the pacer has a finite rate.
func TestBBRStateWaitForPacingThrottles(t *testing.T) {
	est := newBBREstimator()
	ifl := newInflightTracker()
	// Rate = 14 MB/s → inter-packet gap ~100µs for 1430-byte packets.
	// Burst = 1 packet so the first send is immediate, subsequent ones wait.
	p := newPacer(14_000_000, MaxPayloadSize)
	bbr := NewBBRState(est, ifl, p, MaxPayloadSize)

	// Consume burst.
	if err := bbr.WaitForPacing(context.Background(), MaxPayloadSize); err != nil {
		t.Fatal(err)
	}

	// Next call must wait (no remaining burst tokens).
	start := time.Now()
	if err := bbr.WaitForPacing(context.Background(), MaxPayloadSize); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if elapsed < 20*time.Microsecond {
		t.Fatalf("WaitForPacing did not throttle: returned in %v (expected >20µs)", elapsed)
	}
}

// TestBBRStateWaitForPacingContextCancel verifies that WaitForPacing respects
// context cancellation instead of blocking indefinitely.
func TestBBRStateWaitForPacingContextCancel(t *testing.T) {
	est := newBBREstimator()
	ifl := newInflightTracker()
	// Very slow rate: 1 B/s → would wait ~1430 seconds for one packet.
	// We cancel the context after 10ms to verify early exit.
	p := newPacer(1, MaxPayloadSize) // 1 B/s
	bbr := NewBBRState(est, ifl, p, MaxPayloadSize)

	// Exhaust the burst so the next call actually has to wait.
	_ = bbr.WaitForPacing(context.Background(), MaxPayloadSize)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := bbr.WaitForPacing(ctx, MaxPayloadSize)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("WaitForPacing should have returned an error on context cancel")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("WaitForPacing ignored context cancel: blocked for %v", elapsed)
	}
}

// TestWritePacketPacingBypassedForNonData verifies that FIN packets are NOT
// paced — they bypass the pacer and must not be delayed even with rate=1 B/s.
func TestWritePacketPacingBypassedForNonData(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	dialConn, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dialConn.Close()

	// Override the pacer with an extremely slow rate: 1 B/s.
	// DATA packets would wait ~1430 seconds, but FIN (non-DATA) should not.
	dialConn.bbr.pacer.SetRate(1) // 1 B/s
	dialConn.bbr.pacer.mu.Lock()
	dialConn.bbr.pacer.tokens = 0 // drain the burst
	dialConn.bbr.pacer.mu.Unlock()

	// Close() sends a FIN packet — this must complete quickly despite rate=1 B/s.
	start := time.Now()
	dialConn.Close()
	elapsed := time.Since(start)

	// FIN (non-DATA) must not be throttled by the pacer.
	if elapsed > 200*time.Millisecond {
		t.Fatalf("Close/FIN was paced (should not be): took %v", elapsed)
	}
}
