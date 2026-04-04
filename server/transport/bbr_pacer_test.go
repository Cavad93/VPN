package transport

import (
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
