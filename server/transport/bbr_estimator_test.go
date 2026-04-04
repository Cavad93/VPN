package transport

import (
	"testing"
	"time"
)

// ---------- windowedMinFilter tests ----------

func TestMinFilterInitialValue(t *testing.T) {
	f := newWindowedMinFilter(10 * time.Second)
	// Before any sample, get() should return max duration.
	if f.get() <= 0 {
		t.Fatal("initial min filter value should be positive (max duration)")
	}
}

func TestMinFilterTracksMinimum(t *testing.T) {
	f := newWindowedMinFilter(10 * time.Second)
	now := time.Now()

	f.update(100*time.Millisecond, now)
	if f.get() != 100*time.Millisecond {
		t.Fatalf("expected 100ms, got %v", f.get())
	}

	// Smaller value should become new minimum.
	f.update(50*time.Millisecond, now.Add(1*time.Second))
	if f.get() != 50*time.Millisecond {
		t.Fatalf("expected 50ms, got %v", f.get())
	}

	// Larger value should NOT change minimum.
	f.update(200*time.Millisecond, now.Add(2*time.Second))
	if f.get() != 50*time.Millisecond {
		t.Fatalf("expected 50ms still, got %v", f.get())
	}
}

func TestMinFilterExpiresOldMinimum(t *testing.T) {
	f := newWindowedMinFilter(5 * time.Second)
	now := time.Now()

	f.update(10*time.Millisecond, now)
	if f.get() != 10*time.Millisecond {
		t.Fatalf("expected 10ms, got %v", f.get())
	}

	// After window expires, a higher value should replace the old minimum.
	f.update(80*time.Millisecond, now.Add(6*time.Second))
	if f.get() != 80*time.Millisecond {
		t.Fatalf("expected 80ms after expiry, got %v", f.get())
	}
}

func TestMinFilterExpiredFlag(t *testing.T) {
	f := newWindowedMinFilter(5 * time.Second)
	now := time.Now()

	f.update(10*time.Millisecond, now)
	if f.expired(now.Add(3 * time.Second)) {
		t.Fatal("should not be expired within window")
	}
	if !f.expired(now.Add(6 * time.Second)) {
		t.Fatal("should be expired after window")
	}
}

func TestMinFilterReset(t *testing.T) {
	f := newWindowedMinFilter(10 * time.Second)
	now := time.Now()

	f.update(42*time.Millisecond, now)
	f.reset()
	// After reset, should be back to max duration.
	if f.get() < time.Hour {
		t.Fatal("after reset, min filter should be back to max duration")
	}
}

// ---------- windowedMaxFilter tests ----------

func TestMaxFilterInitialValue(t *testing.T) {
	f := newWindowedMaxFilter(10)
	if f.get() != 0 {
		t.Fatalf("initial max filter value should be 0, got %d", f.get())
	}
}

func TestMaxFilterTracksMaximum(t *testing.T) {
	f := newWindowedMaxFilter(10)

	f.update(1000, 1)
	if f.get() != 1000 {
		t.Fatalf("expected 1000, got %d", f.get())
	}

	// Higher value becomes new max.
	f.update(5000, 2)
	if f.get() != 5000 {
		t.Fatalf("expected 5000, got %d", f.get())
	}

	// Lower value should NOT change max.
	f.update(2000, 3)
	if f.get() != 5000 {
		t.Fatalf("expected 5000 still, got %d", f.get())
	}
}

func TestMaxFilterExpiresOldMaximum(t *testing.T) {
	f := newWindowedMaxFilter(3) // window = 3 rounds

	f.update(10000, 1)
	f.update(2000, 2)
	f.update(3000, 3)
	if f.get() != 10000 {
		t.Fatalf("expected 10000, got %d", f.get())
	}

	// Round 4 — round 1 sample (10000) should be evicted.
	f.update(4000, 4)
	// Now window covers rounds 2,3,4 → max should be 4000.
	if f.get() != 4000 {
		t.Fatalf("expected 4000 after round 1 expired, got %d", f.get())
	}
}

func TestMaxFilterReset(t *testing.T) {
	f := newWindowedMaxFilter(10)
	f.update(5000, 1)
	f.reset()
	if f.get() != 0 {
		t.Fatalf("after reset, max filter should be 0, got %d", f.get())
	}
}

// ---------- bbrEstimator tests ----------

func TestEstimatorNewIsEmpty(t *testing.T) {
	e := newBBREstimator()
	if e.BtlBw() != 0 {
		t.Fatalf("new estimator BtlBw should be 0, got %d", e.BtlBw())
	}
	if e.BDP() != 0 {
		t.Fatalf("new estimator BDP should be 0, got %d", e.BDP())
	}
	if e.Delivered() != 0 {
		t.Fatalf("new estimator Delivered should be 0, got %d", e.Delivered())
	}
}

func TestEstimatorRTpropTracksMinRTT(t *testing.T) {
	e := newBBREstimator()

	// Send 3 "packets" with decreasing RTT.
	rtts := []time.Duration{100 * time.Millisecond, 80 * time.Millisecond, 60 * time.Millisecond}
	for _, rtt := range rtts {
		e.OnACK(rtt, 1400, 0, time.Now(), time.Now().Add(-rtt), false)
	}

	if e.RTprop() != 60000 { // 60ms = 60000 us
		t.Fatalf("expected RTprop=60000us, got %d", e.RTprop())
	}
}

func TestEstimatorBtlBwTracksMaxDeliveryRate(t *testing.T) {
	e := newBBREstimator()

	// Simulate a series of ACKs with increasing delivery rate.
	// Each ACK confirms 1400 bytes. We control send-time snapshots
	// to produce known delivery rates.
	now := time.Now()

	// ACK 1: delivered delta = 1400 bytes over 100ms → 14000 B/s
	e.OnACK(
		50*time.Millisecond, // rtt
		1400,                // ackedBytes
		0,                   // sendDelivered (snapshot when pkt was sent)
		now.Add(-100*time.Millisecond), // sendDeliveredTime
		now.Add(-50*time.Millisecond),  // sendTime
		false,
	)
	bw1 := e.BtlBw()
	if bw1 <= 0 {
		t.Fatalf("BtlBw should be positive after first ACK, got %d", bw1)
	}

	// ACK 2: larger rate. delivered delta = 2800 over 50ms → 56000 B/s
	prevDelivered := e.Delivered()
	prevTime := now
	e.OnACK(
		50*time.Millisecond,
		2800,
		prevDelivered-2800, // snapshot: pretend pkt was sent when delivered was lower
		prevTime.Add(-50*time.Millisecond),
		now.Add(-50*time.Millisecond),
		false,
	)
	bw2 := e.BtlBw()
	if bw2 < bw1 {
		t.Fatalf("BtlBw should have increased: was %d, now %d", bw1, bw2)
	}
}

func TestEstimatorBDPCalculation(t *testing.T) {
	e := newBBREstimator()
	now := time.Now()

	// Feed a controlled sample: RTT=80ms, ~10 MB/s delivery rate.
	// We need enough ACKs for the filters to register.
	rtt := 80 * time.Millisecond
	ackedBytes := int64(100000) // 100 KB in one ACK

	e.OnACK(
		rtt,
		ackedBytes,
		0, // sendDelivered
		now.Add(-rtt), // sendDeliveredTime
		now.Add(-rtt), // sendTime
		false,
	)

	bdp := e.BDP()
	rtprop := e.RTprop()
	btlbw := e.BtlBw()

	if rtprop <= 0 {
		t.Fatalf("RTprop should be > 0, got %d", rtprop)
	}
	if btlbw <= 0 {
		t.Fatalf("BtlBw should be > 0, got %d", btlbw)
	}
	// BDP = BtlBw * RTprop / 1e6
	expectedBDP := btlbw * rtprop / 1_000_000
	if bdp != expectedBDP {
		t.Fatalf("BDP mismatch: got %d, expected %d (btlbw=%d, rtprop=%d)",
			bdp, expectedBDP, btlbw, rtprop)
	}
}

func TestEstimatorDeliveredSnapshot(t *testing.T) {
	e := newBBREstimator()
	now := time.Now()

	e.OnACK(50*time.Millisecond, 1400, 0, now.Add(-50*time.Millisecond), now.Add(-50*time.Millisecond), false)

	delivered, deliveredTime := e.DeliveredSnapshot()
	if delivered != 1400 {
		t.Fatalf("expected delivered=1400, got %d", delivered)
	}
	if deliveredTime.IsZero() {
		t.Fatal("deliveredTime should not be zero")
	}
}

func TestEstimatorRoundCounting(t *testing.T) {
	e := newBBREstimator()
	now := time.Now()

	// First ACK starts round 1.
	e.OnACK(50*time.Millisecond, 1400, 0, now.Add(-50*time.Millisecond), now.Add(-50*time.Millisecond), false)
	r1 := e.RoundCount()
	if r1 < 1 {
		t.Fatalf("expected round >= 1 after first ACK, got %d", r1)
	}

	// Second ACK with sendDelivered >= nextRoundDelivered triggers new round.
	d, dt := e.DeliveredSnapshot()
	e.OnACK(50*time.Millisecond, 1400, d, dt, now, false)
	r2 := e.RoundCount()
	if r2 <= r1 {
		t.Fatalf("expected round to increment: was %d, now %d", r1, r2)
	}
}

func TestEstimatorAppLimitedSamplesIgnored(t *testing.T) {
	e := newBBREstimator()
	now := time.Now()

	// Non-app-limited ACK: high delivery rate.
	e.OnACK(50*time.Millisecond, 100000, 0, now.Add(-50*time.Millisecond), now.Add(-50*time.Millisecond), false)
	bwHigh := e.BtlBw()

	// App-limited ACK: low delivery rate (should be ignored by BtlBw filter).
	d, dt := e.DeliveredSnapshot()
	e.OnACK(50*time.Millisecond, 100, d, dt.Add(-5*time.Second), now.Add(-50*time.Millisecond), true)
	bwAfter := e.BtlBw()

	// BtlBw should NOT have decreased due to app-limited sample.
	if bwAfter < bwHigh {
		t.Fatalf("BtlBw should not decrease from app-limited sample: was %d, now %d", bwHigh, bwAfter)
	}
}

func TestEstimatorReset(t *testing.T) {
	e := newBBREstimator()
	now := time.Now()

	e.OnACK(50*time.Millisecond, 1400, 0, now.Add(-50*time.Millisecond), now.Add(-50*time.Millisecond), false)
	if e.BtlBw() == 0 {
		t.Fatal("BtlBw should be non-zero before reset")
	}

	e.Reset()
	if e.BtlBw() != 0 {
		t.Fatalf("BtlBw should be 0 after reset, got %d", e.BtlBw())
	}
	if e.Delivered() != 0 {
		t.Fatalf("Delivered should be 0 after reset, got %d", e.Delivered())
	}
	if e.RoundCount() != 0 {
		t.Fatalf("RoundCount should be 0 after reset, got %d", e.RoundCount())
	}
}

func TestEstimatorRTpropExpired(t *testing.T) {
	e := newBBREstimator()
	now := time.Now()

	// Feed one sample — RTprop should not be expired yet.
	e.OnACK(50*time.Millisecond, 1400, 0, now.Add(-50*time.Millisecond), now.Add(-50*time.Millisecond), false)
	if e.RTpropExpired() {
		t.Fatal("RTprop should not be expired immediately after a sample")
	}
}

func TestEstimatorConcurrentAccess(t *testing.T) {
	e := newBBREstimator()
	now := time.Now()

	// Hammer the estimator from multiple goroutines to catch races.
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 1000; j++ {
				e.OnACK(
					50*time.Millisecond,
					1400,
					0,
					now.Add(-50*time.Millisecond),
					now.Add(-50*time.Millisecond),
					j%3 == 0,
				)
				e.RTprop()
				e.BtlBw()
				e.BDP()
				e.Delivered()
				e.DeliveredSnapshot()
				e.RoundCount()
				e.RTpropExpired()
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
