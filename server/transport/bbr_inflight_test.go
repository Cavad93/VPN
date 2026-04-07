package transport

import (
	"testing"
)

func TestInflightTrackerEmpty(t *testing.T) {
	tr := newInflightTracker()
	if tr.Count() != 0 {
		t.Fatalf("expected count=0, got %d", tr.Count())
	}
	if tr.Bytes() != 0 {
		t.Fatalf("expected bytes=0, got %d", tr.Bytes())
	}
}

func TestInflightOnSend(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(1400)
	tr.OnSend(1400)
	tr.OnSend(800)

	if tr.Count() != 3 {
		t.Fatalf("expected count=3, got %d", tr.Count())
	}
	if tr.Bytes() != 3600 {
		t.Fatalf("expected bytes=3600, got %d", tr.Bytes())
	}
}

func TestInflightOnACK(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(1400)
	tr.OnSend(1400)

	tr.OnACK(1400)
	if tr.Count() != 1 {
		t.Fatalf("expected count=1 after ACK, got %d", tr.Count())
	}
	if tr.Bytes() != 1400 {
		t.Fatalf("expected bytes=1400 after ACK, got %d", tr.Bytes())
	}
}

func TestInflightOnACKUnderflow(t *testing.T) {
	tr := newInflightTracker()
	// ACK without prior send must not underflow below zero.
	tr.OnACK(1400)
	if tr.Count() < 0 {
		t.Fatalf("count should not be negative, got %d", tr.Count())
	}
	if tr.Bytes() < 0 {
		t.Fatalf("bytes should not be negative, got %d", tr.Bytes())
	}
}

func TestInflightOnLoss(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(1400)
	tr.OnSend(1400)

	tr.OnLoss(1400)
	if tr.Count() != 1 {
		t.Fatalf("expected count=1 after loss, got %d", tr.Count())
	}
	if tr.LostBytes() != 1400 {
		t.Fatalf("expected lostBytes=1400, got %d", tr.LostBytes())
	}
}

func TestInflightRetransmitCycle(t *testing.T) {
	// Simulate first retransmit: OnLoss + OnSend (net zero count/bytes change).
	tr := newInflightTracker()
	tr.OnSend(1400) // original send

	// First retransmit: mark lost, re-enter as in-flight.
	tr.OnLoss(1400)
	tr.OnSend(1400)

	if tr.Count() != 1 {
		t.Fatalf("expected count=1 after retransmit cycle, got %d", tr.Count())
	}
	if tr.Bytes() != 1400 {
		t.Fatalf("expected bytes=1400 after retransmit cycle, got %d", tr.Bytes())
	}
	if tr.LostBytes() != 1400 {
		t.Fatalf("expected lostBytes=1400, got %d", tr.LostBytes())
	}

	// ACK arrives.
	tr.OnACK(1400)
	if tr.Count() != 0 {
		t.Fatalf("expected count=0 after ACK, got %d", tr.Count())
	}
}

func TestInflightReset(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(1400)
	tr.OnLoss(1400)
	tr.OnSend(1400)

	tr.Reset()
	if tr.Count() != 0 {
		t.Fatalf("expected count=0 after reset, got %d", tr.Count())
	}
	if tr.Bytes() != 0 {
		t.Fatalf("expected bytes=0 after reset, got %d", tr.Bytes())
	}
	if tr.LostBytes() != 0 {
		t.Fatalf("expected lostBytes=0 after reset, got %d", tr.LostBytes())
	}
}

func TestInflightRoundTracking(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(1400)
	tr.OnSend(1400)
	tr.OnSend(1400)

	tr.OnACK(1400)
	tr.OnLoss(1400)

	if tr.RoundDeliveredBytes() != 1400 {
		t.Fatalf("expected roundDeliv=1400, got %d", tr.RoundDeliveredBytes())
	}
	if tr.RoundLostBytes() != 1400 {
		t.Fatalf("expected roundLost=1400, got %d", tr.RoundLostBytes())
	}

	// ResetRound clears per-round counters but not cumulative lostAtomic.
	tr.ResetRound()
	if tr.RoundDeliveredBytes() != 0 {
		t.Fatalf("expected roundDeliv=0 after ResetRound, got %d", tr.RoundDeliveredBytes())
	}
	if tr.RoundLostBytes() != 0 {
		t.Fatalf("expected roundLost=0 after ResetRound, got %d", tr.RoundLostBytes())
	}
	if tr.LostBytes() != 1400 {
		t.Fatalf("expected cumulative lostBytes=1400 after ResetRound, got %d", tr.LostBytes())
	}
}

func TestInflightResetClearsRoundCounters(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(1400)
	tr.OnACK(700)
	tr.OnLoss(700)

	tr.Reset()
	if tr.RoundDeliveredBytes() != 0 {
		t.Fatalf("expected roundDeliv=0 after Reset, got %d", tr.RoundDeliveredBytes())
	}
	if tr.RoundLostBytes() != 0 {
		t.Fatalf("expected roundLost=0 after Reset, got %d", tr.RoundLostBytes())
	}
}

func TestInflightConcurrent(t *testing.T) {
	tr := newInflightTracker()
	done := make(chan struct{})

	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				tr.OnSend(1400)
				tr.Count()
				tr.Bytes()
				if j%3 == 0 {
					tr.OnACK(1400)
				} else if j%5 == 0 {
					tr.OnLoss(1400)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	// No crash = pass. Verify counts are non-negative.
	if tr.Count() < 0 {
		t.Fatal("count should not be negative")
	}
	if tr.Bytes() < 0 {
		t.Fatal("bytes should not be negative")
	}
}
