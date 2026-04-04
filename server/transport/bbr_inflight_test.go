package transport

import (
	"testing"
	"time"
)

func makeTestPkt(seq uint32, size int) *inflightPkt {
	now := time.Now()
	return &inflightPkt{
		SeqNum:        seq,
		Size:          size,
		SentAt:        now,
		Delivered:     0,
		DeliveredTime: now,
	}
}

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
	tr.OnSend(makeTestPkt(1, 1400))
	tr.OnSend(makeTestPkt(2, 1400))
	tr.OnSend(makeTestPkt(3, 800))

	if tr.Count() != 3 {
		t.Fatalf("expected count=3, got %d", tr.Count())
	}
	if tr.Bytes() != 3600 {
		t.Fatalf("expected bytes=3600, got %d", tr.Bytes())
	}
}

func TestInflightOnACK(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(makeTestPkt(1, 1400))
	tr.OnSend(makeTestPkt(2, 1400))

	pkt, ok := tr.OnACK(1)
	if !ok || pkt == nil {
		t.Fatal("expected to find packet 1")
	}
	if pkt.SeqNum != 1 {
		t.Fatalf("expected seqNum=1, got %d", pkt.SeqNum)
	}
	if tr.Count() != 1 {
		t.Fatalf("expected count=1 after ACK, got %d", tr.Count())
	}
	if tr.Bytes() != 1400 {
		t.Fatalf("expected bytes=1400 after ACK, got %d", tr.Bytes())
	}
}

func TestInflightOnACKUnknown(t *testing.T) {
	tr := newInflightTracker()
	pkt, ok := tr.OnACK(999)
	if ok || pkt != nil {
		t.Fatal("should not find unknown seqNum")
	}
}

func TestInflightOnACKCumulative(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(makeTestPkt(1, 1400))
	tr.OnSend(makeTestPkt(2, 1400))
	tr.OnSend(makeTestPkt(3, 1400))
	tr.OnSend(makeTestPkt(5, 1400)) // gap at 4

	acked := tr.OnACKCumulative(3) // ACK up to 3
	if len(acked) != 3 {
		t.Fatalf("expected 3 acked, got %d", len(acked))
	}
	if tr.Count() != 1 {
		t.Fatalf("expected count=1 (pkt 5 remains), got %d", tr.Count())
	}
	if tr.Bytes() != 1400 {
		t.Fatalf("expected bytes=1400, got %d", tr.Bytes())
	}
}

func TestInflightOnLoss(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(makeTestPkt(1, 1400))
	tr.OnSend(makeTestPkt(2, 1400))

	pkt, ok := tr.OnLoss(1)
	if !ok || pkt == nil {
		t.Fatal("expected to find lost packet 1")
	}
	if tr.Count() != 1 {
		t.Fatalf("expected count=1 after loss, got %d", tr.Count())
	}
	if tr.LostBytes() != 1400 {
		t.Fatalf("expected lostBytes=1400, got %d", tr.LostBytes())
	}
}

func TestInflightOnLossUnknown(t *testing.T) {
	tr := newInflightTracker()
	pkt, ok := tr.OnLoss(999)
	if ok || pkt != nil {
		t.Fatal("should not find unknown seqNum for loss")
	}
}

func TestInflightRetransmitOverwrite(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(makeTestPkt(1, 1400))

	// Retransmit same seqNum with different size.
	retx := makeTestPkt(1, 800)
	retx.Retransmitted = true
	tr.OnSend(retx)

	// Count should still be 1 (overwritten, not double-counted).
	if tr.Count() != 1 {
		t.Fatalf("expected count=1 after retransmit, got %d", tr.Count())
	}
	// Bytes should reflect the new size.
	if tr.Bytes() != 800 {
		t.Fatalf("expected bytes=800 after retransmit overwrite, got %d", tr.Bytes())
	}
}

func TestInflightGet(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(makeTestPkt(42, 1400))

	pkt := tr.Get(42)
	if pkt == nil || pkt.SeqNum != 42 {
		t.Fatal("expected to get packet 42")
	}
	if tr.Get(99) != nil {
		t.Fatal("expected nil for unknown seqNum")
	}
}

func TestInflightReset(t *testing.T) {
	tr := newInflightTracker()
	tr.OnSend(makeTestPkt(1, 1400))
	tr.OnLoss(1)
	tr.OnSend(makeTestPkt(2, 1400))

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

func TestInflightConcurrent(t *testing.T) {
	tr := newInflightTracker()
	done := make(chan struct{})

	for i := 0; i < 4; i++ {
		go func(base uint32) {
			defer func() { done <- struct{}{} }()
			for j := uint32(0); j < 200; j++ {
				seq := base*1000 + j
				tr.OnSend(makeTestPkt(seq, 1400))
				tr.Count()
				tr.Bytes()
				tr.Get(seq)
				if j%3 == 0 {
					tr.OnACK(seq)
				} else if j%5 == 0 {
					tr.OnLoss(seq)
				}
			}
		}(uint32(i))
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	// No crash = pass. Just verify counts are non-negative.
	if tr.Count() < 0 {
		t.Fatal("count should not be negative")
	}
	if tr.Bytes() < 0 {
		t.Fatal("bytes should not be negative")
	}
}

func TestInflightDeliveryRateSnapshot(t *testing.T) {
	tr := newInflightTracker()
	now := time.Now()

	// Simulate: send pkt at t=0 with delivered=5000 snapshot.
	pkt := &inflightPkt{
		SeqNum:        1,
		Size:          1400,
		SentAt:        now,
		Delivered:     5000,
		DeliveredTime: now,
	}
	tr.OnSend(pkt)

	// ACK arrives — retrieve the snapshot for delivery rate calculation.
	got, ok := tr.OnACK(1)
	if !ok {
		t.Fatal("expected to find packet")
	}
	if got.Delivered != 5000 {
		t.Fatalf("expected delivered snapshot=5000, got %d", got.Delivered)
	}
}
