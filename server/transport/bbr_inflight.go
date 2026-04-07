package transport

import (
	"sync/atomic"
)

// inflightTracker tracks packets currently "in flight" (sent but not yet ACKed).
// It provides lock-free O(1) reads of packet count, byte count, and lost bytes.
//
// Delivery-rate snapshots (Delivered, DeliveredTime, SentAt, AppLimited) are stored
// in pendingPacket (udp.go) instead of here — that avoids maintaining a duplicate
// map[seqNum → metadata] alongside c.pending.
//
// All public methods are safe for concurrent use (atomic ops, no mutex).
type inflightTracker struct {
	// Atomic mirrors for lock-free reads from BBR state machine.
	countAtomic atomic.Int32
	bytesAtomic atomic.Int64
	lostAtomic  atomic.Int64

	// Per-round loss tracking. Reset at each BBR round boundary via ResetRound.
	// roundLostAtomic: bytes lost in the current BBR round.
	// roundDelivAtomic: bytes ACKed (delivered) in the current BBR round.
	// These give a windowed loss rate that prevents the cumulative lostAtomic
	// from permanently inflating the loss estimate after the initial burst.
	roundLostAtomic  atomic.Int64
	roundDelivAtomic atomic.Int64
}

// newInflightTracker creates an empty tracker.
func newInflightTracker() *inflightTracker {
	return &inflightTracker{}
}

// OnSend records a newly sent packet of the given payload size.
func (t *inflightTracker) OnSend(size int) {
	t.countAtomic.Add(1)
	t.bytesAtomic.Add(int64(size))
}

// OnACK removes a packet of the given payload size from in-flight tracking.
func (t *inflightTracker) OnACK(size int) {
	if n := t.countAtomic.Add(-1); n < 0 {
		t.countAtomic.Store(0)
	}
	if b := t.bytesAtomic.Add(-int64(size)); b < 0 {
		t.bytesAtomic.Store(0)
	}
	t.roundDelivAtomic.Add(int64(size))
}

// OnLoss marks a packet as lost. Removes it from in-flight and increments
// the cumulative lost byte counter and the per-round lost byte counter.
func (t *inflightTracker) OnLoss(size int) {
	if n := t.countAtomic.Add(-1); n < 0 {
		t.countAtomic.Store(0)
	}
	if b := t.bytesAtomic.Add(-int64(size)); b < 0 {
		t.bytesAtomic.Store(0)
	}
	t.lostAtomic.Add(int64(size))
	t.roundLostAtomic.Add(int64(size))
}

// Count returns the number of packets in flight (lock-free).
func (t *inflightTracker) Count() int {
	return int(t.countAtomic.Load())
}

// Bytes returns the total bytes in flight (lock-free).
func (t *inflightTracker) Bytes() int64 {
	return t.bytesAtomic.Load()
}

// LostBytes returns the cumulative lost bytes (lock-free).
func (t *inflightTracker) LostBytes() int64 {
	return t.lostAtomic.Load()
}

// RoundLostBytes returns bytes lost in the current BBR round (lock-free).
// Reset to zero at each BBR round boundary via ResetRound.
func (t *inflightTracker) RoundLostBytes() int64 {
	return t.roundLostAtomic.Load()
}

// RoundDeliveredBytes returns bytes ACKed in the current BBR round (lock-free).
// Reset to zero at each BBR round boundary via ResetRound.
func (t *inflightTracker) RoundDeliveredBytes() int64 {
	return t.roundDelivAtomic.Load()
}

// ResetRound zeroes the per-round loss and delivery counters.
// Called by BBRState.OnACK at each round boundary (IsRoundStart).
func (t *inflightTracker) ResetRound() {
	t.roundLostAtomic.Store(0)
	t.roundDelivAtomic.Store(0)
}

// Reset clears all inflight state.
func (t *inflightTracker) Reset() {
	t.countAtomic.Store(0)
	t.bytesAtomic.Store(0)
	t.lostAtomic.Store(0)
	t.roundLostAtomic.Store(0)
	t.roundDelivAtomic.Store(0)
}
