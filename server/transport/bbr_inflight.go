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
}

// OnLoss marks a packet as lost. Removes it from in-flight and increments
// the cumulative lost byte counter.
func (t *inflightTracker) OnLoss(size int) {
	if n := t.countAtomic.Add(-1); n < 0 {
		t.countAtomic.Store(0)
	}
	if b := t.bytesAtomic.Add(-int64(size)); b < 0 {
		t.bytesAtomic.Store(0)
	}
	t.lostAtomic.Add(int64(size))
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

// Reset clears all inflight state.
func (t *inflightTracker) Reset() {
	t.countAtomic.Store(0)
	t.bytesAtomic.Store(0)
	t.lostAtomic.Store(0)
}
