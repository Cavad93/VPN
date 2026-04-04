package transport

import (
	"sync"
	"time"
)

// inflightPkt is the metadata stored for each packet that has been sent
// but not yet acknowledged. BBR uses the delivery-rate snapshots to compute
// per-ACK bandwidth measurements.
type inflightPkt struct {
	SeqNum    uint32 // sequence number
	Size      int    // payload size in bytes
	SentAt    time.Time
	Retransmitted bool // true if this is a retransmission

	// Delivery rate snapshots taken at send time — used to compute
	// per-ACK delivery rate when the ACK arrives.
	Delivered     int64     // estimator.delivered at send time
	DeliveredTime time.Time // estimator.deliveredTime at send time

	// AppLimited is true if the sender had no data queued when this
	// packet was sent. App-limited samples underestimate BtlBw and
	// should not update the max filter.
	AppLimited bool
}

// inflightTracker tracks all packets currently "in flight" (sent but not
// yet ACKed). Provides O(1) packet count and byte count.
//
// Thread-safe: all methods acquire mu.
type inflightTracker struct {
	mu      sync.Mutex
	packets map[uint32]*inflightPkt // seqNum → metadata
	count   int                      // number of packets in flight
	bytes   int64                    // total bytes in flight (payload only)
	lost    int64                    // cumulative lost bytes (for loss rate calc)
}

// newInflightTracker creates an empty tracker.
func newInflightTracker() *inflightTracker {
	return &inflightTracker{
		packets: make(map[uint32]*inflightPkt),
	}
}

// OnSend records a newly sent packet. The caller provides delivery-rate
// snapshots from the BBR estimator at the time of sending.
func (t *inflightTracker) OnSend(pkt *inflightPkt) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If this seqNum is already tracked (retransmission), subtract old size first.
	if old, ok := t.packets[pkt.SeqNum]; ok {
		t.bytes -= int64(old.Size)
		t.count--
	}

	t.packets[pkt.SeqNum] = pkt
	t.count++
	t.bytes += int64(pkt.Size)
}

// OnACK removes a packet from inflight tracking when its ACK arrives.
// Returns the packet metadata (for delivery rate computation) and true,
// or nil and false if the seqNum was not tracked.
func (t *inflightTracker) OnACK(seqNum uint32) (*inflightPkt, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	pkt, ok := t.packets[seqNum]
	if !ok {
		return nil, false
	}
	delete(t.packets, seqNum)
	t.count--
	t.bytes -= int64(pkt.Size)
	if t.bytes < 0 {
		t.bytes = 0
	}
	return pkt, true
}

// OnACKCumulative removes all packets with seqNum <= ackNum (cumulative ACK).
// Returns all removed packets in no particular order.
func (t *inflightTracker) OnACKCumulative(ackNum uint32) []*inflightPkt {
	t.mu.Lock()
	defer t.mu.Unlock()

	var acked []*inflightPkt
	for seq, pkt := range t.packets {
		if seq <= ackNum {
			acked = append(acked, pkt)
			delete(t.packets, seq)
			t.count--
			t.bytes -= int64(pkt.Size)
		}
	}
	if t.bytes < 0 {
		t.bytes = 0
	}
	return acked
}

// OnLoss marks a packet as lost. Removes it from inflight and increments
// the cumulative lost byte counter.
func (t *inflightTracker) OnLoss(seqNum uint32) (*inflightPkt, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	pkt, ok := t.packets[seqNum]
	if !ok {
		return nil, false
	}
	delete(t.packets, seqNum)
	t.count--
	t.bytes -= int64(pkt.Size)
	if t.bytes < 0 {
		t.bytes = 0
	}
	t.lost += int64(pkt.Size)
	return pkt, true
}

// Count returns the number of packets in flight.
func (t *inflightTracker) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

// Bytes returns the total bytes in flight.
func (t *inflightTracker) Bytes() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bytes
}

// LostBytes returns the cumulative lost bytes.
func (t *inflightTracker) LostBytes() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lost
}

// Get returns the inflight packet for the given seqNum, or nil.
func (t *inflightTracker) Get(seqNum uint32) *inflightPkt {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.packets[seqNum]
}

// Reset clears all inflight state.
func (t *inflightTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.packets = make(map[uint32]*inflightPkt)
	t.count = 0
	t.bytes = 0
	t.lost = 0
}
