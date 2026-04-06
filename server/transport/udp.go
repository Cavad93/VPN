// Package transport implements reliable UDP transport with ACK, retransmission,
// packet ordering, and BBR congestion control (user-space).
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Packet types.
const (
	PacketTypeData uint8 = 0x01
	PacketTypeACK  uint8 = 0x02
	PacketTypeSYN  uint8 = 0x03
	PacketTypeFIN  uint8 = 0x04
)

// Protocol constants.
const (
	// HeaderSize is the fixed size of the packet header in bytes.
	// Layout: type(1) seqNum(4) ackNum(4) payloadLen(2) = 11 bytes.
	HeaderSize = 11

	// MaxPayloadSize is the maximum payload per packet.
	// Ethernet MTU (1500) − IP header (20) − UDP header (8) − our header (11) = 1461.
	// We use 1460 for alignment; this avoids IP fragmentation on standard networks
	// and increases throughput by ~4% vs the previous 1400.
	MaxPayloadSize = 1460

	// initialRTO is the retransmission timeout before any RTT samples.
	// 300ms is sufficient for most paths; 1s was causing 1-second stalls on first loss.
	initialRTO = 300 * time.Millisecond
	// minRTO prevents too-aggressive retransmission on fast paths.
	// 50ms is the RFC 6298 recommended minimum; 200ms was adding unnecessary latency.
	minRTO = 50 * time.Millisecond
	// maxRTO caps the retransmit timeout to prevent excessive waiting.
	maxRTO = 10 * time.Second

	// MaxRetransmits is the maximum number of retransmission attempts before dropping.
	MaxRetransmits = 10

	// retransmitTick is how often the retransmit loop wakes up.
	retransmitTick = 50 * time.Millisecond
)

// Packet is a transport-layer PDU carrying reliability metadata.
type Packet struct {
	Type    uint8
	SeqNum  uint32
	AckNum  uint32
	Payload []byte
}

// Encode serializes the packet to bytes.
// Wire format: type(1) | seqNum(4) | ackNum(4) | payloadLen(2) | payload(n).
func (p *Packet) Encode() []byte {
	buf := make([]byte, HeaderSize+len(p.Payload))
	buf[0] = p.Type
	binary.BigEndian.PutUint32(buf[1:5], p.SeqNum)
	binary.BigEndian.PutUint32(buf[5:9], p.AckNum)
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(p.Payload)))
	copy(buf[HeaderSize:], p.Payload)
	return buf
}

// pktPool reuses Packet structs to avoid one heap allocation per received packet.
var pktPool = sync.Pool{
	New: func() interface{} { return new(Packet) },
}

// DecodePacket parses a packet from raw bytes.
// The returned Packet's Payload is a fresh copy (safe to hold after data is reused).
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("transport: packet too short")
	}
	payloadLen := binary.BigEndian.Uint16(data[9:11])
	if len(data) < HeaderSize+int(payloadLen) {
		return nil, errors.New("transport: packet truncated")
	}
	p := pktPool.Get().(*Packet)
	p.Type = data[0]
	p.SeqNum = binary.BigEndian.Uint32(data[1:5])
	p.AckNum = binary.BigEndian.Uint32(data[5:9])
	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		copy(p.Payload, data[HeaderSize:HeaderSize+int(payloadLen)])
	} else {
		p.Payload = nil
	}
	return p, nil
}

// pendingPacket tracks a sent but unACKed packet for retransmission.
type pendingPacket struct {
	pkt         *Packet
	firstSentAt time.Time // original send time (for RTT measurement — never updated)
	sentAt      time.Time // last send time (updated on retransmit — for RTO timeout)
	retransmits int

	// BBR delivery-rate snapshots taken at send time.
	delivered     int64
	deliveredTime time.Time
	appLimited    bool
}

// pendingPool reuses pendingPacket structs to avoid one heap allocation per
// sent packet. Returned to pool in processACK when the ACK arrives.
var pendingPool = sync.Pool{
	New: func() interface{} { return new(pendingPacket) },
}

// ackedPktInfo carries per-packet measurements collected under sendMu in
// processACK, then consumed outside sendMu to feed the BBR estimator.
type ackedPktInfo struct {
	seq           uint32
	rtt           time.Duration
	payloadSize   int
	delivered     int64
	deliveredTime time.Time
	sentAt        time.Time
	appLimited    bool
	retransmitted bool
}

// ackedSlicePool pools the backing arrays of the acked-packets slice used
// in processACK. At 30 Mbps with 1460-byte payloads, processACK is called
// ~2500 times/sec; reusing the backing array eliminates that many heap
// allocations and reduces GC pressure by ~3 MB/sec.
var ackedSlicePool = sync.Pool{
	New: func() interface{} {
		s := make([]ackedPktInfo, 0, 16)
		return &s
	},
}

// ackBufPool pools the fixed-size 11-byte slices used to encode pure ACK
// packets, eliminating one heap allocation per received data packet.
var ackBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, HeaderSize)
		b[0] = PacketTypeACK
		return &b
	},
}

// Conn is a reliable UDP connection providing ordered, ACKed delivery
// with BBR congestion control (user-space).
// Multiple goroutines may call Write, Read, and Close concurrently.
type Conn struct {
	conn    *net.UDPConn
	ownConn bool // true when this Conn owns conn (Dial-side)
	remote  *net.UDPAddr

	// Send side: sequence numbers and pending ACK tracking.
	sendMu   sync.Mutex
	sendCond *sync.Cond // signalled when cwnd opens (ACK received or conn closed)
	sendSeq  uint32
	sendBase uint32 // lowest unACKed seq (fast-path duplicate ACK detection)
	pending  map[uint32]*pendingPacket
	batch    *batchWriter // batched send (amortizes syscall overhead)

	// Receive side: ordered delivery buffer.
	recvMu  sync.Mutex
	recvSeq uint32
	recvBuf map[uint32]*Packet // out-of-order packets awaiting delivery

	// recvSeqAtomic mirrors recvSeq for lock-free reads from writePacket.
	// Updated atomically by processData after advancing recvSeq under recvMu.
	recvSeqAtomic atomic.Uint32

	// Congestion control: BBR (user-space).
	bbr *BBRState

	// Adaptive RTO (RFC 6298): SRTT + 4×RTTVAR, clamped to [minRTO, maxRTO].
	rtoMu  sync.Mutex
	srtt   time.Duration // smoothed RTT
	rttvar time.Duration // RTT variance
	rto    time.Duration // current retransmission timeout

	readCh    chan []byte
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closed    chan struct{}
}

// bbrMaxBurst is the initial pacing burst allowance in bytes (10 × MTU).
// Allows a small burst on connection start before pacing kicks in.
const bbrMaxBurst = 10 * MaxPayloadSize

// newConn constructs a Conn. ownConn controls whether Close() shuts down the
// underlying UDP socket (true for Dial-side, false for Listener-side).
func newConn(conn *net.UDPConn, remote *net.UDPAddr, ownConn bool) *Conn {
	ctx, cancel := context.WithCancel(context.Background())

	est := newBBREstimator()
	ifl := newInflightTracker()
	p := newPacer(0, bbrMaxBurst) // unlimited initial rate; Startup will ramp up
	bbr := NewBBRState(est, ifl, p, MaxPayloadSize)

	c := &Conn{
		conn:    conn,
		ownConn: ownConn,
		remote:  remote,
		pending: make(map[uint32]*pendingPacket, 128), // pre-allocate for typical cwnd
		recvBuf: make(map[uint32]*Packet, 32), // pre-allocate for typical reorder window
		readCh:  make(chan []byte, 256), // 256×1460≈370KB; 8192 caused bufferbloat (+1s latency)
		batch:   newBatchWriter(conn),
		bbr:     bbr,
		rto:     initialRTO,
		ctx:     ctx,
		cancel:  cancel,
		closed:  make(chan struct{}),
	}
	c.sendCond = sync.NewCond(&c.sendMu)
	go c.retransmitLoop()
	go c.batchFlushLoop()
	return c
}

// SetInitialBandwidth seeds the BBR model with a known bandwidth and RTT,
// skipping the slow Startup phase. Call before sending data.
// Example: conn.SetInitialBandwidth(12_500_000, 65*time.Millisecond) // 100 Mbps
func (c *Conn) SetInitialBandwidth(bytesPerSec int64, rtt time.Duration) {
	c.bbr.SetInitialBandwidth(bytesPerSec, rtt)
}

// batchFlushInterval is how often the flush loop checks for stale batches.
// 200µs balances latency (unflushed packets sit at most 200µs) vs CPU overhead.
const batchFlushInterval = 200 * time.Microsecond

// batchFlushLoop periodically flushes any pending batch to avoid packets
// sitting in the buffer when no new Write() arrives to trigger a flush.
// This is important when multiple Mux streams write concurrently — each
// stream's Write() flushes its own batch, but packets from OTHER streams'
// writePacket calls (queued between the last cwnd-trigger and Write's flush)
// might sit waiting.
func (c *Conn) batchFlushLoop() {
	ticker := time.NewTicker(batchFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.sendMu.Lock()
			if c.batch.Len() > 0 {
				c.batch.Flush() //nolint:errcheck
			}
			c.sendMu.Unlock()
		}
	}
}

// RemoteAddr returns the remote UDP address of this connection.
func (c *Conn) RemoteAddr() *net.UDPAddr { return c.remote }

// LocalAddr returns the local address of the underlying socket.
func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// Write sends data reliably, fragmenting into MaxPayloadSize chunks as needed.
// After all fragments are queued, any remaining batch is flushed so the data
// doesn't sit in the buffer waiting for more writes.
func (c *Conn) Write(data []byte) error {
	for len(data) > 0 {
		size := len(data)
		if size > MaxPayloadSize {
			size = MaxPayloadSize
		}
		if err := c.writePacket(PacketTypeData, data[:size]); err != nil {
			return err
		}
		data = data[size:]
	}
	// Flush any remaining packets that didn't trigger a batch flush
	// (e.g., last fragment didn't fill cwnd or batch).
	c.sendMu.Lock()
	err := c.batch.Flush()
	c.sendMu.Unlock()
	return err
}

// sendBufPool pools packet encode buffers to avoid allocation on the hot path.
var sendBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, HeaderSize+MaxPayloadSize)
		return &b
	},
}

// writePacket sends one packet and registers it for ACK tracking.
// Blocks if BBR's congestion window is full. Flow control is done entirely
// through cwnd — no per-packet pacing sleep (time.Sleep has ~1ms granularity
// in Go, which caps throughput at ~11 Mbps with 1400-byte packets).
func (c *Conn) writePacket(pktType uint8, payload []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	// Wait for BBR congestion window to open.
	cwndTarget := c.bbr.CwndTarget()
	for len(c.pending) >= cwndTarget {
		if c.ctx.Err() != nil {
			return errors.New("transport: connection closed")
		}
		c.sendCond.Wait()
		if c.ctx.Err() != nil {
			return errors.New("transport: connection closed")
		}
		cwndTarget = c.bbr.CwndTarget()
	}

	seq := c.sendSeq
	c.sendSeq++

	// Lock-free read of recvSeq for piggybacked ACK number.
	ackNum := c.recvSeqAtomic.Load()

	// Copy payload once for retransmission storage. The original slice
	// belongs to the caller and may be reused after Write returns.
	var payloadCopy []byte
	if len(payload) > 0 {
		payloadCopy = make([]byte, len(payload))
		copy(payloadCopy, payload)
	}

	// Encode packet using pooled buffer to avoid allocation.
	bp := sendBufPool.Get().(*[]byte)
	buf := (*bp)[:HeaderSize+len(payloadCopy)]
	buf[0] = pktType
	binary.BigEndian.PutUint32(buf[1:5], seq)
	binary.BigEndian.PutUint32(buf[5:9], ackNum)
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(payloadCopy)))
	copy(buf[HeaderSize:], payloadCopy) // copy from our owned slice

	// Take delivery-rate snapshot for BBR estimator.
	delivered, deliveredTime := c.bbr.estimator.DeliveredSnapshot()
	// Check if sender is app-limited (pipe not full at send time).
	// A packet is app-limited if inflight < cwnd at send time — meaning the
	// application, not the network, is constraining throughput. Only when the
	// pipe is full can we trust the measured delivery rate as a BtlBw sample.
	// Using len(c.pending) < cwndTarget (already computed above, no extra lock)
	// matches the Linux BBR definition. The previous check (== 0) only caught
	// the very first packet after idle; subsequent burst packets were incorrectly
	// marked non-app-limited, causing BtlBw to be underestimated after idle.
	appLimited := len(c.pending) < cwndTarget

	now := time.Now()

	// Add to batch instead of sending immediately.
	// The batch is flushed when: (a) full, or (b) cwnd will be full after this pkt.
	c.batch.Add(buf, c.remote, bp)

	// Flush batch if full OR if this packet fills the cwnd (next writePacket will block).
	pendingAfter := len(c.pending) + 1 // +1 for this packet we're about to register
	if c.batch.Len() >= maxBatchSize || pendingAfter >= cwndTarget {
		if err := c.batch.Flush(); err != nil {
			return err
		}
	}

	// Reuse the single payloadCopy for the retransmission record.
	pkt := &Packet{Type: pktType, SeqNum: seq, AckNum: ackNum, Payload: payloadCopy}

	pp := pendingPool.Get().(*pendingPacket)
	pp.pkt = pkt
	pp.firstSentAt = now
	pp.sentAt = now
	pp.retransmits = 0
	pp.delivered = delivered
	pp.deliveredTime = deliveredTime
	pp.appLimited = appLimited
	c.pending[seq] = pp

	// Register with BBR inflight tracker (pooled allocation).
	ifl := inflightPktPool.Get().(*inflightPkt)
	ifl.SeqNum = seq
	ifl.Size = len(payload)
	ifl.SentAt = now
	ifl.Retransmitted = false
	ifl.Delivered = delivered
	ifl.DeliveredTime = deliveredTime
	ifl.AppLimited = appLimited
	c.bbr.inflight.OnSend(ifl)

	return nil
}

// updateRTO implements RFC 6298 SRTT/RTTVAR calculation and updates c.rto.
func (c *Conn) updateRTO(rtt time.Duration) {
	c.rtoMu.Lock()
	defer c.rtoMu.Unlock()

	if c.srtt == 0 {
		// First measurement (RFC 6298 §2.2).
		c.srtt = rtt
		c.rttvar = rtt / 2
	} else {
		// Subsequent measurements (RFC 6298 §2.3).
		// RTTVAR = (1 - β) × RTTVAR + β × |SRTT - R|, β = 1/4
		diff := c.srtt - rtt
		if diff < 0 {
			diff = -diff
		}
		c.rttvar = (3*c.rttvar + diff) / 4
		// SRTT = (1 - α) × SRTT + α × R, α = 1/8
		c.srtt = (7*c.srtt + rtt) / 8
	}

	// RTO = SRTT + 4 × RTTVAR, clamped to [minRTO, maxRTO].
	c.rto = c.srtt + 4*c.rttvar
	if c.rto < minRTO {
		c.rto = minRTO
	}
	if c.rto > maxRTO {
		c.rto = maxRTO
	}
}

// getRTO returns the current adaptive retransmission timeout.
func (c *Conn) getRTO() time.Duration {
	c.rtoMu.Lock()
	defer c.rtoMu.Unlock()
	return c.rto
}

// processACK handles an incoming ACK, releasing pending packets up to ackNum
// and feeding the BBR estimator with per-ACK measurements.
func (c *Conn) processACK(ackNum uint32) {
	c.sendMu.Lock()

	// Fast path: duplicate or stale ACK — nothing to do.
	if ackNum <= c.sendBase {
		c.sendMu.Unlock()
		return
	}

	now := time.Now()

	// Phase 1: collect ACKed packets under sendMu (fast — just map lookups).
	// Reuse a pooled backing array to avoid a heap allocation on every ACK.
	// At 30 Mbps / 1460-byte payloads this eliminates ~2500 allocs/sec.
	ackedPtr := ackedSlicePool.Get().(*[]ackedPktInfo)
	acked := (*ackedPtr)[:0]
	for seq := range c.pending {
		if seq < ackNum {
			pp := c.pending[seq]
			delete(c.pending, seq)

			rtt := now.Sub(pp.firstSentAt)
			if rtt < 0 {
				rtt = time.Microsecond
			}

			acked = append(acked, ackedPktInfo{
				seq:           seq,
				rtt:           rtt,
				payloadSize:   len(pp.pkt.Payload),
				delivered:     pp.delivered,
				deliveredTime: pp.deliveredTime,
				sentAt:        pp.firstSentAt,
				appLimited:    pp.appLimited,
				retransmitted: pp.retransmits > 0,
			})

			// Return pendingPacket to pool.
			pp.pkt = nil // release payload reference for GC
			pendingPool.Put(pp)
		}
	}
	// Advance sendBase to the ACK frontier.
	c.sendBase = ackNum
	c.sendMu.Unlock()

	if len(acked) == 0 {
		// Nothing was ACKed — return the pooled slice immediately.
		*ackedPtr = acked[:0]
		ackedSlicePool.Put(ackedPtr)
		return
	}

	// Wake writePacket IMMEDIATELY after releasing sendMu — don't wait for
	// BBR processing. This lets the sender push new packets while we update
	// the BBR model, overlapping computation with I/O.
	c.sendCond.Broadcast()

	// Phase 2: feed BBR outside sendMu (no lock contention with writePacket).
	for _, a := range acked {
		if !a.retransmitted {
			c.updateRTO(a.rtt)
		}
		// Use the inflightPkt returned by OnACK — it already has all delivery
		// snapshots, so we avoid allocating a new one.
		ifl, ok := c.bbr.inflight.OnACK(a.seq)
		if ok {
			c.bbr.OnACK(a.rtt, int64(a.payloadSize), ifl)
			inflightPktPool.Put(ifl)
		}
	}

	// Return pooled slice. Zero elements first so pooled backing array does not
	// retain references to time.Time locations or large payload data past their
	// useful lifetime.
	for i := range acked {
		acked[i] = ackedPktInfo{}
	}
	*ackedPtr = acked[:0]
	ackedSlicePool.Put(ackedPtr)
}

// processData handles an incoming data packet, buffers out-of-order packets,
// delivers in-order data to readCh, and sends a cumulative ACK.
func (c *Conn) processData(pkt *Packet) {
	c.recvMu.Lock()

	toDeliver := make([][]byte, 0, 4)
	if pkt.SeqNum == c.recvSeq {
		// In-order: deliver immediately.
		// pkt.Payload is already a unique copy from DecodePacket — no need to copy again.
		if len(pkt.Payload) > 0 {
			toDeliver = append(toDeliver, pkt.Payload)
		}
		c.recvSeq++

		// Drain any consecutively buffered packets.
		for {
			buffered, ok := c.recvBuf[c.recvSeq]
			if !ok {
				break
			}
			if len(buffered.Payload) > 0 {
				toDeliver = append(toDeliver, buffered.Payload)
			}
			delete(c.recvBuf, c.recvSeq)
			c.recvSeq++
		}
	} else if pkt.SeqNum > c.recvSeq {
		// Out-of-order: buffer for later delivery.
		c.recvBuf[pkt.SeqNum] = pkt
	}
	// Duplicate (pkt.SeqNum < c.recvSeq): silently discard.

	// Publish recvSeq for lock-free reads (writePacket, sendACK).
	c.recvSeqAtomic.Store(c.recvSeq)
	c.recvMu.Unlock()

	// Send ACK BEFORE delivering to readCh.
	// Critical for BBR throughput: delivery rate is measured from the time
	// between packets being sent and their ACKs arriving. If readCh is full
	// (consumer is slow), the blocking send below can delay ACKs by 100-300ms.
	// BBR then measures near-zero delivery rate, slashes cwnd, and throughput
	// collapses to ~1 Mbps in a downward spiral.
	// Sending ACK first decouples BBR feedback from consumer backpressure.
	c.sendACK()

	// Deliver payloads OUTSIDE recvMu to avoid deadlock if readCh is full.
	for _, payload := range toDeliver {
		select {
		case c.readCh <- payload:
		case <-c.closed:
			return
		}
	}
}

// sendACK encodes and transmits a pure ACK packet using a pooled buffer to
// avoid a heap allocation per call.
func (c *Conn) sendACK() {
	ackNum := c.recvSeqAtomic.Load()

	bp := ackBufPool.Get().(*[]byte)
	buf := (*bp)[:HeaderSize]
	buf[0] = PacketTypeACK
	binary.BigEndian.PutUint32(buf[1:5], 0)      // SeqNum = 0 for pure ACK
	binary.BigEndian.PutUint32(buf[5:9], ackNum)
	binary.BigEndian.PutUint16(buf[9:11], 0)     // payloadLen = 0
	c.conn.WriteToUDP(buf, c.remote)              //nolint:errcheck
	ackBufPool.Put(bp)
}

// retransmitLoop periodically calls doRetransmit until the connection closes.
// The check interval adapts to the current RTO: max(20ms, RTO/4).
// This avoids wasting CPU scanning pending packets when RTO is high,
// while still detecting timeouts quickly on low-latency paths.
func (c *Conn) retransmitLoop() {
	timer := time.NewTimer(retransmitTick)
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-timer.C:
			c.doRetransmit()
			// Adaptive interval: check more often when RTO is short.
			interval := c.getRTO() / 4
			if interval < 20*time.Millisecond {
				interval = 20 * time.Millisecond
			}
			if interval > 200*time.Millisecond {
				interval = 200 * time.Millisecond
			}
			timer.Reset(interval)
		}
	}
}

// rtxItem holds a pre-encoded retransmit packet ready to send outside sendMu.
type rtxItem struct {
	bp  *[]byte // pointer to pooled buffer (must be returned to sendBufPool)
	buf []byte  // sub-slice of *bp with the encoded frame
}

// doRetransmit resends any packet whose RetransmitTimeout has elapsed.
// BBR does NOT halve cwnd on retransmit (unlike TCP Reno). It just
// retransmits the packet and lets BBR.OnLoss() handle rate adjustment
// only if loss rate exceeds 2%.
//
// Optimisation: packets are encoded and their state updated under sendMu, but
// the actual WriteToUDP syscalls happen AFTER releasing sendMu. This eliminates
// the sendMu hold time from O(N×syscall) to O(N×memcopy), so writePacket is not
// blocked while the OS drains the retransmit queue.
func (c *Conn) doRetransmit() {
	dropped := 0
	lostBytes := int64(0)
	now := time.Now()
	rto := c.getRTO()

	// rtxPending is a small stack-allocated slice; grows on heap only under loss.
	var rtxPending [8]rtxItem
	toSend := rtxPending[:0]

	c.sendMu.Lock()
	for seq, pp := range c.pending {
		if now.Sub(pp.sentAt) < rto {
			continue
		}
		if pp.retransmits >= MaxRetransmits {
			// Give up on this packet — free the window slot.
			payloadLen := int64(len(pp.pkt.Payload))
			delete(c.pending, seq)
			if ifl, ok := c.bbr.inflight.OnLoss(seq); ok {
				inflightPktPool.Put(ifl)
			}
			lostBytes += payloadLen
			dropped++
			pp.pkt = nil
			pendingPool.Put(pp)
			continue
		}

		// Mark as loss in BBR inflight tracker on first retransmit.
		if pp.retransmits == 0 {
			lostBytes += int64(len(pp.pkt.Payload))
			if ifl, ok := c.bbr.inflight.OnLoss(seq); ok {
				inflightPktPool.Put(ifl)
			}
		}

		// Pre-encode frame into a pooled buffer (pure memory ops — no syscall).
		rbp := sendBufPool.Get().(*[]byte)
		rbuf := (*rbp)[:HeaderSize+len(pp.pkt.Payload)]
		rbuf[0] = pp.pkt.Type
		binary.BigEndian.PutUint32(rbuf[1:5], pp.pkt.SeqNum)
		binary.BigEndian.PutUint32(rbuf[5:9], pp.pkt.AckNum)
		binary.BigEndian.PutUint16(rbuf[9:11], uint16(len(pp.pkt.Payload)))
		copy(rbuf[HeaderSize:], pp.pkt.Payload)
		toSend = append(toSend, rtxItem{bp: rbp, buf: rbuf})

		// Update retransmit state under lock so next tick won't re-queue.
		pp.sentAt = now
		pp.retransmits++

		// Re-register in inflight tracker with fresh delivery snapshot (pooled).
		delivered, deliveredTime := c.bbr.estimator.DeliveredSnapshot()
		ifl := inflightPktPool.Get().(*inflightPkt)
		ifl.SeqNum = seq
		ifl.Size = len(pp.pkt.Payload)
		ifl.SentAt = now
		ifl.Retransmitted = true
		ifl.Delivered = delivered
		ifl.DeliveredTime = deliveredTime
		ifl.AppLimited = false
		c.bbr.inflight.OnSend(ifl)
	}
	c.sendMu.Unlock()

	// Send retransmits OUTSIDE sendMu — WriteToUDP is a syscall that can take
	// 1–50 µs per call; holding sendMu across N such calls would block
	// writePacket for N×50 µs, capping throughput under loss conditions.
	// UDP sockets are safe for concurrent writes from multiple goroutines.
	for _, item := range toSend {
		c.conn.WriteToUDP(item.buf, c.remote) //nolint:errcheck
		sendBufPool.Put(item.bp)
	}

	// Notify BBR about loss (it only reduces cwnd if loss rate > 2%).
	if lostBytes > 0 {
		c.bbr.OnLoss(lostBytes)
	}

	// Dropped packets free window slots; wake any blocked writePacket callers.
	if dropped > 0 {
		c.sendCond.Broadcast()
	}
}

// Read blocks until a data payload is available, the context is cancelled,
// or the connection is closed.
func (c *Conn) Read(ctx context.Context) ([]byte, error) {
	select {
	case data := <-c.readCh:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("transport: connection closed")
	}
}

// Close shuts down the connection and, for Dial-side conns, the UDP socket.
func (c *Conn) Close() {
	c.closeOnce.Do(func() {
		// Flush any pending batch before closing.
		c.sendMu.Lock()
		c.batch.Flush() //nolint:errcheck
		c.sendMu.Unlock()
		// Send final ACK before closing.
		c.sendACK()
		c.cancel()
		// Wake any writePacket goroutine blocked on a full congestion window so
		// it can observe the cancelled context and return immediately.
		c.sendCond.Broadcast()
		close(c.closed)
		if c.ownConn {
			c.conn.Close()
		}
	})
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

// Listener accepts incoming reliable UDP connections on a fixed local address.
type Listener struct {
	conn     *net.UDPConn
	connsMu  sync.RWMutex
	conns    map[string]*Conn
	acceptCh chan *Conn
	ctx      context.Context
	cancel   context.CancelFunc
}

// udpSocketBufSize is the target SO_RCVBUF/SO_SNDBUF size for UDP sockets.
// 4 MB allows the kernel to buffer bursts without dropping packets,
// which is critical for user-space congestion control where processing
// latency is higher than in-kernel TCP.
const udpSocketBufSize = 4 * 1024 * 1024

// setUDPBuffers attempts to increase the UDP socket read/write buffers.
// Errors are silently ignored — the OS may cap the size.
func setUDPBuffers(conn *net.UDPConn) {
	conn.SetReadBuffer(udpSocketBufSize)  //nolint:errcheck
	conn.SetWriteBuffer(udpSocketBufSize) //nolint:errcheck
}

// Listen creates a UDP listener bound to addr (e.g. "0.0.0.0:4433").
func Listen(addr string) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	setUDPBuffers(conn)
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		conn:     conn,
		conns:    make(map[string]*Conn),
		acceptCh: make(chan *Conn, 16),
		ctx:      ctx,
		cancel:   cancel,
	}
	go l.readLoop()
	return l, nil
}

// Addr returns the listener's local network address.
func (l *Listener) Addr() net.Addr { return l.conn.LocalAddr() }

// Accept waits for the next incoming connection.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.ctx.Done():
		return nil, errors.New("transport: listener closed")
	}
}

// readLoop is the listener's receive goroutine. It demultiplexes incoming UDP
// datagrams to per-remote-address Conn objects, creating new ones as needed.
// Uses batchReader to amortize syscall overhead when the platform supports it.
func (l *Listener) readLoop() {
	reader := newBatchReader(l.conn, maxBatchSize)
	for {
		results, count, err := reader.Read()
		if err != nil {
			select {
			case <-l.ctx.Done():
				return
			default:
				continue
			}
		}

		for i := 0; i < count; i++ {
			pkt, err := DecodePacket(results[i].buf)
			if err != nil {
				continue
			}

			remote := results[i].addr
			key := remote.String()
			l.connsMu.RLock()
			c, exists := l.conns[key]
			l.connsMu.RUnlock()

			if !exists {
				// New remote — create a Conn sharing the listener's socket.
				c = newConn(l.conn, remote, false)
				l.connsMu.Lock()
				l.conns[key] = c
				l.connsMu.Unlock()
				select {
				case l.acceptCh <- c:
				default:
				}
			}

			switch pkt.Type {
			case PacketTypeData, PacketTypeSYN, PacketTypeFIN:
				c.processData(pkt)
			case PacketTypeACK:
				c.processACK(pkt.AckNum)
				pkt.Payload = nil
				pktPool.Put(pkt)
			}
		}
	}
}

// Close shuts down the listener, its read loop, and all active connections.
func (l *Listener) Close() {
	l.cancel()
	l.conn.Close()

	l.connsMu.RLock()
	defer l.connsMu.RUnlock()
	for _, c := range l.conns {
		c.Close()
	}
}

// ---------------------------------------------------------------------------
// Dial
// ---------------------------------------------------------------------------

// Dial creates a reliable UDP connection to the server at addr.
func Dial(addr string) (*Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	// Bind to an ephemeral port on the wildcard address.
	local := &net.UDPAddr{}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, err
	}
	setUDPBuffers(conn)
	c := newConn(conn, udpAddr, true)
	go dialReadLoop(conn, c)
	return c, nil
}

// dialReadLoop is the receive goroutine for a Dial-side Conn.
// Uses batchReader to amortize syscall overhead when the platform supports it.
func dialReadLoop(conn *net.UDPConn, c *Conn) {
	reader := newBatchReader(conn, maxBatchSize)
	for {
		results, count, err := reader.Read()
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}
		for i := 0; i < count; i++ {
			pkt, err := DecodePacket(results[i].buf)
			if err != nil {
				continue
			}
			switch pkt.Type {
			case PacketTypeData, PacketTypeSYN, PacketTypeFIN:
				c.processData(pkt)
			case PacketTypeACK:
				c.processACK(pkt.AckNum)
				pkt.Payload = nil
				pktPool.Put(pkt)
			}
		}
	}
}
