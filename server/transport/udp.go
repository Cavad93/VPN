// Package transport implements reliable UDP transport with ACK, retransmission,
// packet ordering, and BBR congestion control (user-space).
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
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

	// MaxPayloadSize is the maximum payload per packet (fits in typical MTU).
	MaxPayloadSize = 1400

	// MaxWindowSize caps the congestion window.
	MaxWindowSize = 64

	// initialRTO is the retransmission timeout before any RTT samples.
	initialRTO = 1 * time.Second
	// minRTO prevents too-aggressive retransmission on fast paths.
	minRTO = 200 * time.Millisecond
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

// DecodePacket parses a packet from raw bytes.
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("transport: packet too short")
	}
	payloadLen := binary.BigEndian.Uint16(data[9:11])
	if len(data) < HeaderSize+int(payloadLen) {
		return nil, errors.New("transport: packet truncated")
	}
	p := &Packet{
		Type:   data[0],
		SeqNum: binary.BigEndian.Uint32(data[1:5]),
		AckNum: binary.BigEndian.Uint32(data[5:9]),
	}
	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		copy(p.Payload, data[HeaderSize:HeaderSize+int(payloadLen)])
	}
	return p, nil
}

// pendingPacket tracks a sent but unACKed packet for retransmission.
type pendingPacket struct {
	pkt         *Packet
	sentAt      time.Time
	retransmits int

	// BBR delivery-rate snapshots taken at send time.
	delivered     int64
	deliveredTime time.Time
	appLimited    bool
}

// ackDelay is the maximum time to wait before flushing a coalesced ACK.
// Mirrors TCP delayed ACK (RFC 1122 §4.2.3.2). 1 ms keeps latency low while
// halving ACK packet count in sustained streaming scenarios.
const ackDelay = time.Millisecond

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
	pending  map[uint32]*pendingPacket

	// Receive side: ordered delivery buffer.
	recvMu  sync.Mutex
	recvSeq uint32
	recvBuf map[uint32]*Packet // out-of-order packets awaiting delivery

	// Delayed ACK: coalesce multiple received packets into one ACK (RFC 1122).
	ackMu      sync.Mutex
	ackPending bool       // true when an ACK needs to be sent
	ackTimer   *time.Timer

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
		pending: make(map[uint32]*pendingPacket),
		recvBuf: make(map[uint32]*Packet),
		readCh:  make(chan []byte, 256),
		bbr:     bbr,
		rto:     initialRTO,
		ctx:     ctx,
		cancel:  cancel,
		closed:  make(chan struct{}),
	}
	c.sendCond = sync.NewCond(&c.sendMu)
	go c.retransmitLoop()
	return c
}

// RemoteAddr returns the remote UDP address of this connection.
func (c *Conn) RemoteAddr() *net.UDPAddr { return c.remote }

// LocalAddr returns the local address of the underlying socket.
func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// Write sends data reliably, fragmenting into MaxPayloadSize chunks as needed.
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
	return nil
}

// writePacket sends one packet and registers it for ACK tracking.
// Blocks if BBR's congestion window is full. Uses BBR pacing to space
// packet transmissions evenly.
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

	// BBR pacing: wait for the next send slot (releases sendMu briefly).
	// We unlock during the sleep so ACK processing is not blocked.
	c.sendMu.Unlock()
	c.bbr.pacer.WaitForSlot(len(payload))
	c.sendMu.Lock()
	if c.ctx.Err() != nil {
		return errors.New("transport: connection closed")
	}

	seq := c.sendSeq
	c.sendSeq++

	c.recvMu.Lock()
	ackNum := c.recvSeq
	c.recvMu.Unlock()

	pkt := &Packet{
		Type:   pktType,
		SeqNum: seq,
		AckNum: ackNum,
	}
	if len(payload) > 0 {
		pkt.Payload = make([]byte, len(payload))
		copy(pkt.Payload, payload)
	}

	// Take delivery-rate snapshot for BBR estimator.
	delivered, deliveredTime := c.bbr.estimator.DeliveredSnapshot()
	// Check if sender is app-limited (no data queued beyond this packet).
	appLimited := len(c.pending) == 0

	now := time.Now()
	if _, err := c.conn.WriteToUDP(pkt.Encode(), c.remote); err != nil {
		return err
	}
	c.pending[seq] = &pendingPacket{
		pkt:           pkt,
		sentAt:        now,
		delivered:     delivered,
		deliveredTime: deliveredTime,
		appLimited:    appLimited,
	}

	// Register with BBR inflight tracker.
	c.bbr.inflight.OnSend(&inflightPkt{
		SeqNum:        seq,
		Size:          len(payload),
		SentAt:        now,
		Delivered:     delivered,
		DeliveredTime: deliveredTime,
		AppLimited:    appLimited,
	})

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

	now := time.Now()
	cleared := 0
	for seq := range c.pending {
		if seq < ackNum {
			pp := c.pending[seq]
			delete(c.pending, seq)
			cleared++

			// Only use RTT from non-retransmitted packets (Karn's algorithm).
			rtt := now.Sub(pp.sentAt)
			if rtt < 0 {
				rtt = time.Microsecond // safety floor
			}
			if pp.retransmits == 0 {
				c.updateRTO(rtt)
			}

			// Build inflight metadata for BBR.
			iflPkt := &inflightPkt{
				SeqNum:        seq,
				Size:          len(pp.pkt.Payload),
				SentAt:        pp.sentAt,
				Delivered:     pp.delivered,
				DeliveredTime: pp.deliveredTime,
				AppLimited:    pp.appLimited,
			}

			// Remove from inflight tracker.
			c.bbr.inflight.OnACK(seq)

			// Feed BBR state machine.
			c.bbr.OnACK(rtt, int64(len(pp.pkt.Payload)), iflPkt)
		}
	}
	c.sendMu.Unlock()

	// Wake any writePacket goroutine blocked on a full window.
	if cleared > 0 {
		c.sendCond.Broadcast()
	}
}

// processData handles an incoming data packet, buffers out-of-order packets,
// delivers in-order data to readCh, and sends a cumulative ACK.
func (c *Conn) processData(pkt *Packet) {
	c.recvMu.Lock()

	if pkt.SeqNum == c.recvSeq {
		// In-order: deliver immediately.
		if len(pkt.Payload) > 0 {
			payload := make([]byte, len(pkt.Payload))
			copy(payload, pkt.Payload)
			select {
			case c.readCh <- payload:
			default:
			}
		}
		c.recvSeq++

		// Drain any consecutively buffered packets.
		for {
			buffered, ok := c.recvBuf[c.recvSeq]
			if !ok {
				break
			}
			if len(buffered.Payload) > 0 {
				payload := make([]byte, len(buffered.Payload))
				copy(payload, buffered.Payload)
				select {
				case c.readCh <- payload:
				default:
				}
			}
			delete(c.recvBuf, c.recvSeq)
			c.recvSeq++
		}
	} else if pkt.SeqNum > c.recvSeq {
		// Out-of-order: buffer for later delivery.
		c.recvBuf[pkt.SeqNum] = pkt
	}
	// Duplicate (pkt.SeqNum < c.recvSeq): silently discard.

	ackNum := c.recvSeq
	c.recvMu.Unlock()

	// Schedule a delayed ACK (RFC 1122 §4.2.3.2).
	// If the timer is already running the existing timer will flush the ACK;
	// otherwise we start a new ackDelay timer. This coalesces multiple
	// back-to-back ACKs into one UDP packet, reducing ACK overhead by ~50% in
	// sustained streaming scenarios while keeping the delay ≤1 ms.
	c.ackMu.Lock()
	c.ackPending = true
	if c.ackTimer == nil {
		c.ackTimer = time.AfterFunc(ackDelay, func() {
			c.ackMu.Lock()
			pending := c.ackPending
			c.ackPending = false
			c.ackTimer = nil
			c.ackMu.Unlock()
			if pending {
				c.sendACK()
			}
		})
	}
	c.ackMu.Unlock()
	_ = ackNum // ackNum read at flush time from c.recvSeq
}

// sendACK encodes and transmits a pure ACK packet using a pooled buffer to
// avoid a heap allocation per call.
func (c *Conn) sendACK() {
	c.recvMu.Lock()
	ackNum := c.recvSeq
	c.recvMu.Unlock()

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
func (c *Conn) retransmitLoop() {
	ticker := time.NewTicker(retransmitTick)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.doRetransmit()
		}
	}
}

// doRetransmit resends any packet whose RetransmitTimeout has elapsed.
// BBR does NOT halve cwnd on retransmit (unlike TCP Reno). It just
// retransmits the packet and lets BBR.OnLoss() handle rate adjustment
// only if loss rate exceeds 2%.
func (c *Conn) doRetransmit() {
	c.sendMu.Lock()

	dropped := 0
	lostBytes := int64(0)
	now := time.Now()
	rto := c.getRTO()
	for seq, pp := range c.pending {
		if now.Sub(pp.sentAt) < rto {
			continue
		}
		if pp.retransmits >= MaxRetransmits {
			// Give up on this packet — free the window slot.
			payloadLen := int64(len(pp.pkt.Payload))
			delete(c.pending, seq)
			c.bbr.inflight.OnLoss(seq)
			lostBytes += payloadLen
			dropped++
			continue
		}

		// Mark as loss in BBR inflight tracker and retransmit.
		if pp.retransmits == 0 {
			// First retransmit — count as a loss event.
			lostBytes += int64(len(pp.pkt.Payload))
			c.bbr.inflight.OnLoss(seq)
		}

		c.conn.WriteToUDP(pp.pkt.Encode(), c.remote) //nolint:errcheck
		pp.sentAt = now
		pp.retransmits++

		// Re-register in inflight tracker with fresh delivery snapshot.
		delivered, deliveredTime := c.bbr.estimator.DeliveredSnapshot()
		c.bbr.inflight.OnSend(&inflightPkt{
			SeqNum:        seq,
			Size:          len(pp.pkt.Payload),
			SentAt:        now,
			Delivered:     delivered,
			DeliveredTime: deliveredTime,
			Retransmitted: true,
		})
	}
	c.sendMu.Unlock()

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
// Any pending delayed ACK is flushed synchronously before closing so the remote
// receives the final cumulative ACK.
func (c *Conn) Close() {
	c.closeOnce.Do(func() {
		// Flush pending delayed ACK before cancelling context.
		c.ackMu.Lock()
		if c.ackTimer != nil {
			c.ackTimer.Stop()
			c.ackTimer = nil
		}
		pending := c.ackPending
		c.ackPending = false
		c.ackMu.Unlock()
		if pending {
			c.sendACK()
		}

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
func (l *Listener) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, remote, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.ctx.Done():
				return
			default:
				continue
			}
		}

		pkt, err := DecodePacket(buf[:n])
		if err != nil {
			continue
		}

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
	c := newConn(conn, udpAddr, true)
	go dialReadLoop(conn, c)
	return c, nil
}

// dialReadLoop is the receive goroutine for a Dial-side Conn.
func dialReadLoop(conn *net.UDPConn, c *Conn) {
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}
		pkt, err := DecodePacket(buf[:n])
		if err != nil {
			continue
		}
		switch pkt.Type {
		case PacketTypeData, PacketTypeSYN, PacketTypeFIN:
			c.processData(pkt)
		case PacketTypeACK:
			c.processACK(pkt.AckNum)
		}
	}
}
