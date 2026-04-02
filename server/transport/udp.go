// Package transport implements reliable UDP transport with ACK, retransmission,
// packet ordering, and congestion control (TCP Reno-style slow start).
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

	// RetransmitTimeout is how long to wait before retransmitting an unACKed packet.
	RetransmitTimeout = 200 * time.Millisecond

	// MaxRetransmits is the maximum number of retransmission attempts before dropping.
	MaxRetransmits = 10

	// retransmitTick is how often the retransmit loop wakes up.
	retransmitTick = RetransmitTimeout / 4
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
}

// Conn is a reliable UDP connection providing ordered, ACKed delivery.
// Multiple goroutines may call Write, Read, and Close concurrently.
type Conn struct {
	conn    *net.UDPConn
	ownConn bool // true when this Conn owns conn (Dial-side)
	remote  *net.UDPAddr

	// Send side: sequence numbers and pending ACK tracking.
	sendMu  sync.Mutex
	sendSeq uint32
	pending map[uint32]*pendingPacket

	// Receive side: ordered delivery buffer.
	recvMu  sync.Mutex
	recvSeq uint32
	recvBuf map[uint32]*Packet // out-of-order packets awaiting delivery

	// Congestion control (TCP Reno-style).
	cwnd     int // current congestion window
	ssthresh int // slow-start threshold

	readCh    chan []byte
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closed    chan struct{}
}

// newConn constructs a Conn. ownConn controls whether Close() shuts down the
// underlying UDP socket (true for Dial-side, false for Listener-side).
func newConn(conn *net.UDPConn, remote *net.UDPAddr, ownConn bool) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		conn:     conn,
		ownConn:  ownConn,
		remote:   remote,
		pending:  make(map[uint32]*pendingPacket),
		recvBuf:  make(map[uint32]*Packet),
		readCh:   make(chan []byte, 256),
		cwnd:     4,
		ssthresh: 32,
		ctx:      ctx,
		cancel:   cancel,
		closed:   make(chan struct{}),
	}
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
// Blocks if the congestion window is full.
func (c *Conn) writePacket(pktType uint8, payload []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	// Wait for the congestion window to open.
	for len(c.pending) >= c.cwnd {
		c.sendMu.Unlock()
		select {
		case <-c.ctx.Done():
			c.sendMu.Lock()
			return errors.New("transport: connection closed")
		case <-time.After(time.Millisecond):
		}
		c.sendMu.Lock()
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

	if _, err := c.conn.WriteToUDP(pkt.Encode(), c.remote); err != nil {
		return err
	}
	c.pending[seq] = &pendingPacket{pkt: pkt, sentAt: time.Now()}
	return nil
}

// processACK handles an incoming ACK, releasing pending packets up to ackNum
// and growing the congestion window.
func (c *Conn) processACK(ackNum uint32) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	for seq := range c.pending {
		if seq < ackNum {
			delete(c.pending, seq)
			// Congestion window growth.
			if c.cwnd < c.ssthresh {
				c.cwnd++ // slow start: exponential
			} else if c.cwnd < MaxWindowSize {
				c.cwnd++ // congestion avoidance: linear (simplified)
			}
		}
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

	// Send cumulative ACK; errors are non-fatal (sender will retransmit).
	ack := &Packet{Type: PacketTypeACK, AckNum: ackNum}
	c.conn.WriteToUDP(ack.Encode(), c.remote) //nolint:errcheck
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

// doRetransmit resends any packet whose RetransmitTimeout has elapsed and
// applies multiplicative-decrease congestion control on each loss event.
func (c *Conn) doRetransmit() {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	now := time.Now()
	for seq, pp := range c.pending {
		if now.Sub(pp.sentAt) < RetransmitTimeout {
			continue
		}
		if pp.retransmits >= MaxRetransmits {
			// Give up on this packet.
			delete(c.pending, seq)
			continue
		}
		c.conn.WriteToUDP(pp.pkt.Encode(), c.remote) //nolint:errcheck
		pp.sentAt = now
		pp.retransmits++

		// Multiplicative decrease (TCP Reno on loss).
		c.ssthresh = c.cwnd / 2
		if c.ssthresh < 2 {
			c.ssthresh = 2
		}
		c.cwnd = c.ssthresh
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
		c.cancel()
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
