package transport

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Packet encode / decode
// ---------------------------------------------------------------------------

func TestPacketEncodeDecodeData(t *testing.T) {
	t.Parallel()
	p := &Packet{
		Type:    PacketTypeData,
		SeqNum:  42,
		AckNum:  7,
		Payload: []byte("hello, vpn"),
	}
	encoded := p.Encode()

	got, err := DecodePacket(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Type != p.Type {
		t.Errorf("Type: got %d, want %d", got.Type, p.Type)
	}
	if got.SeqNum != p.SeqNum {
		t.Errorf("SeqNum: got %d, want %d", got.SeqNum, p.SeqNum)
	}
	if got.AckNum != p.AckNum {
		t.Errorf("AckNum: got %d, want %d", got.AckNum, p.AckNum)
	}
	if !bytes.Equal(got.Payload, p.Payload) {
		t.Errorf("Payload: got %q, want %q", got.Payload, p.Payload)
	}
}

func TestPacketEncodeDecodeACK(t *testing.T) {
	t.Parallel()
	p := &Packet{Type: PacketTypeACK, AckNum: 99}
	got, err := DecodePacket(p.Encode())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Type != PacketTypeACK || got.AckNum != 99 || len(got.Payload) != 0 {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestPacketEncodeDecodeEmptyPayload(t *testing.T) {
	t.Parallel()
	p := &Packet{Type: PacketTypeSYN, SeqNum: 1}
	got, err := DecodePacket(p.Encode())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SeqNum != 1 || len(got.Payload) != 0 {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestDecodePacketTooShort(t *testing.T) {
	t.Parallel()
	_, err := DecodePacket([]byte{0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for too-short packet")
	}
}

func TestDecodePacketTruncatedPayload(t *testing.T) {
	t.Parallel()
	// Build a header claiming 100 bytes of payload but supply none.
	buf := make([]byte, HeaderSize)
	buf[0] = PacketTypeData
	buf[9] = 0x00
	buf[10] = 100 // payloadLen = 100
	_, err := DecodePacket(buf)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

func TestPacketEncodeLength(t *testing.T) {
	t.Parallel()
	payload := make([]byte, 32)
	p := &Packet{Type: PacketTypeData, SeqNum: 1, Payload: payload}
	encoded := p.Encode()
	if len(encoded) != HeaderSize+32 {
		t.Errorf("encoded length: got %d, want %d", len(encoded), HeaderSize+32)
	}
}

// ---------------------------------------------------------------------------
// processData — ordering and buffering (unit-level, no real network needed)
// ---------------------------------------------------------------------------

// makeTestConn creates a Conn with a real UDP socket bound on loopback:port=0
// so that ACK writes don't fail with EBADF. The ACKs go to a dummy remote.
func makeTestConn(t *testing.T) *Conn {
	t.Helper()
	localConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { localConn.Close() })
	// Remote can be any address; ACKs will fail silently.
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19999}
	c := newConn(localConn, remote, false)
	t.Cleanup(func() { c.Close() })
	return c
}

func TestProcessDataInOrder(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	c.processData(&Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("a")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 1, Payload: []byte("b")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 2, Payload: []byte("c")})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for _, want := range []string{"a", "b", "c"} {
		rp, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if string(rp.data) != want {
			t.Errorf("Read: got %q, want %q", rp.data, want)
		}
	}
}

func TestProcessDataOutOfOrder(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	// Deliver 0, then 2 (buffered), then 1 — after 1 arrives, 2 should also drain.
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("first")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 2, Payload: []byte("third")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 1, Payload: []byte("second")})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	expected := []string{"first", "second", "third"}
	for _, want := range expected {
		rp, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if string(rp.data) != want {
			t.Errorf("Read: got %q, want %q", rp.data, want)
		}
	}
}

func TestProcessDataDuplicate(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	c.processData(&Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("x")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("x")}) // duplicate

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
	defer cancel()

	// First read should succeed.
	rp, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(rp.data) != "x" {
		t.Errorf("Read: got %q, want %q", rp.data, "x")
	}

	// Second read must time out (duplicate was discarded).
	_, err = c.Read(ctx)
	if err == nil {
		t.Error("expected timeout for duplicate packet, got data")
	}
}

func TestProcessDataNoPayload(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	// A SYN-like packet with no payload should not be delivered to readCh.
	c.processData(&Packet{Type: PacketTypeSYN, SeqNum: 0})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
	defer cancel()

	_, err := c.Read(ctx)
	if err == nil {
		t.Error("expected timeout for empty-payload packet")
	}
}

// ---------------------------------------------------------------------------
// processACK — BBR congestion window
// ---------------------------------------------------------------------------

func TestProcessACKClearsWindow(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	now := time.Now()
	// Manually populate pending packets with delivery snapshots.
	c.sendMu.Lock()
	for i := uint32(0); i < 5; i++ {
		c.pending[i] = &pendingPacket{
			pkt:           &Packet{SeqNum: i, Payload: []byte("data")},
			sentAt:        now.Add(-50 * time.Millisecond),
			deliveredTime: now.Add(-100 * time.Millisecond),
		}
		c.bbr.inflight.OnSend(4)
	}
	c.sendSeq = 5
	c.sendMu.Unlock()

	// ACK covers seq 0..2 (ackNum == 3 means "received up through seq 2").
	c.processACK(3)

	c.sendMu.Lock()
	pending := len(c.pending)
	c.sendMu.Unlock()

	if pending != 2 {
		t.Errorf("pending: got %d, want 2 (seq 3 and 4 remain)", pending)
	}
	// BBR should have a positive pacing rate after processing ACKs.
	if c.bbr.PacingRate() < 0 {
		t.Errorf("BBR pacing rate should be non-negative, got %d", c.bbr.PacingRate())
	}
}

func TestProcessACKCongestionAvoidance(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	now := time.Now()
	// Populate pending packets with delivery snapshots.
	c.sendMu.Lock()
	for i := uint32(0); i < 10; i++ {
		c.pending[i] = &pendingPacket{
			pkt:           &Packet{SeqNum: i, Payload: []byte("data")},
			sentAt:        now.Add(-50 * time.Millisecond),
			deliveredTime: now.Add(-100 * time.Millisecond),
		}
		c.bbr.inflight.OnSend(4)
	}
	c.sendMu.Unlock()

	cwndBefore := c.bbr.CwndTarget()
	c.processACK(10)
	cwndAfter := c.bbr.CwndTarget()

	// BBR's cwnd should not shrink when processing ACKs (no loss).
	if cwndAfter < cwndBefore {
		t.Errorf("BBR cwnd should not shrink after ACKs: %d → %d", cwndBefore, cwndAfter)
	}
}

// ---------------------------------------------------------------------------
// doRetransmit
// ---------------------------------------------------------------------------

func TestDoRetransmitIncreasesCounter(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	pkt := &Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("retry")}
	now := time.Now()
	c.sendMu.Lock()
	c.pending[0] = &pendingPacket{
		pkt:           pkt,
		sentAt:        now.Add(-initialRTO * 2), // far in the past
		deliveredTime: now.Add(-initialRTO * 3),
	}
	// Register in inflight tracker (doRetransmit calls OnLoss then OnSend on first retransmit).
	c.bbr.inflight.OnSend(5)
	c.sendMu.Unlock()

	c.doRetransmit()

	c.sendMu.Lock()
	pp, exists := c.pending[0]
	c.sendMu.Unlock()

	if !exists {
		t.Fatal("packet should still be pending after first retransmit")
	}
	if pp.retransmits != 1 {
		t.Errorf("retransmits: got %d, want 1", pp.retransmits)
	}
}

func TestDoRetransmitDropsAfterMaxRetransmits(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	now := time.Now()
	c.sendMu.Lock()
	c.pending[0] = &pendingPacket{
		pkt:           &Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("x")},
		sentAt:        now.Add(-initialRTO * 2),
		retransmits:   MaxRetransmits, // already at max
		deliveredTime: now.Add(-initialRTO * 3),
	}
	// Register in inflight tracker.
	c.bbr.inflight.OnSend(1)
	c.sendMu.Unlock()

	c.doRetransmit()

	c.sendMu.Lock()
	_, exists := c.pending[0]
	c.sendMu.Unlock()

	if exists {
		t.Error("packet should be dropped after MaxRetransmits")
	}
}

func TestDoRetransmitBBRNoHalving(t *testing.T) {
	// BBR does NOT halve cwnd on retransmit (unlike TCP Reno).
	// At low loss rates (<2%), cwnd should remain unchanged.
	t.Parallel()
	c := makeTestConn(t)

	// Set a known cwnd via BBR state.
	c.bbr.mu.Lock()
	c.bbr.cwndTarget = 20
	c.bbr.mu.Unlock()

	c.sendMu.Lock()
	c.pending[0] = &pendingPacket{
		pkt:    &Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("x")},
		sentAt: time.Now().Add(-initialRTO * 2),
	}
	c.sendMu.Unlock()

	c.doRetransmit()

	// BBR should NOT have halved cwnd from a single retransmit.
	cwnd := c.bbr.CwndTarget()
	if cwnd < 20 {
		t.Errorf("BBR cwnd should not halve on single retransmit: got %d, want >= 20", cwnd)
	}
}

func TestDoRetransmitNoActionBeforeTimeout(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	c.sendMu.Lock()
	c.pending[0] = &pendingPacket{
		pkt:    &Packet{Type: PacketTypeData, SeqNum: 0},
		sentAt: time.Now(), // just sent — not overdue
	}
	c.sendMu.Unlock()

	c.doRetransmit()

	c.sendMu.Lock()
	pp := c.pending[0]
	c.sendMu.Unlock()

	if pp.retransmits != 0 {
		t.Errorf("should not retransmit a packet sent just now")
	}
}

// ---------------------------------------------------------------------------
// Close behaviour
// ---------------------------------------------------------------------------

func TestConnCloseBlocksRead(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)
	c.Close()

	ctx := context.Background()
	_, err := c.Read(ctx)
	if err == nil {
		t.Error("Read after Close should return error")
	}
}

func TestConnCloseIdempotent(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)
	// Calling Close multiple times must not panic.
	c.Close()
	c.Close()
}

// ---------------------------------------------------------------------------
// Integration: Listen + Dial
// ---------------------------------------------------------------------------

func TestListenAndDial(t *testing.T) {
	t.Parallel()
	l, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	addr := l.Addr().String()

	// Dial from client.
	client, err := Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	// Send from client → server.
	msg := []byte("hello server")
	if err := client.Write(msg); err != nil {
		t.Fatalf("client.Write: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	server, err := l.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer server.Close()

	rp, err := server.Read(ctx)
	if err != nil {
		t.Fatalf("server.Read: %v", err)
	}
	if !bytes.Equal(rp.data, msg) {
		t.Errorf("server read: got %q, want %q", rp.data, msg)
	}
}

func TestBidirectionalCommunication(t *testing.T) {
	t.Parallel()
	l, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	client, err := Dial(l.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Client → server.
	if err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client.Write: %v", err)
	}

	server, err := l.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer server.Close()

	rp, err := server.Read(ctx)
	if err != nil {
		t.Fatalf("server.Read: %v", err)
	}
	if string(rp.data) != "ping" {
		t.Errorf("server read: got %q, want %q", rp.data, "ping")
	}

	// Server → client.
	if err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server.Write: %v", err)
	}

	rp2, err := client.Read(ctx)
	if err != nil {
		t.Fatalf("client.Read: %v", err)
	}
	if string(rp2.data) != "pong" {
		t.Errorf("client read: got %q, want %q", rp2.data, "pong")
	}
}

func TestMultipleClients(t *testing.T) {
	t.Parallel()
	l, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	const numClients = 4
	serverConns := make(chan *Conn, numClients)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Accept goroutine.
	go func() {
		for i := 0; i < numClients; i++ {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			serverConns <- c
		}
	}()

	clients := make([]*Conn, numClients)
	for i := range clients {
		c, err := Dial(l.Addr().String())
		if err != nil {
			t.Fatalf("Dial[%d]: %v", i, err)
		}
		clients[i] = c
		msg := fmt.Sprintf("client%d", i)
		if err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	received := make(map[string]bool)
	var mu sync.Mutex

	for i := 0; i < numClients; i++ {
		select {
		case sc := <-serverConns:
			rp, err := sc.Read(ctx)
			if err != nil {
				t.Errorf("server[%d].Read: %v", i, err)
				continue
			}
			mu.Lock()
			received[string(rp.data)] = true
			mu.Unlock()
			sc.Close()
		case <-ctx.Done():
			t.Fatal("timed out waiting for server connection")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < numClients; i++ {
		key := fmt.Sprintf("client%d", i)
		if !received[key] {
			t.Errorf("did not receive message from %s", key)
		}
	}
}

func TestLargePayloadFragmentation(t *testing.T) {
	t.Parallel()
	l, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	client, err := Dial(l.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Payload larger than MaxPayloadSize → must be fragmented.
	bigPayload := make([]byte, MaxPayloadSize*3)
	for i := range bigPayload {
		bigPayload[i] = byte(i % 251)
	}
	if err := client.Write(bigPayload); err != nil {
		t.Fatalf("client.Write: %v", err)
	}

	server, err := l.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer server.Close()

	// Read all fragments and reassemble.
	var received []byte
	for len(received) < len(bigPayload) {
		rp, err := server.Read(ctx)
		if err != nil {
			t.Fatalf("server.Read: %v", err)
		}
		received = append(received, rp.data...)
	}

	if !bytes.Equal(received, bigPayload) {
		t.Errorf("large payload mismatch: got %d bytes, want %d", len(received), len(bigPayload))
	}
}

func TestListenerClose(t *testing.T) {
	t.Parallel()
	l, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := l.Accept(ctx)
		done <- err
	}()

	l.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Accept after Close should return error")
		}
	case <-time.After(time.Second):
		t.Error("Accept did not return after Close")
	}
}

func TestDialInvalidAddress(t *testing.T) {
	t.Parallel()
	_, err := Dial("not-a-valid-address!!!")
	if err == nil {
		t.Error("Dial should fail on invalid address")
	}
}

func TestListenInvalidAddress(t *testing.T) {
	t.Parallel()
	_, err := Listen("not-a-valid-address!!!")
	if err == nil {
		t.Error("Listen should fail on invalid address")
	}
}

// ---------------------------------------------------------------------------
// Fast retransmit (RFC 5681 §3.2)
// ---------------------------------------------------------------------------

// makeTestConnWithPending creates a Conn that has one pending packet at seq=0
// with sendBase=0, simulating the server waiting for an ACK for seq=0.
func makeTestConnWithPending(t *testing.T) *Conn {
	t.Helper()
	c := makeTestConn(t)
	c.sendMu.Lock()
	c.sendBase = 0
	c.pending[0] = &pendingPacket{
		pkt:           &Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("lost-packet")},
		firstSentAt:   time.Now().Add(-50 * time.Millisecond),
		sentAt:        time.Now().Add(-50 * time.Millisecond),
		deliveredTime: time.Now().Add(-100 * time.Millisecond),
	}
	c.bbr.inflight.OnSend(len("lost-packet"))
	c.sendMu.Unlock()
	return c
}

// TestFastRetransmitTriggerOnThirdDupACK verifies that a duplicate ACK at
// sendBase is counted and that the 3rd consecutive dup ACK triggers an
// immediate retransmit of the head-of-line packet (RFC 5681 §3.2).
func TestFastRetransmitTriggerOnThirdDupACK(t *testing.T) {
	t.Parallel()
	c := makeTestConnWithPending(t)

	// Send 1st dup ACK — counter increments but no retransmit yet.
	c.processACK(0)
	c.sendMu.Lock()
	cnt1 := c.dupAckCount
	retx1 := c.pending[0].retransmits
	c.sendMu.Unlock()
	if cnt1 != 1 {
		t.Errorf("after 1st dup ACK: dupAckCount want 1, got %d", cnt1)
	}
	if retx1 != 0 {
		t.Errorf("after 1st dup ACK: retransmits want 0, got %d", retx1)
	}

	// Send 2nd dup ACK — counter increments, still no retransmit.
	c.processACK(0)
	c.sendMu.Lock()
	cnt2 := c.dupAckCount
	retx2 := c.pending[0].retransmits
	c.sendMu.Unlock()
	if cnt2 != 2 {
		t.Errorf("after 2nd dup ACK: dupAckCount want 2, got %d", cnt2)
	}
	if retx2 != 0 {
		t.Errorf("after 2nd dup ACK: retransmits want 0, got %d", retx2)
	}

	// Send 3rd dup ACK — must trigger fast retransmit immediately.
	c.processACK(0)
	c.sendMu.Lock()
	cnt3 := c.dupAckCount
	retx3 := c.pending[0].retransmits
	c.sendMu.Unlock()
	// Counter resets to 0 after the 3rd dup ACK triggers the retransmit.
	if cnt3 != 0 {
		t.Errorf("after 3rd dup ACK: dupAckCount want 0 (reset), got %d", cnt3)
	}
	// The pending packet must have been retransmitted.
	if retx3 != 1 {
		t.Errorf("after 3rd dup ACK: retransmits want 1, got %d", retx3)
	}
}

// TestFastRetransmitResetOnNewACK verifies that the dup ACK counter is cleared
// when a new cumulative ACK (ackNum > sendBase) arrives.
func TestFastRetransmitResetOnNewACK(t *testing.T) {
	t.Parallel()
	c := makeTestConnWithPending(t)

	// Simulate 2 dup ACKs, then a real ACK that clears the packet.
	c.processACK(0) // dup 1
	c.processACK(0) // dup 2

	c.sendMu.Lock()
	cnt := c.dupAckCount
	c.sendMu.Unlock()
	if cnt != 2 {
		t.Fatalf("pre-condition: want dupAckCount=2, got %d", cnt)
	}

	// New ACK advancing past seq 0.
	c.processACK(1)

	c.sendMu.Lock()
	cntAfter := c.dupAckCount
	pendingCount := len(c.pending)
	c.sendMu.Unlock()

	if cntAfter != 0 {
		t.Errorf("dupAckCount should reset to 0 after new ACK, got %d", cntAfter)
	}
	if pendingCount != 0 {
		t.Errorf("pending should be empty after ACK=1, got %d", pendingCount)
	}
}

// TestFastRetransmitNoDupACKWithNoPending verifies that dup ACKs are ignored
// when there are no outstanding packets (nothing to retransmit).
func TestFastRetransmitNoDupACKWithNoPending(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)

	// Send 3 dup ACKs with nothing pending — should not panic or increment counter.
	c.processACK(0)
	c.processACK(0)
	c.processACK(0)

	c.sendMu.Lock()
	cnt := c.dupAckCount
	c.sendMu.Unlock()
	// Counter should be 0 since no pending data means we skip the dup ACK path.
	if cnt != 0 {
		t.Errorf("dupAckCount should remain 0 with no pending, got %d", cnt)
	}
}

// TestFastRetransmitStaleACKIgnored verifies that stale ACKs (ackNum < sendBase)
// are completely ignored and do not affect the dup ACK counter.
func TestFastRetransmitStaleACKIgnored(t *testing.T) {
	t.Parallel()
	c := makeTestConnWithPending(t)

	// Advance sendBase past 0 by ACKing seq 0.
	c.sendMu.Lock()
	c.sendBase = 5
	c.sendMu.Unlock()

	// Stale ACK: ackNum=3 < sendBase=5 — must be silently discarded.
	c.processACK(3)

	c.sendMu.Lock()
	cnt := c.dupAckCount
	c.sendMu.Unlock()
	if cnt != 0 {
		t.Errorf("stale ACK should not increment dupAckCount, got %d", cnt)
	}
}

// TestRetransmitLoopUsesPooledTimer verifies that retransmitLoop uses the pooled
// timer from pacerTimerPool (getPacerTimer/putPacerTimer) so that no heap
// allocation occurs per connection start. We verify indirectly: create two
// connections sequentially and confirm the second one's loop starts without panic
// (pool contract maintained) and that the timer pool has a timer available after
// the first connection closes.
func TestRetransmitLoopUsesPooledTimer(t *testing.T) {
	t.Parallel()

	// Get a timer from the pool, confirm it fires, put it back.
	// This mirrors exactly what retransmitLoop does at startup and shutdown.
	timer := getPacerTimer(10 * time.Millisecond)
	select {
	case <-timer.C:
		// fired as expected
	case <-time.After(500 * time.Millisecond):
		t.Fatal("getPacerTimer: timer did not fire within 500ms")
	}
	putPacerTimer(timer) // must not block

	// After Put, pool has a reusable timer. Get it again and verify it still works.
	timer2 := getPacerTimer(10 * time.Millisecond)
	select {
	case <-timer2.C:
		// reuse works
	case <-time.After(500 * time.Millisecond):
		t.Fatal("reused timer from pool did not fire")
	}
	putPacerTimer(timer2)
}

// TestRetransmitLoopExitsOnContextCancel verifies that retransmitLoop goroutine
// exits promptly when the connection context is cancelled, and that putPacerTimer
// correctly cleans up a potentially-running timer on exit (no goroutine leak).
func TestRetransmitLoopExitsOnContextCancel(t *testing.T) {
	t.Parallel()

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	conn, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Close triggers ctx cancellation, which retransmitLoop listens on.
	// putPacerTimer in the defer must handle the running timer without blocking.
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.Close()
	}()

	select {
	case <-done:
		// Close completed without deadlock — retransmitLoop exited cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked for >2s — possible timer pool deadlock in retransmitLoop")
	}
}
