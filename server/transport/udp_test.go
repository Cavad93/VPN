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
	_, err := DecodePacket([]byte{0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for too-short packet")
	}
}

func TestDecodePacketTruncatedPayload(t *testing.T) {
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
	c := makeTestConn(t)

	c.processData(&Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("a")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 1, Payload: []byte("b")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 2, Payload: []byte("c")})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for _, want := range []string{"a", "b", "c"} {
		data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if string(data) != want {
			t.Errorf("Read: got %q, want %q", data, want)
		}
	}
}

func TestProcessDataOutOfOrder(t *testing.T) {
	c := makeTestConn(t)

	// Deliver 0, then 2 (buffered), then 1 — after 1 arrives, 2 should also drain.
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("first")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 2, Payload: []byte("third")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 1, Payload: []byte("second")})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	expected := []string{"first", "second", "third"}
	for _, want := range expected {
		data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if string(data) != want {
			t.Errorf("Read: got %q, want %q", data, want)
		}
	}
}

func TestProcessDataDuplicate(t *testing.T) {
	c := makeTestConn(t)

	c.processData(&Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("x")})
	c.processData(&Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("x")}) // duplicate

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// First read should succeed.
	data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(data) != "x" {
		t.Errorf("Read: got %q, want %q", data, "x")
	}

	// Second read must time out (duplicate was discarded).
	_, err = c.Read(ctx)
	if err == nil {
		t.Error("expected timeout for duplicate packet, got data")
	}
}

func TestProcessDataNoPayload(t *testing.T) {
	c := makeTestConn(t)

	// A SYN-like packet with no payload should not be delivered to readCh.
	c.processData(&Packet{Type: PacketTypeSYN, SeqNum: 0})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Read(ctx)
	if err == nil {
		t.Error("expected timeout for empty-payload packet")
	}
}

// ---------------------------------------------------------------------------
// processACK — congestion window
// ---------------------------------------------------------------------------

func TestProcessACKClearsWindow(t *testing.T) {
	c := makeTestConn(t)

	// Manually populate pending packets.
	c.sendMu.Lock()
	for i := uint32(0); i < 5; i++ {
		c.pending[i] = &pendingPacket{
			pkt:    &Packet{SeqNum: i},
			sentAt: time.Now(),
		}
	}
	c.sendSeq = 5
	c.sendMu.Unlock()

	// ACK covers seq 0..2 (ackNum == 3 means "received up through seq 2").
	c.processACK(3)

	c.sendMu.Lock()
	pending := len(c.pending)
	cwnd := c.cwnd
	c.sendMu.Unlock()

	if pending != 2 {
		t.Errorf("pending: got %d, want 2 (seq 3 and 4 remain)", pending)
	}
	if cwnd <= 4 {
		t.Errorf("cwnd should have grown after ACKs, got %d", cwnd)
	}
}

func TestProcessACKCongestionAvoidance(t *testing.T) {
	c := makeTestConn(t)

	// Force into congestion-avoidance phase (cwnd >= ssthresh).
	c.sendMu.Lock()
	c.cwnd = 32
	c.ssthresh = 16
	for i := uint32(0); i < 10; i++ {
		c.pending[i] = &pendingPacket{pkt: &Packet{SeqNum: i}}
	}
	c.sendMu.Unlock()

	c.processACK(10)

	c.sendMu.Lock()
	cwnd := c.cwnd
	c.sendMu.Unlock()

	if cwnd < 32 {
		t.Errorf("cwnd should not shrink in congestion avoidance, got %d", cwnd)
	}
}

// ---------------------------------------------------------------------------
// doRetransmit
// ---------------------------------------------------------------------------

func TestDoRetransmitIncreasesCounter(t *testing.T) {
	c := makeTestConn(t)

	pkt := &Packet{Type: PacketTypeData, SeqNum: 0, Payload: []byte("retry")}
	c.sendMu.Lock()
	c.pending[0] = &pendingPacket{
		pkt:    pkt,
		sentAt: time.Now().Add(-RetransmitTimeout * 2), // far in the past
	}
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
	c := makeTestConn(t)

	c.sendMu.Lock()
	c.pending[0] = &pendingPacket{
		pkt:         &Packet{Type: PacketTypeData, SeqNum: 0},
		sentAt:      time.Now().Add(-RetransmitTimeout * 2),
		retransmits: MaxRetransmits, // already at max
	}
	c.sendMu.Unlock()

	c.doRetransmit()

	c.sendMu.Lock()
	_, exists := c.pending[0]
	c.sendMu.Unlock()

	if exists {
		t.Error("packet should be dropped after MaxRetransmits")
	}
}

func TestDoRetransmitCongestionDecrease(t *testing.T) {
	c := makeTestConn(t)
	c.sendMu.Lock()
	c.cwnd = 20
	c.ssthresh = 32
	c.pending[0] = &pendingPacket{
		pkt:    &Packet{Type: PacketTypeData, SeqNum: 0},
		sentAt: time.Now().Add(-RetransmitTimeout * 2),
	}
	c.sendMu.Unlock()

	c.doRetransmit()

	c.sendMu.Lock()
	cwnd := c.cwnd
	ssthresh := c.ssthresh
	c.sendMu.Unlock()

	if ssthresh != 10 {
		t.Errorf("ssthresh: got %d, want 10 (20/2)", ssthresh)
	}
	if cwnd != 10 {
		t.Errorf("cwnd: got %d, want 10 (= ssthresh)", cwnd)
	}
}

func TestDoRetransmitNoActionBeforeTimeout(t *testing.T) {
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
	c := makeTestConn(t)
	c.Close()

	ctx := context.Background()
	_, err := c.Read(ctx)
	if err == nil {
		t.Error("Read after Close should return error")
	}
}

func TestConnCloseIdempotent(t *testing.T) {
	c := makeTestConn(t)
	// Calling Close multiple times must not panic.
	c.Close()
	c.Close()
}

// ---------------------------------------------------------------------------
// Integration: Listen + Dial
// ---------------------------------------------------------------------------

func TestListenAndDial(t *testing.T) {
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

	data, err := server.Read(ctx)
	if err != nil {
		t.Fatalf("server.Read: %v", err)
	}
	if !bytes.Equal(data, msg) {
		t.Errorf("server read: got %q, want %q", data, msg)
	}
}

func TestBidirectionalCommunication(t *testing.T) {
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

	data, err := server.Read(ctx)
	if err != nil {
		t.Fatalf("server.Read: %v", err)
	}
	if string(data) != "ping" {
		t.Errorf("server read: got %q, want %q", data, "ping")
	}

	// Server → client.
	if err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server.Write: %v", err)
	}

	data, err = client.Read(ctx)
	if err != nil {
		t.Fatalf("client.Read: %v", err)
	}
	if string(data) != "pong" {
		t.Errorf("client read: got %q, want %q", data, "pong")
	}
}

func TestMultipleClients(t *testing.T) {
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
			data, err := sc.Read(ctx)
			if err != nil {
				t.Errorf("server[%d].Read: %v", i, err)
				continue
			}
			mu.Lock()
			received[string(data)] = true
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
		chunk, err := server.Read(ctx)
		if err != nil {
			t.Fatalf("server.Read: %v", err)
		}
		received = append(received, chunk...)
	}

	if !bytes.Equal(received, bigPayload) {
		t.Errorf("large payload mismatch: got %d bytes, want %d", len(received), len(bigPayload))
	}
}

func TestListenerClose(t *testing.T) {
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
	_, err := Dial("not-a-valid-address!!!")
	if err == nil {
		t.Error("Dial should fail on invalid address")
	}
}

func TestListenInvalidAddress(t *testing.T) {
	_, err := Listen("not-a-valid-address!!!")
	if err == nil {
		t.Error("Listen should fail on invalid address")
	}
}
