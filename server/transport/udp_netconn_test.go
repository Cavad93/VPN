package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPNetConnImplementsNetConn(t *testing.T) {
	// Compile-time check is in udp_netconn.go, but verify at runtime too.
	var _ net.Conn = (*UDPNetConn)(nil)
}

// setupUDPPair creates a client/server UDPNetConn pair over loopback.
// The client sends a trigger packet so the listener detects the connection.
func setupUDPPair(t *testing.T) (client, server *UDPNetConn) {
	t.Helper()

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	clientConn, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Send a trigger packet so the listener's readLoop sees this client.
	clientConn.Write([]byte("init"))

	serverConn, err := ln.Accept(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	// Drain the trigger packet on the server side.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	serverConn.Read(ctx)

	client = NewUDPNetConn(clientConn)
	server = NewUDPNetConn(serverConn)
	t.Cleanup(func() { client.Close(); server.Close() })
	return
}

func TestUDPNetConnWriteRead(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// Write from client, read on server.
	msg := []byte("hello over UDP net.Conn")
	n, err := client.Write(msg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("Write: wrote %d, want %d", n, len(msg))
	}

	buf := make([]byte, 256)
	n, err = server.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("Read: got %q, want %q", buf[:n], msg)
	}
}

func TestUDPNetConnReadBuffering(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// Send 10 bytes.
	msg := []byte("0123456789")
	client.Write(msg)

	// Read in 4-byte chunks — tests stream buffering.
	buf := make([]byte, 4)
	total := make([]byte, 0, 10)

	for len(total) < 10 {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v (after %d bytes)", err, len(total))
		}
		total = append(total, buf[:n]...)
	}

	if string(total) != string(msg) {
		t.Fatalf("Read buffering: got %q, want %q", total, msg)
	}
}

func TestUDPNetConnBidirectional(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// Client → Server.
	client.Write([]byte("ping"))
	buf := make([]byte, 64)
	n, _ := server.Read(buf)
	if string(buf[:n]) != "ping" {
		t.Fatalf("expected 'ping', got %q", buf[:n])
	}

	// Server → Client.
	server.Write([]byte("pong"))
	n, _ = client.Read(buf)
	if string(buf[:n]) != "pong" {
		t.Fatalf("expected 'pong', got %q", buf[:n])
	}
}

func TestUDPNetConnClose(t *testing.T) {
	t.Parallel()
	c := makeTestConn(t)
	u := NewUDPNetConn(c)
	err := u.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestUDPNetConnDeadlines(t *testing.T) {
	t.Parallel()

	c := makeTestConn(t)
	u := NewUDPNetConn(c)

	// Set deadlines — should not error.
	if err := u.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := u.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := u.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}

func TestUDPNetConnWriteDeadlineExceeded(t *testing.T) {
	t.Parallel()

	c := makeTestConn(t)
	u := NewUDPNetConn(c)

	// Set deadline in the past.
	u.SetWriteDeadline(time.Now().Add(-time.Second))

	_, err := u.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error for expired write deadline")
	}
}

func TestUDPNetConnAddresses(t *testing.T) {
	t.Parallel()
	client, _ := setupUDPPair(t)

	if client.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
	if client.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}
}

func TestUDPNetConnLargeWrite(t *testing.T) {
	t.Parallel()
	client, server := setupUDPPair(t)

	// Write data larger than MaxPayloadSize — should be fragmented by Conn.Write.
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	n, err := client.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Write: wrote %d, want %d", n, len(data))
	}

	// Read all of it back.
	received := make([]byte, 0, 5000)
	buf := make([]byte, 2048)
	for len(received) < 5000 {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v (after %d bytes)", err, len(received))
		}
		received = append(received, buf[:n]...)
	}

	if len(received) != len(data) {
		t.Fatalf("received %d bytes, want %d", len(received), len(data))
	}
	for i := range data {
		if received[i] != data[i] {
			t.Fatalf("data mismatch at byte %d: got %d, want %d", i, received[i], data[i])
		}
	}
}
