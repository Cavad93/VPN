package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestListenUDPAndDialUDP(t *testing.T) {
	t.Parallel()

	ln, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if ln.Addr() == nil {
		t.Fatal("Addr should not be nil")
	}

	// Client connects and sends data (triggers server-side Accept).
	client, err := DialUDP(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Verify client implements net.Conn.
	var _ net.Conn = client

	client.Write([]byte("hello"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// Verify server implements net.Conn.
	var _ net.Conn = server

	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q, want %q", buf[:n], "hello")
	}
}

func TestDialUDPBidirectional(t *testing.T) {
	t.Parallel()

	ln, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := DialUDP(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	client.Write([]byte("syn"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	server, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// Drain trigger.
	buf := make([]byte, 64)
	server.Read(buf)

	// Server → Client.
	server.Write([]byte("server-data"))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "server-data" {
		t.Fatalf("got %q, want %q", buf[:n], "server-data")
	}
}

func TestListenUDPWithObfsConn(t *testing.T) {
	// Verify ObfsConn handshake works over UDP transport.
	t.Parallel()

	ln, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := DialUDP(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Send trigger so server Accept works.
	client.Write([]byte("x"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverRaw, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Drain trigger on server.
	tmp := make([]byte, 16)
	serverRaw.Read(tmp)

	// Wrap both sides with ObfsConn.
	clientObfs := NewObfsConn(client)
	serverObfs := NewObfsConn(serverRaw)

	// Run handshake in parallel.
	errCh := make(chan error, 2)
	go func() { errCh <- clientObfs.ClientHandshake() }()
	go func() { errCh <- serverObfs.ServerHandshake() }()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("ObfsConn handshake over UDP failed: %v", err)
		}
	}

	// Send data through ObfsConn.
	msg := []byte("obfuscated over UDP with BBR")
	clientObfs.Write(msg)

	buf := make([]byte, 256)
	n, err := serverObfs.Read(buf)
	if err != nil {
		t.Fatalf("ObfsConn Read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("got %q, want %q", buf[:n], msg)
	}

	clientObfs.Close()
	serverObfs.Close()
}

func TestListenUDPWithMux(t *testing.T) {
	// Verify Mux works over UDP transport (full stack minus Noise).
	t.Parallel()

	ln, err := ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := DialUDP(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	client.Write([]byte("x"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverRaw, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tmp := make([]byte, 16)
	serverRaw.Read(tmp)

	// ObfsConn handshake.
	clientObfs := NewObfsConn(client)
	serverObfs := NewObfsConn(serverRaw)

	errCh := make(chan error, 2)
	go func() { errCh <- clientObfs.ClientHandshake() }()
	go func() { errCh <- serverObfs.ServerHandshake() }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}

	// Create Mux on both sides.
	clientMux := NewMux(clientObfs, true)  // client = even IDs
	serverMux := NewMux(serverObfs, false) // server = odd IDs

	// Client opens a stream.
	stream, err := clientMux.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	// Server accepts the stream.
	srvStream, err := serverMux.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	// Write/read through the mux stream.
	msg := []byte("mux-over-udp-bbr")
	stream.Write(msg)

	buf := make([]byte, 256)
	n, err := srvStream.Read(buf)
	if err != nil {
		t.Fatalf("Stream Read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("got %q, want %q", buf[:n], msg)
	}

	stream.Close()
	srvStream.Close()
	clientMux.Close()
	serverMux.Close()
}
