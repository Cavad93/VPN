package main

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavad93/vpn/server/crypto"
)

// ---------------------------------------------------------------------------
// Key loading tests
// ---------------------------------------------------------------------------

func TestLoadKeyPairFromHex_Valid(t *testing.T) {
	// Generate a real key pair to get a valid private key
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privHex := hex.EncodeToString(kp.PrivateKey[:])

	loaded, err := loadKeyPairFromHex(privHex)
	if err != nil {
		t.Fatalf("loadKeyPairFromHex: %v", err)
	}
	if loaded == nil {
		t.Fatal("loadKeyPairFromHex returned nil")
	}
	// Public keys should match
	if loaded.PublicKey != kp.PublicKey {
		t.Error("loaded public key does not match original")
	}
}

func TestLoadKeyPairFromHex_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "empty string",
			input:   "",
			wantErr: "expected 32 bytes",
		},
		{
			name:    "too short",
			input:   "abcd",
			wantErr: "expected 32 bytes",
		},
		{
			name:    "non-hex characters",
			input:   strings.Repeat("zz", 32),
			wantErr: "invalid hex",
		},
		{
			name:    "odd length hex",
			input:   "abc",
			wantErr: "invalid hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadKeyPairFromHex(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadKeyPairFromHex_WithWhitespace(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privHex := hex.EncodeToString(kp.PrivateKey[:])

	// With leading/trailing whitespace
	_, err = loadKeyPairFromHex("  " + privHex + "\n")
	if err != nil {
		t.Errorf("loadKeyPairFromHex with whitespace: %v", err)
	}
}

// ---------------------------------------------------------------------------
// VPNClient construction tests
// ---------------------------------------------------------------------------

func TestNewVPNClient(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKeyHex = strings.Repeat("ab", 32)

	vc := NewVPNClient(&cfg)
	if vc == nil {
		t.Fatal("NewVPNClient returned nil")
	}
}

func TestVPNClientIsConnected_Initial(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKeyHex = strings.Repeat("ab", 32)

	vc := NewVPNClient(&cfg)
	if vc.IsConnected() {
		t.Error("new client should not be connected")
	}
}

func TestVPNClientDisconnect_WhenNotConnected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKeyHex = strings.Repeat("ab", 32)

	vc := NewVPNClient(&cfg)
	// Should not panic
	vc.Disconnect()
	if vc.IsConnected() {
		t.Error("should not be connected after Disconnect")
	}
}

func TestVPNClientDisconnect_WhenConnected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKeyHex = strings.Repeat("ab", 32)

	vc := NewVPNClient(&cfg)

	// Manually inject a raw conn to simulate connected state
	connA, connB := net.Pipe()
	defer connB.Close()

	vc.rawConn = connA

	// Disconnect should close rawConn and set it to nil
	vc.Disconnect()

	if vc.IsConnected() {
		t.Error("should not be connected after Disconnect")
	}
	if vc.rawConn != nil {
		t.Error("rawConn should be nil after Disconnect")
	}
}

func TestVPNClientOpenDataStream_WhenNotConnected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKeyHex = strings.Repeat("ab", 32)

	vc := NewVPNClient(&cfg)
	_, err := vc.OpenDataStream()
	if err == nil {
		t.Error("OpenDataStream should fail when not connected")
	}
}

func TestVPNClientConnect_InvalidKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ServerAddr = "127.0.0.1:59999" // nothing listening
	cfg.PrivateKeyHex = "invalidhex"   // invalid

	vc := NewVPNClient(&cfg)
	_, err := vc.Connect(context.Background())
	if err == nil {
		t.Error("Connect should fail with invalid key")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("error should mention key, got: %v", err)
	}
}

func TestVPNClientConnect_NoServer(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.ServerAddr = "127.0.0.1:59998" // nothing listening
	cfg.PrivateKeyHex = hex.EncodeToString(kp.PrivateKey[:])

	vc := NewVPNClient(&cfg)
	ctx := context.Background()
	_, err = vc.Connect(ctx)
	if err == nil {
		t.Error("Connect should fail when no server is listening")
	}
	// Should mention dial or connect
	if !strings.Contains(err.Error(), "dial") && !strings.Contains(err.Error(), "connect") {
		t.Errorf("error should mention dial/connect, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Buffer pool tests
// ---------------------------------------------------------------------------

func TestVPNClientBufferPool(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKeyHex = strings.Repeat("ab", 32)

	vc := NewVPNClient(&cfg)

	buf := vc.GetReadBuffer()
	if buf == nil {
		t.Fatal("GetReadBuffer returned nil")
	}
	if len(*buf) != 65536 {
		t.Errorf("buffer size: got %d, want 65536", len(*buf))
	}

	// Return to pool and get again — should reuse
	vc.PutReadBuffer(buf)
	buf2 := vc.GetReadBuffer()
	if buf2 == nil {
		t.Fatal("GetReadBuffer returned nil on second call")
	}
	vc.PutReadBuffer(buf2)
}

func TestVPNClientWritePool_NewFunc(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PrivateKeyHex = strings.Repeat("ab", 32)

	vc := NewVPNClient(&cfg)

	// Access writePool to trigger the New function
	raw := vc.writePool.Get()
	if raw == nil {
		t.Fatal("writePool.Get returned nil")
	}
	bp, ok := raw.(*[]byte)
	if !ok {
		t.Fatal("writePool item is not *[]byte")
	}
	if cap(*bp) == 0 {
		t.Error("writePool buffer should have non-zero capacity")
	}
	vc.writePool.Put(bp)
}

// ---------------------------------------------------------------------------
// noiseConn tests
// ---------------------------------------------------------------------------

func TestNoiseConn_WriteRead(t *testing.T) {
	// Create two connected noise sessions via a real Noise_XX exchange
	kpA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kpB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Use an in-memory pipe to simulate the network
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	// Run Noise_XX handshake in parallel goroutines to avoid deadlock
	type handshakeResult struct {
		session *crypto.Session
		err     error
	}

	chA := make(chan handshakeResult, 1)
	chB := make(chan handshakeResult, 1)

	// Initiator goroutine
	go func() {
		hsA, err := crypto.NewHandshake(crypto.Initiator, kpA)
		if err != nil {
			chA <- handshakeResult{err: err}
			return
		}
		msg1, err := hsA.WriteMessage1()
		if err != nil {
			chA <- handshakeResult{err: err}
			return
		}
		if _, err := connA.Write(msg1); err != nil {
			chA <- handshakeResult{err: err}
			return
		}
		msg2 := make([]byte, 2048)
		n, err := connA.Read(msg2)
		if err != nil {
			chA <- handshakeResult{err: err}
			return
		}
		if err := hsA.ReadMessage2(msg2[:n]); err != nil {
			chA <- handshakeResult{err: err}
			return
		}
		msg3, session, err := hsA.WriteMessage3()
		if err != nil {
			chA <- handshakeResult{err: err}
			return
		}
		if _, err := connA.Write(msg3); err != nil {
			chA <- handshakeResult{err: err}
			return
		}
		chA <- handshakeResult{session: session}
	}()

	// Responder goroutine
	go func() {
		hsB, err := crypto.NewHandshake(crypto.Responder, kpB)
		if err != nil {
			chB <- handshakeResult{err: err}
			return
		}
		msg1 := make([]byte, 2048)
		n, err := connB.Read(msg1)
		if err != nil {
			chB <- handshakeResult{err: err}
			return
		}
		if err := hsB.ReadMessage1(msg1[:n]); err != nil {
			chB <- handshakeResult{err: err}
			return
		}
		msg2, err := hsB.WriteMessage2()
		if err != nil {
			chB <- handshakeResult{err: err}
			return
		}
		if _, err := connB.Write(msg2); err != nil {
			chB <- handshakeResult{err: err}
			return
		}
		msg3 := make([]byte, 2048)
		n, err = connB.Read(msg3)
		if err != nil {
			chB <- handshakeResult{err: err}
			return
		}
		session, err := hsB.ReadMessage3(msg3[:n])
		chB <- handshakeResult{session: session, err: err}
	}()

	resA := <-chA
	if resA.err != nil {
		t.Fatalf("initiator handshake: %v", resA.err)
	}
	resB := <-chB
	if resB.err != nil {
		t.Fatalf("responder handshake: %v", resB.err)
	}

	sessionA := resA.session
	sessionB := resB.session
	if sessionA == nil || sessionB == nil {
		t.Fatal("session not established")
	}

	// Wrap in noiseConn
	ncA := newNoiseConn(connA, sessionA, nil)
	ncB := newNoiseConn(connB, sessionB, nil)

	// A writes, B reads (in parallel to avoid deadlock on net.Pipe)
	writeMsg := []byte("hello from A")
	readResult := make(chan struct {
		data []byte
		err  error
	}, 1)

	go func() {
		buf := make([]byte, 1024)
		n, err := ncB.Read(buf)
		readResult <- struct {
			data []byte
			err  error
		}{data: buf[:n], err: err}
	}()

	if _, err := ncA.Write(writeMsg); err != nil {
		t.Fatalf("noiseConn write: %v", err)
	}

	result := <-readResult
	if result.err != nil {
		t.Fatalf("noiseConn read: %v", result.err)
	}
	if string(result.data) != string(writeMsg) {
		t.Errorf("noiseConn read: got %q, want %q", result.data, writeMsg)
	}
}

func TestNoiseConn_WriteRead_WithPool(t *testing.T) {
	kpA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kpB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	type handshakeResult struct {
		session *crypto.Session
		err     error
	}
	chA := make(chan handshakeResult, 1)
	chB := make(chan handshakeResult, 1)

	go func() {
		hsA, err := crypto.NewHandshake(crypto.Initiator, kpA)
		if err != nil {
			chA <- handshakeResult{err: err}
			return
		}
		msg1, _ := hsA.WriteMessage1()
		connA.Write(msg1)
		msg2 := make([]byte, 2048)
		n, _ := connA.Read(msg2)
		hsA.ReadMessage2(msg2[:n])
		msg3, session, err := hsA.WriteMessage3()
		connA.Write(msg3)
		chA <- handshakeResult{session: session, err: err}
	}()

	go func() {
		hsB, err := crypto.NewHandshake(crypto.Responder, kpB)
		if err != nil {
			chB <- handshakeResult{err: err}
			return
		}
		msg1 := make([]byte, 2048)
		n, _ := connB.Read(msg1)
		hsB.ReadMessage1(msg1[:n])
		msg2, _ := hsB.WriteMessage2()
		connB.Write(msg2)
		msg3 := make([]byte, 2048)
		n, _ = connB.Read(msg3)
		session, err := hsB.ReadMessage3(msg3[:n])
		chB <- handshakeResult{session: session, err: err}
	}()

	resA := <-chA
	resB := <-chB
	if resA.err != nil || resB.err != nil {
		t.Fatalf("handshake: %v %v", resA.err, resB.err)
	}

	// Use write pool for ncA
	pool := &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 2+1460+16)
			return &buf
		},
	}

	ncA := newNoiseConn(connA, resA.session, pool)
	ncB := newNoiseConn(connB, resB.session, nil)

	writeMsg := []byte("pool-optimized write")
	readResult := make(chan struct {
		data []byte
		err  error
	}, 1)

	go func() {
		buf := make([]byte, 1024)
		n, err := ncB.Read(buf)
		readResult <- struct {
			data []byte
			err  error
		}{data: buf[:n], err: err}
	}()

	if _, err := ncA.Write(writeMsg); err != nil {
		t.Fatalf("noiseConn write with pool: %v", err)
	}

	result := <-readResult
	if result.err != nil {
		t.Fatalf("noiseConn read: %v", result.err)
	}
	if string(result.data) != string(writeMsg) {
		t.Errorf("got %q, want %q", result.data, writeMsg)
	}
}

func TestNoiseConn_ReadFromBuffer(t *testing.T) {
	// Test the readBuf path in noiseConn.Read
	kpA, _ := crypto.GenerateKeyPair()
	kpB, _ := crypto.GenerateKeyPair()
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	type hs struct {
		session *crypto.Session
		err     error
	}
	chA := make(chan hs, 1)
	chB := make(chan hs, 1)

	go func() {
		hsA, _ := crypto.NewHandshake(crypto.Initiator, kpA)
		msg1, _ := hsA.WriteMessage1()
		connA.Write(msg1)
		msg2 := make([]byte, 2048)
		n, _ := connA.Read(msg2)
		hsA.ReadMessage2(msg2[:n])
		msg3, session, err := hsA.WriteMessage3()
		connA.Write(msg3)
		chA <- hs{session, err}
	}()
	go func() {
		hsB, _ := crypto.NewHandshake(crypto.Responder, kpB)
		msg1 := make([]byte, 2048)
		n, _ := connB.Read(msg1)
		hsB.ReadMessage1(msg1[:n])
		msg2, _ := hsB.WriteMessage2()
		connB.Write(msg2)
		msg3 := make([]byte, 2048)
		n, _ = connB.Read(msg3)
		session, err := hsB.ReadMessage3(msg3[:n])
		chB <- hs{session, err}
	}()

	resA, resB := <-chA, <-chB
	if resA.err != nil || resB.err != nil {
		t.Fatal("handshake failed")
	}

	ncA := newNoiseConn(connA, resA.session, nil)
	ncB := newNoiseConn(connB, resB.session, nil)

	// Write a large message, then read it in small chunks to exercise readBuf
	bigMsg := make([]byte, 200)
	for i := range bigMsg {
		bigMsg[i] = byte(i)
	}

	readDone := make(chan []byte, 1)
	go func() {
		var all []byte
		smallBuf := make([]byte, 50) // smaller than message
		for len(all) < len(bigMsg) {
			n, err := ncB.Read(smallBuf)
			if err != nil {
				return
			}
			all = append(all, smallBuf[:n]...)
		}
		readDone <- all
	}()

	if _, err := ncA.Write(bigMsg); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-readDone:
		if string(got) != string(bigMsg) {
			t.Errorf("partial reads: content mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout reading in chunks")
	}
}

func TestNoiseConn_Close(t *testing.T) {
	connA, connB := net.Pipe()
	defer connB.Close()

	nc := newNoiseConn(connA, &crypto.Session{}, nil)
	if err := nc.Close(); err != nil {
		t.Errorf("noiseConn Close: %v", err)
	}
}

func TestNoiseConn_NetConnInterface(t *testing.T) {
	// Verify noiseConn satisfies net.Conn interface
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	kp, _ := crypto.GenerateKeyPair()
	hs, _ := crypto.NewHandshake(crypto.Initiator, kp)
	_ = hs

	// Just test that noiseConn can be assigned to net.Conn
	// We construct with a dummy session-like via direct struct
	nc := newNoiseConn(connA, &crypto.Session{}, nil)
	var _ net.Conn = nc

	// Test deadline methods don't panic
	_ = nc.SetDeadline(time.Time{})
	_ = nc.SetReadDeadline(time.Time{})
	_ = nc.SetWriteDeadline(time.Time{})
	_ = nc.LocalAddr()
	_ = nc.RemoteAddr()
}

// ---------------------------------------------------------------------------
// Handshake framing tests
// ---------------------------------------------------------------------------

func TestHandshakeFraming(t *testing.T) {
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	msg := []byte("test handshake message")
	type result struct {
		data []byte
		err  error
	}
	errc := make(chan result, 1)
	go func() {
		received, err := readHandshakeMsg(conn2)
		errc <- result{data: received, err: err}
	}()

	if err := writeHandshakeMsg(conn1, msg); err != nil {
		t.Fatalf("writeHandshakeMsg: %v", err)
	}

	r := <-errc
	if r.err != nil {
		t.Fatalf("readHandshakeMsg: %v", r.err)
	}
	if string(r.data) != string(msg) {
		t.Errorf("got %q, want %q", r.data, msg)
	}
}

func TestHandshakeFraming_Empty(t *testing.T) {
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	errc := make(chan error, 1)
	go func() {
		// Write empty message (length=0) — should be rejected by reader
		_, _ = conn1.Write([]byte{0, 0})
	}()
	go func() {
		_, err := readHandshakeMsg(conn2)
		errc <- err
	}()

	err := <-errc
	if err == nil {
		t.Error("expected error for zero-length message")
	}
}

func TestHandshakeFraming_Multiple(t *testing.T) {
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	messages := [][]byte{
		[]byte("first"),
		[]byte("second message"),
		make([]byte, 100),
	}
	// Fill last message with distinct bytes
	for i := range messages[2] {
		messages[2][i] = byte(i)
	}

	type result struct {
		err    error
		failed bool
	}
	errc := make(chan result, 1)
	go func() {
		for _, expected := range messages {
			got, err := readHandshakeMsg(conn2)
			if err != nil {
				errc <- result{err: err}
				return
			}
			if string(got) != string(expected) {
				errc <- result{failed: true}
				return
			}
		}
		errc <- result{}
	}()

	writeDone := make(chan error, 1)
	go func() {
		for _, m := range messages {
			if err := writeHandshakeMsg(conn1, m); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	if err := <-writeDone; err != nil {
		t.Fatalf("writeHandshakeMsg: %v", err)
	}

	r := <-errc
	if r.err != nil {
		t.Fatalf("readHandshakeMsg: %v", r.err)
	}
	if r.failed {
		t.Error("received message content mismatch")
	}
}

// ---------------------------------------------------------------------------
// AssignedRoute tests
// ---------------------------------------------------------------------------

func TestAssignedRoute(t *testing.T) {
	r := &AssignedRoute{
		AssignedIP: "10.8.0.2",
		PrefixLen:  24,
		Gateway:    "10.8.0.1",
		CIDR:       "10.8.0.2/24",
	}
	if r.AssignedIP == "" {
		t.Error("AssignedIP should not be empty")
	}
	if r.CIDR != "10.8.0.2/24" {
		t.Errorf("CIDR: got %s", r.CIDR)
	}
}
