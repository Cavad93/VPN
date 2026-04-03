package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cavad93/vpn/server/crypto"
	"github.com/cavad93/vpn/server/transport"
)

// mockVPNServer simulates a VPN server for integration testing.
// It performs the full protocol: ObfsConn + Noise_XX + Mux + control stream.
type mockVPNServer struct {
	listener net.Listener
	kp       *crypto.KeyPair
	addr     string
}

func newMockVPNServer(t *testing.T) *mockVPNServer {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &mockVPNServer{
		listener: ln,
		kp:       kp,
		addr:     ln.Addr().String(),
	}
}

func (s *mockVPNServer) close() {
	s.listener.Close()
}

// serve handles one connection then returns.
func (s *mockVPNServer) serve(t *testing.T) {
	t.Helper()
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// TLS obfuscation: server handshake
	obfs := transport.NewObfsConn(conn)
	if err := obfs.ServerHandshake(); err != nil {
		t.Logf("server: obfs handshake: %v", err)
		return
	}

	// Noise_XX responder handshake
	hs, err := crypto.NewHandshake(crypto.Responder, s.kp)
	if err != nil {
		t.Logf("server: noise init: %v", err)
		return
	}

	msg1, err := readHandshakeMsg(obfs)
	if err != nil {
		t.Logf("server: read msg1: %v", err)
		return
	}
	if err := hs.ReadMessage1(msg1); err != nil {
		t.Logf("server: process msg1: %v", err)
		return
	}
	msg2, err := hs.WriteMessage2()
	if err != nil {
		t.Logf("server: msg2: %v", err)
		return
	}
	if err := writeHandshakeMsg(obfs, msg2); err != nil {
		t.Logf("server: send msg2: %v", err)
		return
	}
	msg3, err := readHandshakeMsg(obfs)
	if err != nil {
		t.Logf("server: read msg3: %v", err)
		return
	}
	session, err := hs.ReadMessage3(msg3)
	if err != nil {
		t.Logf("server: process msg3: %v", err)
		return
	}

	// Wrap in noiseConn
	nc := newNoiseConn(obfs, session, nil)
	mux := transport.NewMux(nc, false) // server uses odd stream IDs
	defer mux.Close()

	// Accept control stream
	ctlStream, err := mux.AcceptStream(context.Background())
	if err != nil {
		t.Logf("server: accept ctl stream: %v", err)
		return
	}
	defer ctlStream.Close()

	// Read ctlHello
	hello := make([]byte, 1)
	if _, err := io.ReadFull(ctlStream, hello); err != nil {
		t.Logf("server: read hello: %v", err)
		return
	}
	if hello[0] != ctlHello {
		t.Logf("server: unexpected hello byte 0x%02x", hello[0])
		return
	}

	// Send ctlAssign: [0x02][10.8.0.2][/24][10.8.0.1]
	resp := make([]byte, 1+ctlAssignPayload)
	resp[0] = ctlAssign
	copy(resp[1:5], []byte{10, 8, 0, 2})  // assigned IP: 10.8.0.2
	resp[5] = 24                            // prefix len
	copy(resp[6:10], []byte{10, 8, 0, 1}) // gateway: 10.8.0.1
	if _, err := ctlStream.Write(resp); err != nil {
		t.Logf("server: write assign: %v", err)
		return
	}

	// Keep serving for a bit so the client can close
	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// Integration test: full Connect flow
// ---------------------------------------------------------------------------

func TestVPNClientConnect_FullFlow(t *testing.T) {
	srv := newMockVPNServer(t)
	defer srv.close()

	// Start server in background
	go srv.serve(t)

	// Give server a moment to start
	time.Sleep(10 * time.Millisecond)

	// Generate client key pair
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		ServerAddr:    srv.addr,
		PrivateKeyHex: hexEncode(kp.PrivateKey[:]),
	}

	vc := NewVPNClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	route, err := vc.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if route.AssignedIP != "10.8.0.2" {
		t.Errorf("AssignedIP: got %s, want 10.8.0.2", route.AssignedIP)
	}
	if route.PrefixLen != 24 {
		t.Errorf("PrefixLen: got %d, want 24", route.PrefixLen)
	}
	if route.Gateway != "10.8.0.1" {
		t.Errorf("Gateway: got %s, want 10.8.0.1", route.Gateway)
	}
	if route.CIDR != "10.8.0.2/24" {
		t.Errorf("CIDR: got %s, want 10.8.0.2/24", route.CIDR)
	}

	if !vc.IsConnected() {
		t.Error("client should be connected")
	}

	// Test OpenDataStream
	stream, err := vc.OpenDataStream()
	if err != nil {
		t.Fatalf("OpenDataStream: %v", err)
	}
	stream.Close()

	vc.Disconnect()
	if vc.IsConnected() {
		t.Error("client should not be connected after Disconnect")
	}
}

func TestVPNClientConnect_WithServerKeyVerification(t *testing.T) {
	srv := newMockVPNServer(t)
	defer srv.close()

	go srv.serve(t)
	time.Sleep(10 * time.Millisecond)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Configure with correct server public key
	serverKeyHex := hexEncode(srv.kp.PublicKey[:])

	cfg := &Config{
		ServerAddr:    srv.addr,
		PrivateKeyHex: hexEncode(kp.PrivateKey[:]),
		ServerKeyHex:  serverKeyHex,
	}

	vc := NewVPNClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	route, err := vc.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect with server key verification: %v", err)
	}
	if route.AssignedIP != "10.8.0.2" {
		t.Errorf("AssignedIP: got %s, want 10.8.0.2", route.AssignedIP)
	}
	vc.Disconnect()
}

func TestVPNClientConnect_WrongServerKey(t *testing.T) {
	srv := newMockVPNServer(t)
	defer srv.close()

	go srv.serve(t)
	time.Sleep(10 * time.Millisecond)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Configure with WRONG server public key
	wrongKey, _ := crypto.GenerateKeyPair()
	wrongKeyHex := hexEncode(wrongKey.PublicKey[:])

	cfg := &Config{
		ServerAddr:    srv.addr,
		PrivateKeyHex: hexEncode(kp.PrivateKey[:]),
		ServerKeyHex:  wrongKeyHex,
	}

	vc := NewVPNClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = vc.Connect(ctx)
	if err == nil {
		t.Fatal("Connect should fail with wrong server key")
	}
}

func TestHandleConnect_Success(t *testing.T) {
	srv := newMockVPNServer(t)
	defer srv.close()

	go srv.serve(t)
	time.Sleep(10 * time.Millisecond)

	kp, _ := crypto.GenerateKeyPair()
	cfg := &Config{
		ServerAddr:    srv.addr,
		PrivateKeyHex: hexEncode(kp.PrivateKey[:]),
	}

	app := newAppState(cfg)
	tray := NewTrayApp(TrayCallbacks{})

	// Call handleConnect — should transition through Connecting → Connected
	app.handleConnect(context.Background(), tray)

	// Wait for connection to complete
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state := app.sm.State()
		if state == StateConnected || state == StateError {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if app.sm.State() != StateConnected {
		t.Errorf("expected StateConnected, got %v", app.sm.State())
	}
	if app.sm.LastEvent().AssignedIP != "10.8.0.2" {
		t.Errorf("AssignedIP: got %s", app.sm.LastEvent().AssignedIP)
	}
}

func TestHandleConnect_SuccessWithKillSwitch(t *testing.T) {
	srv := newMockVPNServer(t)
	defer srv.close()

	go srv.serve(t)
	time.Sleep(10 * time.Millisecond)

	kp, _ := crypto.GenerateKeyPair()
	cfg := &Config{
		ServerAddr:    srv.addr,
		PrivateKeyHex: hexEncode(kp.PrivateKey[:]),
	}

	app := newAppState(cfg)

	// Inject a mock kill switch that will be called on success
	mks := &mockKillSwitch{}
	app.ks = mks

	tray := NewTrayApp(TrayCallbacks{})
	app.handleConnect(context.Background(), tray)

	// Wait for connection to complete
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state := app.sm.State()
		if state == StateConnected || state == StateError {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if app.sm.State() != StateConnected {
		t.Errorf("expected StateConnected, got %v", app.sm.State())
	}
	if !mks.active {
		t.Error("kill switch should be active after successful connect")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hexEncode(b []byte) string {
	const hexChars = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hexChars[v>>4]
		dst[i*2+1] = hexChars[v&0xf]
	}
	return string(dst)
}

// Verify binary encoding matches what the server uses.
var _ = binary.BigEndian
