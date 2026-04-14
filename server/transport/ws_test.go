package transport

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

// testPipe creates a connected pair of net.Conn using net.Pipe.
func testPipe() (client, server net.Conn) {
	return net.Pipe()
}

func TestWSUpgrade_Success(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	errCh := make(chan error, 1)
	go func() {
		ws, err := WSUpgrade(server, "/tunnel")
		if err != nil {
			errCh <- err
			return
		}
		done <- ws
	}()

	// Send WebSocket upgrade request
	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET /tunnel HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	client.Write([]byte(req))

	// Read response
	buf := make([]byte, 4096)
	n, _ := client.Read(buf)
	resp := string(buf[:n])

	if !strings.Contains(resp, "101 Switching Protocols") {
		t.Fatalf("expected 101, got: %s", resp)
	}
	if !strings.Contains(resp, "Sec-WebSocket-Accept:") {
		t.Fatal("missing Sec-WebSocket-Accept header")
	}

	// Verify accept key
	h := sha1.New()
	h.Write([]byte(wsKey + wsGUID))
	expectedAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if !strings.Contains(resp, expectedAccept) {
		t.Errorf("wrong accept key, expected %s", expectedAccept)
	}

	select {
	case ws := <-done:
		if ws.Path() != "/tunnel" {
			t.Errorf("path = %q, want /tunnel", ws.Path())
		}
		// Close client first so ws.Close() doesn't block on net.Pipe
		client.Close()
		ws.Close()
	case err := <-errCh:
		t.Fatal(err)
	}
}

func TestWSUpgrade_WrongPath(t *testing.T) {
	client, server := testPipe()

	errCh := make(chan error, 1)
	go func() {
		_, err := WSUpgrade(server, "/tunnel")
		errCh <- err
		server.Close()
	}()

	req := "GET /wrong-path HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n"
	client.Write([]byte(req))

	// Drain the HTTP error response so writeHTTPError doesn't block on net.Pipe
	go io.Copy(io.Discard, client)

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for wrong path")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("unexpected error: %v", err)
	}
	client.Close()
}

func TestWSUpgrade_MissingUpgradeHeader(t *testing.T) {
	client, server := testPipe()

	errCh := make(chan error, 1)
	go func() {
		_, err := WSUpgrade(server, "")
		errCh <- err
		server.Close()
	}()

	req := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"
	client.Write([]byte(req))
	go io.Copy(io.Discard, client)

	err := <-errCh
	if err == nil {
		t.Fatal("expected error")
	}
	client.Close()
}

func TestWSBinaryMessageRoundTrip(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, err := WSUpgrade(server, "")
		if err != nil {
			t.Error(err)
			return
		}
		done <- ws
	}()

	// Client: send upgrade
	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"\r\n"
	client.Write([]byte(req))

	// Read upgrade response (discard)
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	// Run server reader concurrently (net.Pipe is synchronous)
	serverGot := make(chan string, 1)
	go func() {
		readBuf := make([]byte, 1024)
		n, err := ws.Read(readBuf)
		if err != nil {
			serverGot <- "ERROR: " + err.Error()
			return
		}
		serverGot <- string(readBuf[:n])
	}()

	// Client sends a masked binary frame
	sendMaskedFrame(t, client, wsOpBinary, []byte("hello from client"))

	got := <-serverGot
	if got != "hello from client" {
		t.Errorf("server got %q", got)
	}

	// Server sends unmasked binary frame (client must read concurrently)
	go func() { ws.Write([]byte("hello from server")) }()

	gotPayload := readUnmaskedFrame(t, client)
	if string(gotPayload) != "hello from server" {
		t.Errorf("client got %q", gotPayload)
	}

	client.Close()
	ws.Close()
}

func TestWSPingPong(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, _ := WSUpgrade(server, "")
		done <- ws
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	// Start server reader — it handles ping (responds with pong) then reads data
	readDone := make(chan string, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := ws.Read(buf)
		if err != nil {
			readDone <- "ERROR: " + err.Error()
			return
		}
		readDone <- string(buf[:n])
	}()

	// Send ping from client (server goroutine handles it and sends pong)
	sendMaskedFrame(t, client, wsOpPing, []byte("ping"))

	// Read the pong response
	pongPayload := readUnmaskedFrame(t, client)
	if string(pongPayload) != "ping" {
		t.Errorf("pong payload = %q, want %q", pongPayload, "ping")
	}

	// Send actual data — the server goroutine will return this
	sendMaskedFrame(t, client, wsOpBinary, []byte("data after ping"))

	got := <-readDone
	if got != "data after ping" {
		t.Errorf("got %q", got)
	}

	client.Close()
	ws.Close()
}

func TestWSClose(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, _ := WSUpgrade(server, "")
		done <- ws
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	// Server reads concurrently (ws.Read handles the close frame, sends close back)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		_, err := ws.Read(buf)
		readErr <- err
	}()

	// Client sends close frame
	sendMaskedFrame(t, client, wsOpClose, nil)

	// Drain close response from server so it doesn't block
	go io.Copy(io.Discard, client)

	err := <-readErr
	if err != io.EOF {
		t.Errorf("expected EOF, got: %v", err)
	}

	client.Close()
	ws.Close()
}

func TestWSLargePayload(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, _ := WSUpgrade(server, "")
		done <- ws
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	// Server reads concurrently (net.Pipe is synchronous)
	type result struct {
		n   int
		err error
		buf []byte
	}
	resCh := make(chan result, 1)
	go func() {
		readBuf := make([]byte, 80000)
		n, err := ws.Read(readBuf)
		resCh <- result{n, err, readBuf}
	}()

	// Send a 70000-byte payload (triggers 64-bit length encoding)
	payload := bytes.Repeat([]byte{0xAB}, 70000)
	sendMaskedFrame(t, client, wsOpBinary, payload)

	res := <-resCh
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.n != 70000 {
		t.Errorf("read %d bytes, want 70000", res.n)
	}
	if !bytes.Equal(res.buf[:res.n], payload) {
		t.Error("payload mismatch")
	}

	client.Close()
	ws.Close()
}

// TestWSBufferedRead verifies that a single WebSocket frame can be consumed
// via multiple Read calls (critical for VLESS header parsing with io.ReadFull).
func TestWSBufferedRead(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, err := WSUpgrade(server, "")
		if err != nil {
			t.Error(err)
			return
		}
		done <- ws
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	// Simulate VLESS: client sends a 30-byte header in one WS frame,
	// server reads it in multiple small io.ReadFull calls.
	payload := make([]byte, 30)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Start server reads concurrently (net.Pipe is synchronous)
	type readResult struct {
		data []byte
		err  error
	}
	resCh := make(chan readResult, 1)
	go func() {
		// Read 10 bytes, then 10 bytes, then 10 bytes — like io.ReadFull would
		var all []byte
		for i := 0; i < 3; i++ {
			buf := make([]byte, 10)
			n, err := io.ReadFull(ws, buf)
			if err != nil {
				resCh <- readResult{nil, err}
				return
			}
			all = append(all, buf[:n]...)
		}
		resCh <- readResult{all, nil}
	}()

	// Client sends one masked frame with all 30 bytes
	sendMaskedFrame(t, client, wsOpBinary, payload)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("read error: %v", res.err)
	}
	if !bytes.Equal(res.data, payload) {
		t.Errorf("got %v, want %v", res.data, payload)
	}

	client.Close()
	ws.Close()
}

// TestWSWriteFrameZeroAllocHotPath verifies that writing a VPN-sized binary
// frame (≤ wsWriteBufSize) does not allocate on the heap.  Allocations in the
// download direction (server→client) at ~2630 frames/sec caused ~3.75 MB/sec
// of GC pressure before the embedded-buffer fix.
func TestWSWriteFrameZeroAllocHotPath(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, err := WSUpgrade(server, "")
		if err != nil {
			t.Error(err)
			return
		}
		done <- ws
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	// Drain client reads so net.Pipe doesn't block writes.
	go io.Copy(io.Discard, client)

	// Payload sizes that should all take the zero-alloc hot path.
	// The condition is: hdrLen + length <= wsWriteBufSize.
	//   - length ≤ 125:          hdrLen = 2  → max payload = wsWriteBufSize-2 = 1470
	//   - 126 ≤ length ≤ 65535:  hdrLen = 4  → max payload = wsWriteBufSize-4 = 1468
	//
	// Max expected VPN payload: tunMTU(1430)+mux(7)+noise(18) = 1455 < 1468 → always hot path.
	sizes := []int{
		1,    // tiny
		125,  // max single-byte length field
		126,  // first extended-16 length
		1430, // tunMTU (typical VPN IP packet)
		1455, // max Noise+mux wrapped VPN frame  (worst-case in practice)
		1468, // max payload that fits hot path with 4-byte extended-16 header
	}
	for _, sz := range sizes {
		payload := bytes.Repeat([]byte{0xAB}, sz)
		allocs := testing.AllocsPerRun(5, func() {
			ws.Write(payload)
		})
		if allocs > 0 {
			t.Errorf("Write(%d bytes): got %.0f allocs, want 0", sz, allocs)
		}
	}

	client.Close()
	ws.Close()
}

// TestWSWriteFrameOversizedPayload verifies that a payload larger than
// wsWriteBufSize is sent correctly (slow-path heap alloc).
func TestWSWriteFrameOversizedPayload(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, err := WSUpgrade(server, "")
		if err != nil {
			t.Error(err)
			return
		}
		done <- ws
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	payload := bytes.Repeat([]byte{0xCD}, wsWriteBufSize+100)

	// Receive data on client side concurrently (net.Pipe is synchronous).
	gotCh := make(chan []byte, 1)
	go func() {
		gotCh <- readUnmaskedFrame(t, client)
	}()

	if _, err := ws.Write(payload); err != nil {
		t.Fatalf("Write oversized: %v", err)
	}

	got := <-gotCh
	if !bytes.Equal(got, payload) {
		t.Errorf("oversized write: payload mismatch (len got=%d want=%d)", len(got), len(payload))
	}

	client.Close()
	ws.Close()
}

// TestWSWriteFrameDataIntegrity verifies that the embedded writeBuf produces
// byte-for-byte identical output to the previous heap-alloc implementation.
func TestWSWriteFrameDataIntegrity(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, err := WSUpgrade(server, "")
		if err != nil {
			t.Error(err)
			return
		}
		done <- ws
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	// Write a 1430-byte frame (typical tunMTU packet).
	want := make([]byte, 1430)
	for i := range want {
		want[i] = byte(i & 0xFF)
	}

	gotCh := make(chan []byte, 1)
	go func() {
		gotCh <- readUnmaskedFrame(t, client)
	}()

	if _, err := ws.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := <-gotCh
	if !bytes.Equal(got, want) {
		t.Errorf("data integrity failure: first diff at byte %d", func() int {
			for i := range want {
				if i >= len(got) || got[i] != want[i] {
					return i
				}
			}
			return -1
		}())
	}

	client.Close()
	ws.Close()
}

// TestWSWriteFrameControlNotAffected verifies that control frames (ping/pong/close)
// remain correct after the writeBuf optimisation — they must NOT use writeBuf.
func TestWSWriteFrameControlNotAffected(t *testing.T) {
	client, server := testPipe()

	done := make(chan *WSConn, 1)
	go func() {
		ws, err := WSUpgrade(server, "")
		if err != nil {
			t.Error(err)
			return
		}
		done <- ws
	}()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)

	ws := <-done

	// Pattern for net.Pipe (synchronous): start the server-side reader goroutine
	// FIRST, then write from the client side.  The reader goroutine handles the
	// ping and auto-sends a pong; the client's pongCh goroutine reads the pong.

	// 1. Start server reader — processes ping and replies with pong.
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		_, err := ws.Read(buf) // blocks until ping arrives
		readDone <- err
	}()

	// 2. Start client receiver — waits for the pong that ws.Read will auto-send.
	pongCh := make(chan []byte, 1)
	go func() {
		pongCh <- readUnmaskedFrame(t, client)
	}()

	// 3. Client sends a ping; ws.Read() goroutine wakes up, processes it, sends pong.
	pingPayload := []byte("keepalive-check")
	sendMaskedFrame(t, client, wsOpPing, pingPayload)

	// 4. Verify pong echoes the ping payload.
	pong := <-pongCh
	if !bytes.Equal(pong, pingPayload) {
		t.Errorf("pong payload = %q, want %q", pong, pingPayload)
	}

	// 5. Close connections; ws.Read() goroutine will return with an error.
	client.Close()
	ws.Close()
	<-readDone // drain to avoid goroutine leak
}

// --- wsReadPool tests ---

// upgradeServerSide performs the server-side WS upgrade handshake and returns
// the WSConn, using the same client conn for writing upgrade headers.
func upgradeServerSide(t *testing.T, client, server net.Conn) *WSConn {
	t.Helper()
	done := make(chan *WSConn, 1)
	errCh := make(chan error, 1)
	go func() {
		ws, err := WSUpgrade(server, "")
		if err != nil {
			errCh <- err
		} else {
			done <- ws
		}
	}()
	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	client.Write([]byte(req))
	respBuf := make([]byte, 4096)
	client.Read(respBuf)
	select {
	case ws := <-done:
		return ws
	case err := <-errCh:
		t.Fatalf("WSUpgrade: %v", err)
		return nil
	}
}

// TestWSReadFrameVPNSizeDataIntegrity verifies that a VPN-sized (1430-byte)
// masked client frame is decoded correctly when read via the wsReadPool path.
func TestWSReadFrameVPNSizeDataIntegrity(t *testing.T) {
	client, server := testPipe()
	ws := upgradeServerSide(t, client, server)

	payload := make([]byte, 1430)
	for i := range payload {
		payload[i] = byte(i)
	}

	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := ws.Read(buf)
		if err != nil {
			t.Errorf("Read: %v", err)
			readDone <- nil
			return
		}
		readDone <- buf[:n]
	}()

	sendMaskedFrame(t, client, wsOpBinary, payload)
	got := <-readDone

	if !bytes.Equal(got, payload) {
		t.Errorf("data mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	client.Close()
	ws.Close()
}

// TestWSReadFramePoolMaxSizeDataIntegrity verifies a frame exactly at
// wsReadPoolMaxSize is decoded correctly (boundary of hot path).
func TestWSReadFramePoolMaxSizeDataIntegrity(t *testing.T) {
	client, server := testPipe()
	ws := upgradeServerSide(t, client, server)

	payload := bytes.Repeat([]byte{0xCA}, wsReadPoolMaxSize)

	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, wsReadPoolMaxSize+10)
		n, err := ws.Read(buf)
		if err != nil {
			t.Errorf("Read: %v", err)
			readDone <- nil
			return
		}
		readDone <- buf[:n]
	}()

	sendMaskedFrame(t, client, wsOpBinary, payload)
	got := <-readDone

	if !bytes.Equal(got, payload) {
		t.Errorf("at wsReadPoolMaxSize: data mismatch: len=%d want=%d", len(got), len(payload))
	}
	client.Close()
	ws.Close()
}

// TestWSReadFrameOversizedDataIntegrity verifies a frame just above
// wsReadPoolMaxSize (slow-path make) is still decoded correctly.
func TestWSReadFrameOversizedDataIntegrity(t *testing.T) {
	client, server := testPipe()
	ws := upgradeServerSide(t, client, server)

	payload := bytes.Repeat([]byte{0xBB}, wsReadPoolMaxSize+1)

	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, wsReadPoolMaxSize+100)
		n, err := ws.Read(buf)
		if err != nil {
			t.Errorf("Read: %v", err)
			readDone <- nil
			return
		}
		readDone <- buf[:n]
	}()

	sendMaskedFrame(t, client, wsOpBinary, payload)
	got := <-readDone

	if !bytes.Equal(got, payload) {
		t.Errorf("oversized frame: data mismatch")
	}
	client.Close()
	ws.Close()
}

// TestWSReadFramePartialReadDrainsCorrectly verifies that when a frame is read
// in multiple small calls (via ws.readBuf), all bytes are correct and the pool
// backing is released only after the last byte is consumed.
func TestWSReadFramePartialReadDrainsCorrectly(t *testing.T) {
	client, server := testPipe()
	ws := upgradeServerSide(t, client, server)

	// 60-byte payload, read 20 bytes at a time → triggers readBuf path.
	payload := make([]byte, 60)
	for i := range payload {
		payload[i] = byte(i * 3)
	}

	type result struct {
		data []byte
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		var all []byte
		smallBuf := make([]byte, 20)
		for len(all) < len(payload) {
			n, err := ws.Read(smallBuf)
			if err != nil {
				resCh <- result{nil, err}
				return
			}
			all = append(all, smallBuf[:n]...)
		}
		resCh <- result{all, nil}
	}()

	sendMaskedFrame(t, client, wsOpBinary, payload)
	res := <-resCh
	if res.err != nil {
		t.Fatalf("partial read: %v", res.err)
	}
	if !bytes.Equal(res.data, payload) {
		t.Errorf("partial read: data mismatch")
	}
	// After all bytes consumed, readBufBacking must be nil (returned to pool).
	if ws.readBufBacking != nil {
		t.Error("readBufBacking not nil after full drain — pool buffer leaked")
	}

	client.Close()
	ws.Close()
}

// TestWSReadFrameSequentialFramesCorrect verifies N back-to-back frames are
// all decoded correctly when pool buffers are recycled between reads.
func TestWSReadFrameSequentialFramesCorrect(t *testing.T) {
	client, server := testPipe()
	ws := upgradeServerSide(t, client, server)

	const N = 10
	payloadSize := 1430

	allDone := make(chan [][]byte, 1)
	go func() {
		received := make([][]byte, 0, N)
		buf := make([]byte, payloadSize*2)
		for i := 0; i < N; i++ {
			n, err := ws.Read(buf)
			if err != nil {
				t.Errorf("frame %d read error: %v", i, err)
				allDone <- nil
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			received = append(received, cp)
		}
		allDone <- received
	}()

	for i := 0; i < N; i++ {
		payload := bytes.Repeat([]byte{byte(i + 1)}, payloadSize)
		sendMaskedFrame(t, client, wsOpBinary, payload)
	}

	received := <-allDone
	if received == nil {
		t.Fatal("goroutine reported error")
	}
	for i, got := range received {
		want := bytes.Repeat([]byte{byte(i + 1)}, payloadSize)
		if !bytes.Equal(got, want) {
			t.Errorf("frame %d: data mismatch (len got=%d want=%d)", i, len(got), len(want))
		}
	}
	client.Close()
	ws.Close()
}

// TestWSReadFrameZeroLengthPayload verifies that a zero-length data frame
// does not panic. ws.Read may return (0, nil) for it, which is valid for
// io.Reader. We then verify the next non-empty frame is still decoded correctly.
func TestWSReadFrameZeroLengthPayload(t *testing.T) {
	client, server := testPipe()
	ws := upgradeServerSide(t, client, server)

	// Send both frames from a goroutine. net.Pipe is synchronous: each
	// sendMaskedFrame blocks until the server-side reader (ws.Read) consumes it.
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		sendMaskedFrame(t, client, wsOpBinary, []byte{})           // zero-length
		sendMaskedFrame(t, client, wsOpBinary, []byte{1, 2, 3, 4}) // follow-up
	}()

	buf := make([]byte, 64)
	// First ws.Read — processes the zero-length frame (returns 0, nil).
	n0, err := ws.Read(buf)
	if err != nil {
		t.Fatalf("Read(zero-length frame): unexpected error: %v", err)
	}
	if n0 != 0 {
		t.Errorf("Read(zero-length frame): got n=%d, want 0", n0)
	}

	// Second ws.Read — processes the 4-byte follow-up frame.
	n1, err := ws.Read(buf)
	if err != nil {
		t.Fatalf("Read(4-byte frame): unexpected error: %v", err)
	}
	if n1 != 4 || !bytes.Equal(buf[:n1], []byte{1, 2, 3, 4}) {
		t.Errorf("Read(4-byte frame): got %v (n=%d), want [1 2 3 4]", buf[:n1], n1)
	}

	<-sendDone
	client.Close()
	ws.Close()
}

// --- Helpers for tests ---

// sendMaskedFrame sends a WebSocket frame with masking (client→server).
func sendMaskedFrame(t *testing.T, conn net.Conn, opcode byte, payload []byte) {
	t.Helper()
	length := len(payload)
	var hdr []byte

	firstByte := byte(0x80) | opcode // FIN=1
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}

	if length <= 125 {
		hdr = []byte{firstByte, byte(length) | 0x80} // MASK=1
	} else if length <= 65535 {
		hdr = make([]byte, 4)
		hdr[0] = firstByte
		hdr[1] = 126 | 0x80
		binary.BigEndian.PutUint16(hdr[2:], uint16(length))
	} else {
		hdr = make([]byte, 10)
		hdr[0] = firstByte
		hdr[1] = 127 | 0x80
		binary.BigEndian.PutUint64(hdr[2:], uint64(length))
	}

	var buf bytes.Buffer
	buf.Write(hdr)
	buf.Write(mask[:])
	masked := make([]byte, length)
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	buf.Write(masked)
	conn.Write(buf.Bytes())
}

// readUnmaskedFrame reads a server→client unmasked frame.
func readUnmaskedFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var hdr [2]byte
	io.ReadFull(conn, hdr[:])

	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		io.ReadFull(conn, ext[:])
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		io.ReadFull(conn, ext[:])
		length = binary.BigEndian.Uint64(ext[:])
	}

	payload := make([]byte, length)
	io.ReadFull(conn, payload)
	return payload
}
