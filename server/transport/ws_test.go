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

// TestWSUnmask verifies wsUnmask correctness for various payload lengths,
// including 0-, 1-, 3-, 4-, 5-, 7-, 8-, and 15-byte cases to cover all
// alignment variants of the 4-byte-at-a-time loop.
func TestWSUnmask(t *testing.T) {
	mask := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}

	// reference: naive byte-by-byte XOR
	naiveUnmask := func(b []byte) []byte {
		out := make([]byte, len(b))
		for i, v := range b {
			out[i] = v ^ mask[i%4]
		}
		return out
	}

	sizes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 127, 128, 1430, 65535}
	for _, sz := range sizes {
		orig := make([]byte, sz)
		for i := range orig {
			orig[i] = byte(i * 13)
		}
		want := naiveUnmask(orig)

		got := make([]byte, sz)
		copy(got, orig)
		wsUnmask(got, mask)

		if !bytes.Equal(got, want) {
			t.Errorf("wsUnmask(%d bytes): mismatch", sz)
		}
	}
}

// TestWSUnmaskIdempotent verifies that applying wsUnmask twice restores the original.
func TestWSUnmaskIdempotent(t *testing.T) {
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	orig := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	buf := make([]byte, len(orig))
	copy(buf, orig)
	wsUnmask(buf, mask)
	wsUnmask(buf, mask) // second application must restore original
	if !bytes.Equal(buf, orig) {
		t.Errorf("double wsUnmask: got %v, want %v", buf, orig)
	}
}

// TestWSWritePoolReuse verifies that the zero-alloc write path produces the
// same bytes as the reference naive implementation.
func TestWSWritePoolReuse(t *testing.T) {
	// Write a VPN-sized frame (1452 bytes) and verify the received payload.
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

	payload := bytes.Repeat([]byte{0xAB}, 1452)
	go ws.Write(payload)

	got := readUnmaskedFrame(t, client)
	if !bytes.Equal(got, payload) {
		t.Errorf("1452-byte frame: payload mismatch (len got=%d, want=%d)", len(got), len(payload))
	}

	client.Close()
	ws.Close()
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
