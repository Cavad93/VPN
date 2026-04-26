// Package transport — minimal WebSocket server (RFC 6455).
//
// Implements only what VLESS+WS needs: server-side HTTP upgrade handshake
// and binary message framing. No client-side, no extensions, no compression.
//
// Supports V2Ray early data (0-RTT): if the client encodes the first bytes
// in Sec-WebSocket-Protocol as base64, they are prepended to the first Read.
//
// The implementation is intentionally minimal to avoid external dependencies.
package transport

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// wsWritePoolMax is the maximum total WebSocket frame size (header+payload) that
// is served from wsWritePool. Covers all standard WS frames (2-byte length field,
// payload ≤ 65535 bytes). Frames with 8-byte length fields (> 65535 bytes) are
// extremely rare and fall back to a plain make().
const wsWritePoolMax = 65535 + 10 // 10 = max WS header (1+1+8 extended length)

// wsReadPoolMax is the maximum payload size served from wsReadPool.
const wsReadPoolMax = 65535

// wsWritePool pools write buffers to eliminate one heap allocation per WebSocket
// write. At 30 Mbps with ~1452-byte frames: ~2600 writes/s → ~3.8 MB/s heap
// pressure eliminated.
var wsWritePool = sync.Pool{
	New: func() any { b := make([]byte, wsWritePoolMax); return &b },
}

// wsReadPool pools read payload buffers to eliminate one heap allocation per
// WebSocket frame. Symmetric savings on the receive path.
var wsReadPool = sync.Pool{
	New: func() any { b := make([]byte, wsReadPoolMax); return &b },
}

// WebSocket opcodes (RFC 6455 §5.2).
const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// wsGUID is the WebSocket magic GUID (RFC 6455 §4.2.2).
const wsGUID = "258EAFA5-E914-47DA-95CA-5AB5DC085B11"

// WSConn wraps a net.Conn with WebSocket binary message framing.
// After Upgrade(), reads and writes are transparently framed.
// Read implements io.Reader: a single WebSocket frame's payload may be
// consumed across multiple Read calls (buffered internally).
type WSConn struct {
	conn           net.Conn
	br             *bufio.Reader
	path           string // requested URL path (e.g. "/tunnel")
	closed         bool
	earlyData      []byte // V2Ray 0-RTT data from Sec-WebSocket-Protocol
	readBuf        []byte // leftover from partially consumed frame
	readBufBacking *[]byte // pool token for readBuf; nil when readBuf is from large-frame make()
}

// Upgrade performs the server-side WebSocket upgrade handshake.
// Returns a WSConn on success. The underlying conn should be a raw TCP
// connection (possibly wrapped in TLS).
//
// Validates that the request targets the expected path. If path is empty,
// any path is accepted.
func WSUpgrade(conn net.Conn, expectedPath string) (*WSConn, error) {
	return WSUpgradeFromReader(conn, bufio.NewReaderSize(conn, 4096), expectedPath)
}

// WSUpgradeFromReader performs server-side WebSocket upgrade using an existing
// buffered reader. Use this when the caller already peeked at the stream to
// detect the protocol (e.g. raw VLESS vs WebSocket).
func WSUpgradeFromReader(conn net.Conn, br *bufio.Reader, expectedPath string) (*WSConn, error) {
	// Read HTTP request
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("ws: read request: %w", err)
	}

	// Validate upgrade headers
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		writeHTTPError(conn, 400, "Bad Request")
		return nil, errors.New("ws: missing Upgrade: websocket header")
	}
	if !headerContains(req.Header, "Connection", "upgrade") {
		writeHTTPError(conn, 400, "Bad Request")
		return nil, errors.New("ws: missing Connection: upgrade header")
	}
	wsKey := req.Header.Get("Sec-WebSocket-Key")
	if wsKey == "" {
		writeHTTPError(conn, 400, "Bad Request")
		return nil, errors.New("ws: missing Sec-WebSocket-Key")
	}

	// Validate path if required
	if expectedPath != "" && req.URL.Path != expectedPath {
		writeHTTPError(conn, 404, "Not Found")
		return nil, fmt.Errorf("ws: path %q does not match %q", req.URL.Path, expectedPath)
	}

	// Compute accept key
	h := sha1.New()
	h.Write([]byte(wsKey))
	h.Write([]byte(wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Handle Sec-WebSocket-Protocol (required by V2Ray clients).
	// V2Ray may send either "binary" or base64-encoded early data (0-RTT).
	var earlyData []byte
	subProto := req.Header.Get("Sec-WebSocket-Protocol")
	respSubProto := ""
	if subProto != "" {
		// Try to decode as base64 (V2Ray early data / 0-RTT).
		// If it decodes and has reasonable length, treat as early data.
		// Otherwise echo it back as-is (e.g. "binary").
		if decoded, err := base64.RawURLEncoding.DecodeString(subProto); err == nil && len(decoded) > 0 && len(decoded) <= 2048 {
			earlyData = decoded
		}
		// Always echo the sub-protocol back — V2Ray clients expect this.
		respSubProto = subProto
	}

	// Write HTTP 101 response
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n"
	if respSubProto != "" {
		resp += "Sec-WebSocket-Protocol: " + respSubProto + "\r\n"
	}
	resp += "\r\n"

	if _, err := conn.Write([]byte(resp)); err != nil {
		return nil, fmt.Errorf("ws: write response: %w", err)
	}

	return &WSConn{
		conn:      conn,
		br:        br,
		path:      req.URL.Path,
		earlyData: earlyData,
	}, nil
}

// WSUpgradeFromParsedRequest performs WebSocket upgrade using an already-parsed
// HTTP request. Use when the caller parsed the request to check headers before
// deciding whether to upgrade or serve a cover site.
func WSUpgradeFromParsedRequest(conn net.Conn, req *http.Request, expectedPath string) (*WSConn, error) {
	if !headerContains(req.Header, "Connection", "upgrade") {
		return nil, errors.New("ws: missing Connection: upgrade header")
	}
	wsKey := req.Header.Get("Sec-WebSocket-Key")
	if wsKey == "" {
		return nil, errors.New("ws: missing Sec-WebSocket-Key")
	}
	if expectedPath != "" && req.URL.Path != expectedPath {
		return nil, fmt.Errorf("ws: path %q does not match %q", req.URL.Path, expectedPath)
	}

	h := sha1.New()
	h.Write([]byte(wsKey))
	h.Write([]byte(wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	var earlyData []byte
	subProto := req.Header.Get("Sec-WebSocket-Protocol")
	respSubProto := ""
	if subProto != "" {
		if decoded, err := base64.RawURLEncoding.DecodeString(subProto); err == nil && len(decoded) > 0 && len(decoded) <= 2048 {
			earlyData = decoded
		}
		respSubProto = subProto
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n"
	if respSubProto != "" {
		resp += "Sec-WebSocket-Protocol: " + respSubProto + "\r\n"
	}
	resp += "\r\n"

	if _, err := conn.Write([]byte(resp)); err != nil {
		return nil, fmt.Errorf("ws: write response: %w", err)
	}

	return &WSConn{
		conn:      conn,
		br:        bufio.NewReaderSize(conn, 4096),
		path:      req.URL.Path,
		earlyData: earlyData,
	}, nil
}

// Path returns the URL path from the upgrade request.
func (ws *WSConn) Path() string { return ws.path }

// HasEarlyData returns true if 0-RTT data was received during upgrade.
func (ws *WSConn) HasEarlyData() bool { return len(ws.earlyData) > 0 }

// Read reads WebSocket data into p, implementing io.Reader.
// A single WebSocket frame's payload may be consumed across multiple Read calls.
// If early data (0-RTT) was received during upgrade, it is returned first.
// Handles ping/pong and close frames transparently.
func (ws *WSConn) Read(p []byte) (int, error) {
	// 1. Return early data first (V2Ray 0-RTT from Sec-WebSocket-Protocol)
	if len(ws.earlyData) > 0 {
		n := copy(p, ws.earlyData)
		ws.earlyData = ws.earlyData[n:]
		if len(ws.earlyData) == 0 {
			ws.earlyData = nil
		}
		return n, nil
	}

	// 2. Return leftover data from a previous frame
	if len(ws.readBuf) > 0 {
		n := copy(p, ws.readBuf)
		ws.readBuf = ws.readBuf[n:]
		if len(ws.readBuf) == 0 {
			ws.readBuf = nil
			// Return pool buffer when all leftover bytes are consumed.
			if ws.readBufBacking != nil {
				wsReadPool.Put(ws.readBufBacking)
				ws.readBufBacking = nil
			}
		}
		return n, nil
	}

	// 3. Read the next frame
	for {
		_, opcode, payload, backing, err := ws.readFrame()
		if err != nil {
			return 0, err
		}

		// putBacking returns backing to the pool (nil-safe).
		putBacking := func() {
			if backing != nil {
				wsReadPool.Put(backing)
			}
		}

		switch opcode {
		case wsOpClose:
			ws.closed = true
			putBacking()
			ws.writeFrame(wsOpClose, nil)
			return 0, io.EOF
		case wsOpPing:
			ws.writeFrame(wsOpPong, payload)
			putBacking()
			continue
		case wsOpPong:
			putBacking()
			continue
		case wsOpBinary, wsOpText, wsOpContinuation:
			n := copy(p, payload)
			if n < len(payload) {
				// Partial read: keep leftover in readBuf.
				// Hold the pool token until readBuf is fully drained (step 2 above).
				ws.readBuf = payload[n:]
				ws.readBufBacking = backing
			} else {
				// All bytes consumed in this call — return backing immediately.
				putBacking()
			}
			return n, nil
		default:
			putBacking()
			return 0, fmt.Errorf("ws: unknown opcode 0x%x", opcode)
		}
	}
}

// Write sends data as a single binary WebSocket frame (server→client, unmasked).
func (ws *WSConn) Write(p []byte) (int, error) {
	if err := ws.writeFrame(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends a close frame and closes the underlying connection.
func (ws *WSConn) Close() error {
	if !ws.closed {
		ws.closed = true
		ws.writeFrame(wsOpClose, nil)
	}
	return ws.conn.Close()
}

// Underlying returns the raw net.Conn.
func (ws *WSConn) Underlying() net.Conn { return ws.conn }

// readFrame reads a single WebSocket frame. Client→server frames are masked.
// Returns (fin, opcode, payload, backing, err).
// backing is a *[]byte pool token; the caller must return it to wsReadPool
// when it is done with payload (or nil for frames backed by a plain make).
func (ws *WSConn) readFrame() (fin bool, opcode byte, payload []byte, backing *[]byte, err error) {
	// Read first 2 bytes: FIN + opcode + MASK + payload length
	var hdr [2]byte
	if _, err := io.ReadFull(ws.br, hdr[:]); err != nil {
		return false, 0, nil, nil, err
	}

	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)

	// Extended payload length
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
			return false, 0, nil, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
			return false, 0, nil, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	// Masking key (client→server always masked per RFC 6455)
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(ws.br, maskKey[:]); err != nil {
			return false, 0, nil, nil, err
		}
	}

	if length > 16*1024*1024 { // 16 MB sanity limit
		return false, 0, nil, nil, errors.New("ws: frame too large")
	}

	// Allocate payload buffer — pool for standard frames, make for huge ones.
	if length <= wsReadPoolMax {
		pb := wsReadPool.Get().(*[]byte)
		payload = (*pb)[:length]
		backing = pb
	} else {
		payload = make([]byte, length)
		backing = nil
	}

	if length > 0 {
		if _, err := io.ReadFull(ws.br, payload); err != nil {
			if backing != nil {
				wsReadPool.Put(backing)
			}
			return false, 0, nil, nil, err
		}
	}

	// Unmask in-place. Process 4 bytes at a time to avoid per-byte modular
	// arithmetic (i%4); tail handles the remaining 0–3 bytes.
	if masked {
		wsUnmask(payload, maskKey)
	}

	return fin, opcode, payload, backing, nil
}

// wsUnmask applies WebSocket masking in-place (RFC 6455 §5.3).
// Processes 4 bytes per iteration using a single uint32 XOR, avoiding the
// per-byte modular arithmetic of the naive loop.
func wsUnmask(b []byte, maskKey [4]byte) {
	mask32 := binary.LittleEndian.Uint32(maskKey[:])
	i := 0
	for ; i+4 <= len(b); i += 4 {
		v := binary.LittleEndian.Uint32(b[i:])
		binary.LittleEndian.PutUint32(b[i:], v^mask32)
	}
	// Tail: 0–3 remaining bytes. i&3 == i%4 for non-negative i.
	for ; i < len(b); i++ {
		b[i] ^= maskKey[i&3]
	}
}

// writeFrame writes a single WebSocket frame. Server→client frames are NOT masked.
// Uses a stack-allocated header (no heap alloc for header bytes) and a pooled
// combined buffer for frames ≤ wsWritePoolMax bytes. This eliminates two heap
// allocations per frame that existed in the previous implementation.
func (ws *WSConn) writeFrame(opcode byte, payload []byte) error {
	length := len(payload)
	firstByte := byte(0x80) | (opcode & 0x0F) // FIN=1

	// Build WS frame header on the stack — max 10 bytes (2 + 8-byte extended length).
	var hdrArr [10]byte
	var hdrLen int
	if length <= 125 {
		hdrArr[0] = firstByte
		hdrArr[1] = byte(length)
		hdrLen = 2
	} else if length <= 65535 {
		hdrArr[0] = firstByte
		hdrArr[1] = 126
		binary.BigEndian.PutUint16(hdrArr[2:], uint16(length))
		hdrLen = 4
	} else {
		hdrArr[0] = firstByte
		hdrArr[1] = 127
		binary.BigEndian.PutUint64(hdrArr[2:], uint64(length))
		hdrLen = 10
	}

	// Header-only frames (close, ping with no payload).
	if length == 0 {
		_, err := ws.conn.Write(hdrArr[:hdrLen])
		return err
	}

	totalLen := hdrLen + length
	if totalLen <= wsWritePoolMax {
		// Pool path: zero heap allocations for standard-sized frames.
		pb := wsWritePool.Get().(*[]byte)
		buf := (*pb)[:totalLen]
		copy(buf[:hdrLen], hdrArr[:hdrLen])
		copy(buf[hdrLen:], payload)
		_, err := ws.conn.Write(buf)
		wsWritePool.Put(pb)
		return err
	}

	// Large frame (> 65 KB): fall back to plain allocation.
	buf := make([]byte, totalLen)
	copy(buf[:hdrLen], hdrArr[:hdrLen])
	copy(buf[hdrLen:], payload)
	_, err := ws.conn.Write(buf)
	return err
}

// writeHTTPError sends a minimal HTTP error response.
func writeHTTPError(conn net.Conn, code int, status string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, status)
	conn.Write([]byte(resp))
}

// headerContains checks if an HTTP header contains a value (case-insensitive).
func headerContains(h http.Header, key, value string) bool {
	for _, v := range h[http.CanonicalHeaderKey(key)] {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(s), value) {
				return true
			}
		}
	}
	return false
}
