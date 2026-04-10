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
)

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
	conn      net.Conn
	br        *bufio.Reader
	path      string // requested URL path (e.g. "/tunnel")
	closed    bool
	earlyData []byte // V2Ray 0-RTT data from Sec-WebSocket-Protocol
	readBuf   []byte // leftover from partially consumed frame
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
		}
		return n, nil
	}

	// 3. Read the next frame
	for {
		_, opcode, payload, err := ws.readFrame()
		if err != nil {
			return 0, err
		}

		switch opcode {
		case wsOpClose:
			ws.closed = true
			ws.writeFrame(wsOpClose, nil)
			return 0, io.EOF
		case wsOpPing:
			ws.writeFrame(wsOpPong, payload)
			continue
		case wsOpPong:
			continue
		case wsOpBinary, wsOpText, wsOpContinuation:
			n := copy(p, payload)
			// Buffer any leftover bytes for subsequent Read calls
			if n < len(payload) {
				ws.readBuf = payload[n:]
			}
			return n, nil
		default:
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
func (ws *WSConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	// Read first 2 bytes: FIN + opcode + MASK + payload length
	var hdr [2]byte
	if _, err := io.ReadFull(ws.br, hdr[:]); err != nil {
		return false, 0, nil, err
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
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	// Masking key (client→server always masked per RFC 6455)
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(ws.br, maskKey[:]); err != nil {
			return false, 0, nil, err
		}
	}

	// Read payload
	if length > 16*1024*1024 { // 16 MB sanity limit
		return false, 0, nil, errors.New("ws: frame too large")
	}
	payload = make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(ws.br, payload); err != nil {
			return false, 0, nil, err
		}
	}

	// Unmask
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return fin, opcode, payload, nil
}

// writeFrame writes a single WebSocket frame. Server→client frames are NOT masked.
func (ws *WSConn) writeFrame(opcode byte, payload []byte) error {
	length := len(payload)

	// Build header
	var hdr []byte
	firstByte := byte(0x80) | (opcode & 0x0F) // FIN=1

	if length <= 125 {
		hdr = []byte{firstByte, byte(length)}
	} else if length <= 65535 {
		hdr = make([]byte, 4)
		hdr[0] = firstByte
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(length))
	} else {
		hdr = make([]byte, 10)
		hdr[0] = firstByte
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(length))
	}

	// Write header + payload in one syscall when possible
	if length == 0 {
		_, err := ws.conn.Write(hdr)
		return err
	}
	buf := make([]byte, len(hdr)+length)
	copy(buf, hdr)
	copy(buf[len(hdr):], payload)
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
