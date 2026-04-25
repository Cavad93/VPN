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

// wsUnmask applies the WebSocket per-frame masking transform in-place.
//
// RFC 6455 §5.3 mandates that all client→server frames are masked with a
// 4-byte key applied cyclically: payload[i] ^= maskKey[i%4].
//
// This function processes 8 bytes per iteration using uint64 XOR, reducing
// loop iterations by ~8× compared to a naive byte-by-byte approach.
// At 30 Mbps upload with ~2630 masked frames/sec (≈1455 bytes each), the
// byte-by-byte approach executes ~3.83 M XOR ops/sec; the uint64 approach
// executes ~480 K XOR ops/sec — a measurable reduction in hot-path CPU time.
//
// Correctness proof: the 4-byte key repeats with period 4.  Since 8 is a
// multiple of 4, a two-copy 64-bit key word covers exactly two complete key
// periods.  LittleEndian encoding ensures that byte j of a uint64 chunk maps
// to bit-offset 8*j, so byte at absolute index i*8+j is XOR'd with
// maskKey[(i*8+j)%4] = maskKey[j%4] = maskKey[j&3].
//
// The tail loop (0–7 remaining bytes) uses i&3 (equivalent to i%4 for the
// power-of-two modulus, but avoids a division instruction on older CPUs).
func wsUnmask(payload []byte, maskKey [4]byte) {
	if len(payload) == 0 {
		return
	}
	// Build a 64-bit key: two consecutive copies of the 32-bit key.
	// LittleEndian layout: key64 byte[j] == maskKey[j&3] for j = 0..7.
	key32 := uint32(maskKey[0]) | uint32(maskKey[1])<<8 |
		uint32(maskKey[2])<<16 | uint32(maskKey[3])<<24
	key64 := uint64(key32) | uint64(key32)<<32

	i := 0
	for ; i+8 <= len(payload); i += 8 {
		v := binary.LittleEndian.Uint64(payload[i:])
		binary.LittleEndian.PutUint64(payload[i:], v^key64)
	}
	// Handle remaining 0–7 bytes.
	for ; i < len(payload); i++ {
		payload[i] ^= maskKey[i&3]
	}
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

// wsWriteBufSize is the size of the pre-allocated write buffer embedded in
// WSConn. It must accommodate the largest expected WS frame in VPN operation:
//
//	tunMTU(1430) + mux overhead(7) + noise overhead(18) = 1455 bytes payload
//	WS header for that length (126 ≤ n ≤ 65535)          =    4 bytes header
//	total:                                                 = 1459 bytes
//
// 1472 bytes (a multiple of 16) gives 13 bytes of headroom and fits comfortably
// in two CPU cache lines (64 bytes each → 23 cache lines for the buffer).
const wsWriteBufSize = 1472

// wsLargeWriteBufSize is the pool buffer size for the writeFrame slow path.
// This covers the VLESS TCP proxy case where io.Copy delivers up to 32 KiB per
// Write call (io.Copy default buffer = 32 KiB; WS header = max 10 bytes).
// Frames > wsLargeWriteBufSize are rare (would need payloads > 32 KiB) and
// fall back to make() as before.
const wsLargeWriteBufSize = 32*1024 + 10

// wsLargeWritePool pools combined header+payload buffers for the writeFrame
// slow path (payload > wsWriteBufSize). This eliminates per-frame heap
// allocations on the VLESS TCP proxy download path, where io.Copy delivers
// large chunks:
//
//	io.Copy buffer (32 KiB) → ws.Write(32 KiB) → writeFrame slow path
//	At 10 Mbps with ~4 KiB frames: ~2500 allocs/sec × ~4 KiB ≈ 10 MB/sec
//	After pooling: 0 allocs/sec for frames ≤ wsLargeWriteBufSize.
var wsLargeWritePool = sync.Pool{New: func() any {
	b := make([]byte, wsLargeWriteBufSize)
	return &b
}}

// wsReadBufSize is the size of the bufio.Reader wrapping the underlying TCP
// connection in WSConn. It governs how many bytes are fetched from the OS per
// syscall when draining the receive buffer.
//
// Sizing rationale:
//
//	One masked VPN frame ≈ 1455 bytes payload + 8 bytes header = 1463 bytes.
//	At 30 Mbps the OS typically delivers 8–12 frames in a single recv().
//	16384 / 1463 ≈ 11 frames — covers the common burst window in one syscall.
//	16384 = max TLS record size — aligns with TLS layer reads when ws.go is
//	        layered over TLS (VLESS mode), avoiding a second partial read.
//	Memory cost: 16 KB per connection (vs 4 KB before) — negligible for a VPN.
//
// With the previous 4096-byte buffer a 5-frame burst (5×1463 = 7315 bytes)
// required 2 syscalls; with 16384 it fits in 1 syscall.
const wsReadBufSize = 16384

// WSConn wraps a net.Conn with WebSocket binary message framing.
// After Upgrade(), reads and writes are transparently framed.
// Read implements io.Reader: a single WebSocket frame's payload may be
// consumed across multiple Read calls (streamed directly into the caller's
// buffer without intermediate heap allocation or copy).
type WSConn struct {
	conn      net.Conn
	br        *bufio.Reader
	path      string // requested URL path (e.g. "/tunnel")
	closed    bool
	earlyData []byte // V2Ray 0-RTT data from Sec-WebSocket-Protocol

	// Streaming read state — eliminates heap alloc and the copy(p,readBuf)
	// cost that the previous pool+readBuf approach incurred on partial reads.
	// Data flows: network → bufio.Reader → caller's p directly.
	frameRem int     // payload bytes remaining in the current data frame
	masked   bool    // current frame uses RFC 6455 client→server masking
	maskKey  [4]byte // XOR masking key for the current frame
	maskOff  int     // current byte offset in the 4-byte masking cycle (0–3)

	// writeBuf is a pre-allocated scratch buffer for assembling outgoing data
	// frames (binary/text/continuation). Data writes are serialised by the
	// mux layer (mux.writeMu), so only one goroutine touches writeBuf at a
	// time — eliminating the make([]byte, hdrLen+length) allocation that
	// previously appeared on every download-direction VPN packet.
	//
	// Control frames (ping/pong/close) do NOT use writeBuf; they use
	// stack-allocated headers to remain safe under concurrent read/write.
	writeBuf [wsWriteBufSize]byte
}

// Upgrade performs the server-side WebSocket upgrade handshake.
// Returns a WSConn on success. The underlying conn should be a raw TCP
// connection (possibly wrapped in TLS).
//
// Validates that the request targets the expected path. If path is empty,
// any path is accepted.
func WSUpgrade(conn net.Conn, expectedPath string) (*WSConn, error) {
	return WSUpgradeFromReader(conn, bufio.NewReaderSize(conn, wsReadBufSize), expectedPath)
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
		br:        bufio.NewReaderSize(conn, wsReadBufSize),
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
// Zero heap allocations in the steady-state VPN data path: data flows
// network → bufio.Reader → p without any intermediate make or copy.
func (ws *WSConn) Read(p []byte) (int, error) {
	// 1. V2Ray 0-RTT early data received during upgrade handshake.
	if len(ws.earlyData) > 0 {
		n := copy(p, ws.earlyData)
		ws.earlyData = ws.earlyData[n:]
		if len(ws.earlyData) == 0 {
			ws.earlyData = nil
		}
		return n, nil
	}

	// 2. Bytes remaining from the current in-progress data frame: deliver
	//    directly from bufio.Reader into p — no intermediate allocation or copy.
	if ws.frameRem > 0 {
		return ws.consumeFrameData(p)
	}

	// 3. Read the next frame header, handling control frames inline.
	for {
		fin, opcode, length, masked, maskKey, err := ws.readFrameHeader()
		if err != nil {
			return 0, err
		}
		_ = fin // fragmentation not used in VPN path

		switch opcode {
		case wsOpClose:
			ws.closed = true
			// Drain any close-reason bytes (≤125 per RFC 6455 §5.5).
			if length > 0 {
				io.CopyN(io.Discard, ws.br, int64(length)) //nolint:errcheck
			}
			ws.writeFrame(wsOpClose, nil)
			return 0, io.EOF

		case wsOpPing:
			// RFC 6455 §5.5: control frame payload ≤ 125 bytes.
			// Stack-allocated buffer avoids heap allocation.
			var pingBuf [125]byte
			pingLen := int(length)
			if pingLen > 125 {
				pingLen = 125
			}
			if pingLen > 0 {
				if _, err := io.ReadFull(ws.br, pingBuf[:pingLen]); err != nil {
					return 0, err
				}
				if masked {
					wsUnmask(pingBuf[:pingLen], maskKey)
				}
			}
			ws.writeFrame(wsOpPong, pingBuf[:pingLen])
			continue

		case wsOpPong:
			// Drain pong payload; we don't initiate pings but tolerate them.
			if length > 0 {
				io.CopyN(io.Discard, ws.br, int64(length)) //nolint:errcheck
			}
			continue

		case wsOpBinary, wsOpText, wsOpContinuation:
			if length == 0 {
				// Empty data frame — return 0, nil to the caller (matches
				// original behaviour; caller retries if more bytes needed).
				return 0, nil
			}
			ws.frameRem = int(length)
			ws.masked = masked
			ws.maskKey = maskKey
			ws.maskOff = 0
			return ws.consumeFrameData(p)

		default:
			return 0, fmt.Errorf("ws: unknown opcode 0x%x", opcode)
		}
	}
}

// consumeFrameData reads up to min(len(p), ws.frameRem) bytes from the
// buffered reader directly into p, applying RFC 6455 masking in-place using
// the fast wsUnmask (uint64 batch XOR). The maskOff field tracks the rotating
// 4-byte key position so large frames can be consumed across multiple Read calls.
// Single-buffer design: data flows network → bufio.Reader → p, zero copies.
func (ws *WSConn) consumeFrameData(p []byte) (int, error) {
	toRead := ws.frameRem
	if toRead > len(p) {
		toRead = len(p)
	}
	n, err := io.ReadFull(ws.br, p[:toRead])
	if n > 0 && ws.masked {
		// Rotate the mask key to start at the current cycle offset so that
		// wsUnmask's uint64-batched XOR produces the correct result even when
		// maskOff > 0 (i.e. this is a continuation of a partially-read frame).
		var rotKey [4]byte
		off := ws.maskOff
		for i := range rotKey {
			rotKey[i] = ws.maskKey[(off+i)&3]
		}
		wsUnmask(p[:n], rotKey)
		ws.maskOff = (off + n) & 3
	}
	ws.frameRem -= n
	return n, err
}

// readFrameHeader reads the WebSocket frame header (2–14 bytes) and returns
// the frame metadata. The payload is NOT read here; the caller must consume
// exactly length bytes from ws.br afterwards. All locals are stack-allocated
// — zero heap allocations.
func (ws *WSConn) readFrameHeader() (fin bool, opcode byte, length uint64, masked bool, maskKey [4]byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(ws.br, hdr[:]); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0F
	masked = hdr[1]&0x80 != 0
	length = uint64(hdr[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(ws.br, ext[:]); err != nil {
			return
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(ws.br, ext[:]); err != nil {
			return
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	if masked {
		if _, err = io.ReadFull(ws.br, maskKey[:]); err != nil {
			return
		}
	}

	if length > 16*1024*1024 {
		err = errors.New("ws: frame too large")
		return
	}
	return
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

// writeFrame writes a single WebSocket frame. Server→client frames are NOT masked.
//
// Data frames (binary/text/continuation) are assembled directly into the
// pre-allocated ws.writeBuf, eliminating the make([]byte, hdrLen+length)
// allocation that previously occurred on every download-direction VPN packet.
// At 30 Mbps with 1430-byte TUN frames this was ~2630 allocations/sec
// (≈3.75 MB/sec of heap pressure) — now zero for steady-state traffic.
//
// Control frames (ping/pong/close) use stack-allocated headers because they
// may be written from the read goroutine (e.g. pong responses) concurrently
// with data writes from the mux write goroutine; sharing writeBuf between
// those goroutines would cause a data race.
func (ws *WSConn) writeFrame(opcode byte, payload []byte) error {
	length := len(payload)
	firstByte := byte(0x80) | (opcode & 0x0F) // FIN=1

	// ── Control frames (ping / pong / close) ────────────────────────────────
	// RFC 6455 §5.5: control frame payloads must be ≤ 125 bytes.
	// These may be sent from the read goroutine (pong auto-reply), so we must
	// NOT touch ws.writeBuf here.
	if opcode == wsOpClose || opcode == wsOpPing || opcode == wsOpPong {
		if length > 125 {
			return errors.New("ws: control frame payload exceeds 125 bytes")
		}
		var hdr [2]byte
		hdr[0] = firstByte
		hdr[1] = byte(length)
		if length == 0 {
			_, err := ws.conn.Write(hdr[:])
			return err
		}
		// RFC 6455 §5.5 guarantees payload ≤ 125 bytes, so 2+125 = 127 fits in a
		// stack-allocated array. net.Conn.Write copies data into the kernel send
		// buffer before returning, so passing a pointer to a local array is safe.
		var buf [127]byte
		buf[0] = hdr[0]
		buf[1] = hdr[1]
		copy(buf[2:], payload)
		_, err := ws.conn.Write(buf[:2+length])
		return err
	}

	// ── Data frames (binary / text / continuation) ───────────────────────────
	// Writes are serialised by mux.writeMu → only one goroutine here at a time.
	// Build the full frame directly in ws.writeBuf (zero heap allocation).
	var hdrLen int
	ws.writeBuf[0] = firstByte
	if length <= 125 {
		ws.writeBuf[1] = byte(length)
		hdrLen = 2
	} else if length <= 65535 {
		ws.writeBuf[1] = 126
		binary.BigEndian.PutUint16(ws.writeBuf[2:], uint16(length))
		hdrLen = 4
	} else {
		ws.writeBuf[1] = 127
		binary.BigEndian.PutUint64(ws.writeBuf[2:], uint64(length))
		hdrLen = 10
	}

	// Hot path: frame fits in embedded buffer → zero heap allocation.
	if hdrLen+length <= wsWriteBufSize {
		copy(ws.writeBuf[hdrLen:], payload)
		_, err := ws.conn.Write(ws.writeBuf[:hdrLen+length])
		return err
	}

	// Slow path: payload exceeds embedded buffer (VLESS TCP proxy: io.Copy delivers
	// up to 32 KiB per Write call; VPN tunnel never reaches here — max is 1455 B).
	// Use wsLargeWritePool to eliminate the per-frame heap allocation.
	totalSize := hdrLen + length
	if totalSize <= wsLargeWriteBufSize {
		pb := wsLargeWritePool.Get().(*[]byte)
		buf := (*pb)[:totalSize]
		copy(buf, ws.writeBuf[:hdrLen])
		copy(buf[hdrLen:], payload)
		_, err := ws.conn.Write(buf)
		// ws.conn.Write copies data into TLS/TCP send buffer before returning —
		// safe to return the pool buffer immediately.
		wsLargeWritePool.Put(pb)
		return err
	}
	// Extremely large frame (> 32 KiB + 10): extraordinary case, make() once.
	buf := make([]byte, totalSize)
	copy(buf, ws.writeBuf[:hdrLen])
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
