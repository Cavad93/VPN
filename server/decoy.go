// Package main — decoy.go implements active-probe protection for the VPN server.
//
// When an external scanner or DPI probe connects to the VPN port, it sends
// data that does NOT start with a TLS Handshake record (0x16). This module
// intercepts such connections BEFORE the ObfsConn handshake and responds with
// a convincing HTTP/1.1 400 "plain HTTP sent to HTTPS port" page — exactly
// what nginx returns in this situation.
//
// Decision tree (based on first byte only, zero overhead for real clients):
//
//	first byte == 0x16  →  VPN path (TLS ClientHello, ObfsConn takes over)
//	first byte == other →  serveHTTPDecoy (nginx-like 400) + close
//
// The 400 response is chosen deliberately:
//  1. It is the most common real-world nginx response when plain HTTP is sent
//     to an HTTPS listener — scanners expect and recognise it.
//  2. It does NOT expose that this is a VPN server.
//  3. It closes the connection immediately after — no lingering state.
//
// peekConn prepends the already-consumed first byte back into the read stream
// so the rest of the handshake pipeline (BufConn → ObfsConn → Noise) never
// knows that peeking happened.
package main

import (
	"fmt"
	"net"
	"time"
)

// tlsHandshakeRecordType is the TLS content_type byte for a Handshake record.
// A real TLS ClientHello, and our synthetic ObfsConn ClientHello, both start
// with this byte (0x16 = 22 decimal).
const tlsHandshakeRecordType = byte(0x16)

// decoyReadDeadline is how long we wait for the client to send its first byte.
// Real VPN clients connect and immediately send a ClientHello; 5 s is generous.
// Scanners that send nothing (SYN-only probes) will be dropped after this.
// Declared as a variable (not const) so unit tests can override it.
var decoyReadDeadline = 5 * time.Second

// decoyHTTPResponse is the response served to non-VPN probes.
// It mimics nginx's standard "400 The plain HTTP request was sent to HTTPS
// port" error — the most widely recognised response for HTTPS servers receiving
// HTTP traffic. The Date header is omitted intentionally: it would require
// time.Now() formatting and scanners do not verify it for fingerprinting.
// decoyHTTPBody is the HTML body of the decoy response.
// Kept as a separate constant so the init check and tests can verify that
// Content-Length in the headers matches exactly.
const decoyHTTPBody = "<html>\r\n" +
	"<head><title>400 Bad Request</title></head>\r\n" +
	"<body>\r\n" +
	"<center><h1>400 Bad Request</h1></center>\r\n" +
	"<center>The plain HTTP request was sent to HTTPS port</center>\r\n" +
	"<hr><center>nginx/1.24.0</center>\r\n" +
	"</body>\r\n" +
	"</html>\r\n"

// decoyBodyLen is len(decoyHTTPBody); used in Content-Length and tests.
const decoyBodyLen = len(decoyHTTPBody) // 221

var decoyHTTPResponse = []byte("HTTP/1.1 400 Bad Request\r\n" +
	"Server: nginx/1.24.0\r\n" +
	"Content-Type: text/html\r\n" +
	fmt.Sprintf("Content-Length: %d\r\n", decoyBodyLen) +
	"Connection: close\r\n" +
	"\r\n" +
	decoyHTTPBody)

func init() {
	// Compile-time guard: verify Content-Length header matches actual body.
	if decoyBodyLen != 221 {
		panic(fmt.Sprintf("decoy: body length changed: got %d, expected 221 — update Content-Length header", decoyBodyLen))
	}
}

// peekConn wraps a net.Conn and prepends a single already-read byte back into
// the read stream. All other net.Conn methods are forwarded unchanged.
//
// Concurrency: Read is not safe for concurrent use (same as net.TCPConn).
// All other methods are safe for concurrent use.
type peekConn struct {
	net.Conn
	peeked byte // the byte that was read during probing
	used   bool // true once the peeked byte has been consumed
}

// Read satisfies io.Reader. The first call (or the first call after the peeked
// byte has been injected) prepends the peeked byte before delegating to the
// underlying connection.
func (p *peekConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if !p.used {
		p.used = true
		b[0] = p.peeked
		if len(b) == 1 {
			// Caller asked for exactly 1 byte — return it without a syscall.
			return 1, nil
		}
		// Caller wants more; read the rest from the wire.
		n, err := p.Conn.Read(b[1:])
		return 1 + n, err
	}
	return p.Conn.Read(b)
}

// peekAndRoute reads the first byte of conn and decides whether the connection
// carries a VPN handshake or an active probe.
//
// Returns:
//   - (peeked net.Conn, true)  — the byte was 0x16; caller should proceed with
//     the normal VPN pipeline. The returned conn transparently replays the
//     peeked byte so the pipeline never sees a truncated stream.
//   - (nil, false)             — the byte was something else; peekAndRoute has
//     already written the HTTP decoy response and closed the connection.
//     Caller must not touch conn.
func peekAndRoute(conn net.Conn) (net.Conn, bool) {
	// Give the client a short window to send its first byte.
	_ = conn.SetReadDeadline(time.Now().Add(decoyReadDeadline))

	var first [1]byte
	if _, err := conn.Read(first[:]); err != nil {
		// No data arrived (timeout, reset, etc.) — close silently.
		conn.Close()
		return nil, false
	}

	// Clear the read deadline so the rest of the pipeline is unaffected.
	_ = conn.SetReadDeadline(time.Time{})

	if first[0] == tlsHandshakeRecordType {
		// Looks like a TLS ClientHello — let the VPN pipeline handle it.
		return &peekConn{Conn: conn, peeked: first[0]}, true
	}

	// Not a VPN client. Serve the HTTP decoy and close.
	serveHTTPDecoy(conn)
	return nil, false
}

// serveHTTPDecoy writes the nginx-like 400 response and closes conn.
// The write deadline is intentionally short (2 s): we do not want to block
// the goroutine on a slow scanner.
func serveHTTPDecoy(conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(decoyHTTPResponse) //nolint:errcheck
	conn.Close()
}
