// Package main — decoy.go implements active-probe protection for the VPN server.
//
// When an external scanner or DPI probe connects to the VPN port, this module
// intercepts the connection BEFORE the ObfsConn handshake and decides how to
// handle it based on the first byte of data.
//
// Decision tree (based on first byte only, zero overhead for real clients):
//
//	first byte == 0x16  →  VPN path (TLS ClientHello, ObfsConn takes over)
//	first byte == other →  serveFallback: HTTP → cooking blog; non-HTTP → nginx 400
//
// Anti-probing strategy (per gfw.report, Trojan protocol, and XRAY research):
//  1. HTTP probes receive a full, convincing cooking blog website — the server
//     looks like a normal web server to any scanner that visits it.
//  2. Non-HTTP binary probes get a standard nginx 400 response — consistent
//     with nginx receiving plain HTTP on an HTTPS port.
//  3. TLS probes that fail ObfsConn handshake are silently drained (DEBUG log).
//
// peekConn prepends the already-consumed first byte back into the read stream
// so the rest of the handshake pipeline (BufConn → ObfsConn → Noise) never
// knows that peeking happened.
package main

import (
	"net"
	"sync/atomic"
	"time"
)

// tlsHandshakeRecordType is the TLS content_type byte for a Handshake record.
// A real TLS ClientHello, and our synthetic ObfsConn ClientHello, both start
// with this byte (0x16 = 22 decimal).
const tlsHandshakeRecordType = byte(0x16)

// decoyReadDeadlineNs stores the read deadline duration in nanoseconds.
// Using atomic.Int64 prevents data races when unit tests temporarily override
// the value while TestServerRun concurrently calls peekAndRoute.
// Real VPN clients connect and immediately send a ClientHello; 5 s is generous.
// Scanners that send nothing (SYN-only probes) will be dropped after this.
var decoyReadDeadlineNs atomic.Int64

func init() {
	decoyReadDeadlineNs.Store(int64(5 * time.Second))
}

// decoyReadDeadline returns the current read deadline duration.
func decoyReadDeadline() time.Duration {
	return time.Duration(decoyReadDeadlineNs.Load())
}

// setDecoyReadDeadline sets the read deadline duration.
// Used only in tests; the production default is 5 s (set in init).
func setDecoyReadDeadline(d time.Duration) {
	decoyReadDeadlineNs.Store(int64(d))
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
	_ = conn.SetReadDeadline(time.Now().Add(decoyReadDeadline()))

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

	// Not a VPN client. Serve fallback website (cooking blog for HTTP,
	// nginx 400 for non-HTTP binary probes). serveFallback closes conn.
	serveFallback(&peekConn{Conn: conn, peeked: first[0]})
	return nil, false
}
