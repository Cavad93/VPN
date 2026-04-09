// Package main — decoy.go implements active-probe protection for the VPN server.
//
// When an external scanner or DPI probe connects to the VPN port, it sends
// data that does NOT start with a TLS Handshake record (0x16). This module
// intercepts such connections BEFORE the ObfsConn handshake and routes them
// to the cover website (a realistic cooking blog served from cover.go).
//
// Decision tree (based on first byte only, zero overhead for real clients):
//
//	first byte == 0x16  →  VPN path (TLS ClientHello, ObfsConn takes over)
//	first byte == other →  cover website (full HTTP handler) + close
//	no data (timeout)   →  close silently
//
// Anti-probing design (based on Trojan-GFW approach):
//   - Non-TLS connections get a full cover website with multiple pages,
//     internal links, and realistic content — not just a 400 error.
//   - All handshake failures (ObfsConn, Noise) are logged at DEBUG level
//     to avoid exposing VPN presence in logs during mass scanning.
//   - The cover site uses standard http.Handler, making it indistinguishable
//     from a real nginx-backed website to automated scanners.
//
// peekConn prepends the already-consumed first byte back into the read stream
// so the rest of the handshake pipeline (BufConn → ObfsConn → Noise) never
// knows that peeking happened.
package main

import (
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/cavad93/vpn/server/transport"
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

// prefixConn wraps a net.Conn and prepends a multi-byte prefix that was
// already consumed (e.g. during knock verification) back into the read stream.
// All net.Conn methods except Read are forwarded unchanged.
type prefixConn struct {
	net.Conn
	prefix []byte
	offset int
}

// Read satisfies io.Reader. Returns buffered prefix bytes first, then
// delegates to the underlying connection.
func (p *prefixConn) Read(b []byte) (int, error) {
	if p.offset < len(p.prefix) {
		n := copy(b, p.prefix[p.offset:])
		p.offset += n
		return n, nil
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
//     already served the cover website and closed the connection.
//     Caller must not touch conn.
func peekAndRoute(conn net.Conn) (net.Conn, bool) {
	// Give the client a short window to send its first byte.
	_ = conn.SetReadDeadline(time.Now().Add(decoyReadDeadline()))

	var first [1]byte
	if _, err := conn.Read(first[:]); err != nil {
		// No data arrived (timeout, reset, etc.) — close silently.
		// No logging: SYN-only probes are routine noise and MUST NOT appear
		// in logs to avoid fingerprinting the server as a VPN.
		conn.Close()
		return nil, false
	}

	// Clear the read deadline so the rest of the pipeline is unaffected.
	_ = conn.SetReadDeadline(time.Time{})

	if first[0] == tlsHandshakeRecordType {
		// Looks like a TLS ClientHello — let the VPN pipeline handle it.
		return &peekConn{Conn: conn, peeked: first[0]}, true
	}

	// Not a VPN client. Serve the full cover website (cooking blog).
	// This makes the server indistinguishable from a real HTTP website
	// to DPI scanners and active probes. The cover site has multiple
	// pages (/recipe1, /recipe2, /contacts, /about) with internal links,
	// increasing scanner confidence that this is a legitimate web server.
	serveCoverSiteFromPeeked(conn, first[0])
	return nil, false
}

// peekAndRouteKnock is like peekAndRoute but additionally verifies a
// Reality-style port-knock tag embedded in the TLS ClientHello's session_id.
//
// If knockKey is nil, delegates to peekAndRoute (backward compatible).
//
// When knockKey is set, the function reads the first 76 bytes of the stream
// and verifies session_id == HMAC-SHA256(knockKey, random). This prevents
// the relay from connecting to the backend unless the client knows the PSK.
//
// Decision tree:
//
//	first byte != 0x16        → serve cover website (HTTP scanner)
//	first byte == 0x16, HMAC matches → forward to upstream (VPN client)
//	first byte == 0x16, HMAC fails   → close silently (DPI probe / replay)
//
// The "close silently" for failed TLS knock mimics a server that dropped the
// connection due to handshake failure — a common behavior for misconfigured
// TLS endpoints, revealing no information about the relay's purpose.
func peekAndRouteKnock(conn net.Conn, knockKey *transport.KnockPSK) (net.Conn, bool) {
	if knockKey == nil {
		return peekAndRoute(conn)
	}

	// Give the client time to send the ClientHello header.
	_ = conn.SetReadDeadline(time.Now().Add(decoyReadDeadline()))

	// Read the minimum bytes needed to verify the knock.
	var buf [transport.KnockMinBytes]byte
	n, err := io.ReadFull(conn, buf[:])
	if err != nil {
		if n > 0 && buf[0] != tlsHandshakeRecordType {
			// Got some non-TLS bytes — serve cover site with what we have.
			serveCoverSiteFromPrefix(conn, buf[:n])
			return nil, false
		}
		// Not enough data or read error — close silently.
		conn.Close()
		return nil, false
	}

	// Clear the read deadline.
	_ = conn.SetReadDeadline(time.Time{})

	// Non-TLS: serve cover website.
	if buf[0] != tlsHandshakeRecordType {
		serveCoverSiteFromPrefix(conn, buf[:n])
		return nil, false
	}

	// TLS ClientHello — verify knock.
	if !transport.VerifyKnock(*knockKey, buf[:n]) {
		// Knock failed: a DPI probe or replayed ClientHello.
		// Close silently — no information leakage.
		conn.Close()
		return nil, false
	}

	// Knock verified. Wrap in prefixConn so the upstream sees the full stream.
	peeked := make([]byte, n)
	copy(peeked, buf[:n])
	return &prefixConn{Conn: conn, prefix: peeked}, true
}

// serveCoverSiteFromPrefix serves the cover website on a connection where
// multiple bytes have already been consumed (e.g. during knock verification).
// The prefix bytes are replayed before the remaining connection data.
func serveCoverSiteFromPrefix(conn net.Conn, prefix []byte) {
	pc := &prefixConn{Conn: conn, prefix: prefix}
	_ = pc.SetReadDeadline(time.Time{})
	serveCoverSite(pc)
}
