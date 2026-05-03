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
	"crypto/rand"
	"encoding/binary"
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

// Read satisfies io.Reader. The first call returns ONLY the peeked byte
// without touching the underlying connection.  Subsequent calls delegate
// directly.
//
// We intentionally do NOT attempt to combine the peeked byte with a second
// read from the wire in the same call.  While that would save one Read call,
// it interacts badly with deadline-aware wrappers like idleTimeoutConn:
// the wrapper sets a ReadDeadline before calling Read, and the deadline would
// apply to the wire read, potentially delaying delivery of the already-known
// peeked byte by the full idle timeout.  One extra Read call per connection
// lifetime is negligible.
func (p *peekConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if !p.used {
		p.used = true
		b[0] = p.peeked
		return 1, nil
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
// If kv is nil, delegates to peekAndRoute (backward compatible).
//
// When kv is non-nil, the function reads the first 76 bytes of the stream
// and calls kv.Verify (zero-alloc — HMAC hasher is borrowed from sync.Pool).
// This prevents the relay from connecting to the backend unless the client
// knows the PSK. Allocation-free design means even DDoS flood of bad knocks
// adds zero heap pressure from HMAC state.
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
func peekAndRouteKnock(conn net.Conn, kv *transport.KnockVerifier) (net.Conn, bool) {
	if kv == nil {
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
	if !kv.Verify(buf[:n]) {
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

// ---------------------------------------------------------------------------
// TLS 1.3 fallback records for anti-probing
// ---------------------------------------------------------------------------
//
// When a connection passes the TLS handshake (ObfsConn) but fails Noise
// authentication, the server must behave like a real TLS 1.3 server that
// encountered a fatal error during the post-ServerHello handshake phase.
//
// In real TLS 1.3, all records after ServerHello are encrypted (wrapped in
// application_data records with content type 0x17). A passive observer sees
// only random-looking payloads — our random-filled records are byte-identical
// in distribution.
//
// Scientific basis:
//   - RFC 8446 §5.1: CCS for middlebox compatibility
//   - RFC 8446 §6: alerts after ServerHello encrypted as application_data
//   - TrojanProbe (ScienceDirect 2024): servers that close without sending
//     post-ServerHello records are fingerprinted as proxy/VPN software
//   - Frolov & Wustrow (NDSS 2019): TLS fingerprinting detects missing CCS
// ---------------------------------------------------------------------------

// sendTLS13FallbackRecords writes a realistic TLS 1.3 post-handshake error
// sequence to w. Called when ObfsConn succeeded (ServerHello + CCS were sent)
// but Noise authentication failed.
//
// Wire sequence matches real TLS 1.3 server behavior on handshake error:
//
//	17 03 03 XX XX [random ~280-430 bytes]  — "encrypted" EncryptedExtensions
//	17 03 03 XX XX [random ~1050-2000 bytes] — "encrypted" Certificate
//	17 03 03 XX XX [random ~115-195 bytes]  — "encrypted" CertificateVerify
//	17 03 03 XX XX [random ~52-72 bytes]    — "encrypted" Finished
//	17 03 03 XX XX [random ~19-31 bytes]    — "encrypted" fatal alert
//	[TCP close]
//
// All payloads are crypto/rand — computationally indistinguishable from
// real AEAD ciphertext.
func sendTLS13FallbackRecords(w io.Writer) {
	// "Encrypted" post-handshake records with realistic size distribution.
	// Sizes match nginx/Apache TLS 1.3 traffic patterns.
	sizes := [5]int{
		280 + cryptoRandIntn(150),  // EncryptedExtensions (~280-429)
		1050 + cryptoRandIntn(950), // Certificate (~1050-1999)
		115 + cryptoRandIntn(80),   // CertificateVerify (~115-194)
		52 + cryptoRandIntn(20),    // Finished (~52-71)
		19 + cryptoRandIntn(12),    // Fatal alert (~19-30)
	}
	for _, size := range sizes {
		writeFakeAppDataRecord(w, size)
	}
}

// sendPlaintextTLSAlert writes a plaintext TLS alert record to w.
// Used when the ObfsConn handshake fails BEFORE ServerHello is sent —
// at this point the connection is still in plaintext TLS mode.
//
// A real TLS server that cannot parse the ClientHello sends:
//
//	15 03 03 00 02 02 XX
//	^  ^---^  ^---^  ^  ^-- alert description
//	|  |      |      +--- alert level: fatal (0x02)
//	|  |      +---------- length: 2
//	|  +----------------- version: TLS 1.2 (legacy)
//	+-------------------- content_type: Alert (0x15)
//
// Common descriptions: decode_error(50), handshake_failure(40),
// protocol_version(70), internal_error(80).
func sendPlaintextTLSAlert(w io.Writer, level, desc byte) {
	alert := [7]byte{0x15, 0x03, 0x03, 0x00, 0x02, level, desc}
	w.Write(alert[:]) //nolint:errcheck
}

// writeFakeAppDataRecord writes one TLS application_data record with
// random content. The content is crypto/rand so it's indistinguishable
// from real AEAD-encrypted TLS data.
func writeFakeAppDataRecord(w io.Writer, size int) {
	rec := make([]byte, 5+size)
	rec[0] = 0x17 // application_data
	rec[1] = 0x03
	rec[2] = 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(size))
	rand.Read(rec[5:]) //nolint:errcheck
	w.Write(rec)       //nolint:errcheck
}

// cryptoRandIntn returns a random int in [0, n) using crypto/rand.
// Used for size randomization of fake TLS records.
func cryptoRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var b [2]byte
	rand.Read(b[:]) //nolint:errcheck
	return int(binary.BigEndian.Uint16(b[:])) % n
}
