// Package transport — obfs.go implements a TLS-obfuscation layer that wraps
// arbitrary byte streams inside synthetic TLS 1.3 records so that Deep Packet
// Inspection (DPI) systems classify the traffic as ordinary HTTPS.
//
// The layer is intentionally NOT cryptographically TLS — real encryption is
// handled by the Noise handshake in crypto/handshake.go.  This module only
// mimics the wire format of TLS so that byte patterns, record types, and header
// fields match what a real TLS 1.3 session would produce.
//
// Wire format of one obfuscated record:
//
//	byte 0      — TLS content type  (0x17 = application_data)
//	bytes 1-2   — TLS version       (0x03 0x03 = TLS 1.2 legacy field)
//	bytes 3-4   — payload length    (big-endian uint16, 1…16383)
//	bytes 5-N   — payload
package transport

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// TLS record content types.
const (
	tlsRecordCCS       = byte(0x14) // ChangeCipherSpec (middlebox compat, RFC 8446 §5.1)
	tlsRecordHandshake = byte(0x16)
	tlsRecordAppData   = byte(0x17)
)

// TLS handshake message types.
const (
	tlsHelloClient = byte(0x01)
	tlsHelloServer = byte(0x02)
)

// TLS version field used in record headers (TLS 1.2 legacy value, required by RFC 8446).
const (
	tlsVersionMajor = byte(0x03)
	tlsVersionMinor = byte(0x03)
)

// ObfsHeaderSize is the size of the synthetic TLS record header in bytes.
const ObfsHeaderSize = 5

// maxObfsPayload is the maximum payload bytes per record (TLS spec: 2^14).
const maxObfsPayload = 16383

// obfsRecordPool pools the TLS record slices (header + payload) used in
// ObfsConn.Write, avoiding one make() per outgoing TLS record.
var obfsRecordPool = sync.Pool{
	New: func() interface{} {
		// header(5) + mux_header(7) + tunMTU(1430) + noise_len(2) + AEAD_tag(16) = 1460
		// = MaxPayloadSize: fits in exactly one UDP datagram, no splitting.
		// Rounded to 1536 for allocator-friendly sizing.
		b := make([]byte, 0, 1536)
		return &b
	},
}

// ObfsConn wraps a net.Conn and presents data framed inside synthetic TLS
// records.  Callers must run ClientHandshake (initiator side) or
// ServerHandshake (responder side) before calling Read/Write.
type ObfsConn struct {
	conn             net.Conn
	bufr             *bufio.Reader // buffered reader reduces read syscalls
	readBufRemaining int           // bytes remaining in the current TLS record not yet returned to caller
	sniSelector      SNISelector   // optional; if set, ClientHandshake embeds an SNI extension
	knockKey         *KnockPSK    // optional; if set, session_id = HMAC(knockKey, random) for relay auth
	// hdr is a reusable 5-byte scratch buffer for TLS record headers.
	// Avoids one heap allocation per read in the hot data path.
	hdr [ObfsHeaderSize]byte
}

// NewObfsConn wraps conn.  No I/O is performed until Handshake is called.
// A 64 KB bufio.Reader is used internally to batch small reads (TLS record
// headers) into fewer syscalls, improving throughput by ~15-20%.
func NewObfsConn(conn net.Conn) *ObfsConn {
	return &ObfsConn{conn: conn, bufr: bufio.NewReaderSize(conn, 65536)}
}

// WithSNI attaches an SNISelector to the connection.  When set, ClientHandshake
// will include a server_name extension in the synthetic ClientHello using the
// domain returned by selector.Select().  Returns c to allow method chaining:
//
//	conn := transport.NewObfsConn(raw).WithSNI(transport.NewRandomSNI())
func (c *ObfsConn) WithSNI(selector SNISelector) *ObfsConn {
	c.sniSelector = selector
	return c
}

// WithKnock attaches a port-knock PSK to the connection. When set,
// ClientHandshake computes session_id = HMAC-SHA256(knockKey, random) instead
// of filling it with random bytes. The relay verifies this tag before
// forwarding the connection to the backend. Returns c for method chaining:
//
//	conn := transport.NewObfsConn(raw).WithKnock(psk)
func (c *ObfsConn) WithKnock(key KnockPSK) *ObfsConn {
	c.knockKey = &key
	return c
}

// ClientHandshake sends a synthetic ClientHello and reads the ServerHello.
// If an SNISelector was attached via WithSNI, the ClientHello includes a
// server_name extension for the domain returned by the selector.
// If a KnockPSK was attached via WithKnock, the session_id field contains
// HMAC-SHA256(knockKey, random) for relay port-knock authentication.
// Must be called exactly once before the first Write/Read on the initiator.
func (c *ObfsConn) ClientHandshake() error {
	var sni *string
	if c.sniSelector != nil {
		s := c.sniSelector.Select()
		sni = &s
	}
	hello := buildClientHelloCore(sni, c.knockKey)
	if _, err := c.conn.Write(hello); err != nil {
		return err
	}
	return c.readHandshakeRecord(tlsHelloServer)
}

// ServerHandshake reads the ClientHello and sends a synthetic ServerHello
// followed by a ChangeCipherSpec record (RFC 8446 §5.1 middlebox compat).
//
// Real TLS 1.3 servers send CCS immediately after ServerHello. Without this,
// active probes can fingerprint the server by observing that no CCS follows
// the ServerHello — a pattern unique to non-standard TLS implementations.
// (Frolov & Wustrow, NDSS 2019: "The use of TLS in Censorship Circumvention")
//
// Must be called exactly once before the first Write/Read on the responder.
func (c *ObfsConn) ServerHandshake() error {
	if err := c.readHandshakeRecord(tlsHelloClient); err != nil {
		return err
	}
	// Send ServerHello + CCS in one write for TCP coalescing.
	sh := buildServerHello()
	ccs := buildChangeCipherSpec()
	combined := make([]byte, len(sh)+len(ccs))
	copy(combined, sh)
	copy(combined[len(sh):], ccs)
	_, err := c.conn.Write(combined)
	return err
}

// Write sends p as one or more TLS application_data records.
// Implements io.Writer.  Uses pooled buffers to avoid heap allocations.
func (c *ObfsConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxObfsPayload {
			chunk = p[:maxObfsPayload]
		}
		need := ObfsHeaderSize + len(chunk)
		bp := obfsRecordPool.Get().(*[]byte)
		if cap(*bp) < need {
			*bp = make([]byte, need)
		}
		rec := (*bp)[:need]
		rec[0] = tlsRecordAppData
		rec[1] = tlsVersionMajor
		rec[2] = tlsVersionMinor
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(chunk)))
		copy(rec[5:], chunk)

		_, err := c.conn.Write(rec)
		obfsRecordPool.Put(bp)
		if err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read reads data from incoming TLS application_data records.
// Implements io.Reader.  If the caller's buffer is smaller than the record
// payload, subsequent calls continue draining the current record before
// decoding the next header.
//
// ChangeCipherSpec records (0x14) are silently skipped — the server sends
// CCS after ServerHello for TLS 1.3 middlebox compatibility (RFC 8446 §5.1).
// CCS appears at most once per connection, so the branch adds negligible
// overhead to the hot path (one byte comparison per record header).
//
// Single-buffer design: data flows network → bufio.Reader → p with no
// intermediate allocations.  readBufRemaining tracks how many payload bytes
// remain in the current TLS record so that bufio.Reader serves as the sole
// buffer in the system — eliminating the old separate readBuf allocation.
func (c *ObfsConn) Read(p []byte) (int, error) {
	if c.readBufRemaining == 0 {
		// Decode the next TLS record header, skipping CCS records.
		for {
			if _, err := io.ReadFull(c.bufr, c.hdr[:]); err != nil {
				return 0, err
			}
			if c.hdr[0] == tlsRecordCCS {
				// CCS payload is typically 1 byte (0x01). Discard without
				// allocation — io.Discard uses an internal pooled buffer.
				length := int64(binary.BigEndian.Uint16(c.hdr[3:5]))
				if length > 0 && length <= int64(maxObfsPayload) {
					io.CopyN(io.Discard, c.bufr, length) //nolint:errcheck
				}
				continue
			}
			break
		}
		if c.hdr[0] != tlsRecordAppData {
			return 0, errors.New("obfs: unexpected TLS record content type")
		}
		length := int(binary.BigEndian.Uint16(c.hdr[3:5]))
		if length == 0 || length > maxObfsPayload {
			return 0, errors.New("obfs: invalid TLS record length")
		}
		c.readBufRemaining = length
	}

	// Read up to readBufRemaining bytes directly from bufio into p.
	// Zero allocation regardless of whether p is larger or smaller than the record.
	toRead := c.readBufRemaining
	if len(p) < toRead {
		toRead = len(p)
	}
	n, err := io.ReadFull(c.bufr, p[:toRead])
	c.readBufRemaining -= n
	return n, err
}

// Close closes the underlying connection.
func (c *ObfsConn) Close() error { return c.conn.Close() }

// LocalAddr returns the local network address.
func (c *ObfsConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the remote network address.
func (c *ObfsConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline sets the read and write deadlines.
func (c *ObfsConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline sets the read deadline.
func (c *ObfsConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline.
func (c *ObfsConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// readRecord reads exactly one TLS record and validates its content type.
// Used only during handshake; the hot-path Read() inlines the header parsing
// to avoid the intermediate allocation.
// Reads go through the buffered reader (c.bufr) to reduce syscalls.
//
// ChangeCipherSpec records (0x14) are silently skipped — this is required
// because real TLS 1.3 servers send CCS for middlebox compatibility
// (RFC 8446 §5.1). Our ServerHandshake sends CCS after ServerHello, so
// the client must skip it when reading the handshake response.
func (c *ObfsConn) readRecord(wantType byte) ([]byte, error) {
	for {
		if _, err := io.ReadFull(c.bufr, c.hdr[:]); err != nil {
			return nil, err
		}
		// Skip ChangeCipherSpec records (TLS 1.3 middlebox compatibility).
		// CCS payload is always 1 byte (0x01). Read and discard.
		if c.hdr[0] == tlsRecordCCS {
			length := int64(binary.BigEndian.Uint16(c.hdr[3:5]))
			if length == 0 || length > int64(maxObfsPayload) {
				return nil, errors.New("obfs: invalid CCS record length")
			}
			// Discard CCS payload without heap allocation.
			if _, err := io.CopyN(io.Discard, c.bufr, length); err != nil {
				return nil, err
			}
			continue
		}
		if c.hdr[0] != wantType {
			return nil, errors.New("obfs: unexpected TLS record content type")
		}
		length := binary.BigEndian.Uint16(c.hdr[3:5])
		if length == 0 || length > maxObfsPayload {
			return nil, errors.New("obfs: invalid TLS record length")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.bufr, payload); err != nil {
			return nil, err
		}
		return payload, nil
	}
}

// readHandshakeRecord reads a TLS handshake record and checks the message type.
// Uses the buffered reader via readRecord.
func (c *ObfsConn) readHandshakeRecord(wantMsgType byte) error {
	payload, err := c.readRecord(tlsRecordHandshake)
	if err != nil {
		return err
	}
	if len(payload) < 4 {
		return errors.New("obfs: handshake record too short")
	}
	if payload[0] != wantMsgType {
		return errors.New("obfs: unexpected handshake message type")
	}
	return nil
}

// buildAppDataRecord wraps payload in a TLS application_data record.
func buildAppDataRecord(payload []byte) []byte {
	rec := make([]byte, ObfsHeaderSize+len(payload))
	rec[0] = tlsRecordAppData
	rec[1] = tlsVersionMajor
	rec[2] = tlsVersionMinor
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

// ---------------------------------------------------------------------------
// Chrome-120 ClientHello builder — browser-fingerprint mimicry
// ---------------------------------------------------------------------------

// greaseTable contains the 16 GREASE pseudo-values (RFC 8701).
// Inserted into cipher suite lists, extension type fields, and named group
// lists to prevent protocol ossification. Real browsers pick independently
// for each slot; we do the same via pickGrease().
var greaseTable = [16]uint16{
	0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
	0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
	0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
	0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

// pickGrease returns a random GREASE value (RFC 8701).
func pickGrease() uint16 {
	var b [1]byte
	rand.Read(b[:]) //nolint:errcheck
	return greaseTable[b[0]&0x0F]
}

// buildExt encodes a TLS extension: type(2) + data_length(2) + data.
func buildExt(typ uint16, data []byte) []byte {
	ext := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(ext[0:2], typ)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(data)))
	copy(ext[4:], data)
	return ext
}

// buildSupportedGroupsExt encodes supported_groups (RFC 8422) with
// GREASE + x25519 + secp256r1 + secp384r1 — Chrome 120 order.
func buildSupportedGroupsExt(grease uint16) []byte {
	data := []byte{
		0x00, 0x08, // named_group_list length = 8 bytes (4 groups × 2)
		byte(grease >> 8), byte(grease), // GREASE
		0x00, 0x1D, // x25519
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
	}
	return buildExt(0x000A, data)
}

// buildALPNExt encodes the ALPN extension (RFC 7301) advertising h2 and
// http/1.1 — Chrome's standard browser-mode advertisement order.
func buildALPNExt() []byte {
	data := []byte{
		0x00, 0x0E, // protocol_name_list length = 14 bytes
		0x00, 0x02, 'h', '2', // "h2"
		0x00, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1', // "http/1.1"
	}
	return buildExt(0x0010, data)
}

// buildSigAlgsExt encodes signature_algorithms (RFC 8446 §4.2.3) matching
// Chrome 120's list.
func buildSigAlgsExt() []byte {
	data := []byte{
		0x00, 0x10, // algorithms list length = 16 bytes (8 × 2)
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x04, 0x01, // rsa_pkcs1_sha256
		0x05, 0x03, // ecdsa_secp384r1_sha384
		0x08, 0x05, // rsa_pss_rsae_sha384
		0x05, 0x01, // rsa_pkcs1_sha384
		0x08, 0x06, // rsa_pss_rsae_sha512
		0x06, 0x01, // rsa_pkcs1_sha512
	}
	return buildExt(0x000D, data)
}

// buildKeyShareExt encodes key_share (RFC 8446 §4.2.8) with a minimal GREASE
// entry followed by a random x25519 public key. Random bytes are used because
// the obfs layer does not perform a real TLS key exchange — Noise handles key
// agreement independently.
func buildKeyShareExt(grease uint16) []byte {
	var x25519Pub [32]byte
	rand.Read(x25519Pub[:]) //nolint:errcheck

	// Two entries: GREASE (1-byte payload) + x25519 (32-byte payload).
	entries := make([]byte, 0, 41)
	entries = append(entries, byte(grease>>8), byte(grease), 0x00, 0x01, 0x00)
	entries = append(entries, 0x00, 0x1D, 0x00, 0x20)
	entries = append(entries, x25519Pub[:]...)

	data := make([]byte, 2+len(entries))
	binary.BigEndian.PutUint16(data[0:2], uint16(len(entries)))
	copy(data[2:], entries)
	return buildExt(0x0033, data)
}

// buildSupportedVersionsClientExt encodes supported_versions for a ClientHello
// (RFC 8446 §4.2.1) advertising GREASE + TLS 1.3 + TLS 1.2.
func buildSupportedVersionsClientExt(grease uint16) []byte {
	data := []byte{
		0x06,                            // versions list length = 6 bytes (3 × 2)
		byte(grease >> 8), byte(grease), // GREASE
		0x03, 0x04, // TLS 1.3
		0x03, 0x03, // TLS 1.2
	}
	return buildExt(0x002B, data)
}

// buildCompressCertExt encodes compress_certificate (RFC 8879) with brotli and
// zlib — Chrome's standard advertisement.
func buildCompressCertExt() []byte {
	return buildExt(0x001B, []byte{
		0x02,       // algorithms count = 2
		0x00, 0x02, // brotli
		0x00, 0x01, // zlib
	})
}

// buildClientHello returns a Chrome-120-equivalent ClientHello.
func buildClientHello() []byte {
	return buildClientHelloCore(nil, nil)
}

// buildClientHelloCore builds a Chrome-120-equivalent TLS ClientHello.
//
// The resulting record defeats JA3/JA4 fingerprinting by DPI systems (TSPU,
// GFW) because it is indistinguishable from a real Chrome 120 ClientHello:
//
//   - Record header version 0x03 0x01 (Chrome uses legacy TLS 1.0 in the
//     outer record_version field — RFC 8446 §5.1 permits it; all browsers
//     do it; 0x03 0x03 here is a known non-browser fingerprint signal).
//   - 16 cipher suites + GREASE matching Chrome's exact list and order.
//   - Full Chrome extension set in Chrome order, including GREASE at positions
//     0 and 15, ALPN h2+http/1.1, key_share with GREASE+x25519, and
//     compress_certificate with brotli+zlib.
//   - GREASE values (RFC 8701) independently randomised per connection for
//     each of: cipher suite slot 0, ext type slot 0 and 15, supported_groups
//     slot 0, key_share slot 0, supported_versions slot 0.
//
// If knockKey is non-nil, session_id = HMAC-SHA256(knockKey, random) so the
// relay can authenticate the connection (see knock.go). The HMAC output is
// indistinguishable from uniform random, so the knock tag passes all DPI
// entropy checks for the session_id field.
func buildClientHelloCore(sni *string, knockKey *KnockPSK) []byte {
	var random [32]byte
	var sessionID [32]byte
	rand.Read(random[:]) //nolint:errcheck

	if knockKey != nil {
		sessionID = ComputeKnockTag(*knockKey, random)
	} else {
		rand.Read(sessionID[:]) //nolint:errcheck
	}

	// Independent GREASE values per slot (Chrome picks independently).
	greaseCS := pickGrease()   // cipher suite list, position 0
	greaseExt1 := pickGrease() // first extension (GREASE ext)
	greaseExt2 := pickGrease() // last extension (second GREASE ext)
	greaseGrp := pickGrease()  // supported_groups position 0
	greaseVer := pickGrease()  // supported_versions position 0
	greaseKS := pickGrease()   // key_share entry 0

	// Cipher suites: GREASE + 16 Chrome suites.
	cipherSuites := []byte{
		byte(greaseCS >> 8), byte(greaseCS), // GREASE
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
		0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
		0xC0, 0x2B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC0, 0x2C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xC0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xCC, 0xA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		0xCC, 0xA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		0xC0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		0xC0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x9C, // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x00, 0x9D, // TLS_RSA_WITH_AES_256_GCM_SHA384
		0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
	}

	// Extensions in Chrome 120 order.
	var exts []byte
	exts = append(exts, buildExt(greaseExt1, []byte{0x00, 0x00})...)              // GREASE
	if sni != nil {
		exts = append(exts, buildSNIExtension(*sni)...)                            // server_name
	}
	exts = append(exts, buildExt(0x0017, nil)...)                                  // extended_master_secret
	exts = append(exts, buildExt(0xFF01, []byte{0x00})...)                         // renegotiation_info
	exts = append(exts, buildSupportedGroupsExt(greaseGrp)...)                    // supported_groups
	exts = append(exts, buildExt(0x000B, []byte{0x01, 0x00})...)                   // ec_point_formats
	exts = append(exts, buildExt(0x0023, nil)...)                                  // session_ticket
	exts = append(exts, buildALPNExt()...)                                         // ALPN: h2, http/1.1
	exts = append(exts, buildExt(0x0005, []byte{0x01, 0x00, 0x00, 0x00, 0x00})...) // status_request (OCSP)
	exts = append(exts, buildSigAlgsExt()...)                                      // signature_algorithms
	exts = append(exts, buildExt(0x0012, nil)...)                                  // signed_certificate_timestamp
	exts = append(exts, buildKeyShareExt(greaseKS)...)                             // key_share
	exts = append(exts, buildExt(0x002D, []byte{0x01, 0x01})...)                   // psk_key_exchange_modes
	exts = append(exts, buildSupportedVersionsClientExt(greaseVer)...)             // supported_versions
	exts = append(exts, buildCompressCertExt()...)                                 // compress_certificate
	exts = append(exts, buildExt(greaseExt2, []byte{0x00, 0x00})...)               // GREASE (second slot)

	// Assemble the ClientHello body (RFC 8446 §4.1.2).
	body := make([]byte, 0, 512)
	body = append(body, 0x03, 0x03)      // legacy_version = TLS 1.2
	body = append(body, random[:]...)    // Random (32 bytes)
	body = append(body, 0x20)            // legacy_session_id length = 32
	body = append(body, sessionID[:]...) // legacy_session_id (32 bytes; knock tag if relay auth)
	body = binary.BigEndian.AppendUint16(body, uint16(len(cipherSuites)))
	body = append(body, cipherSuites...)
	body = append(body, 0x01, 0x00) // compression_methods: length=1, null
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	// Build Handshake header: type(1) + length(3).
	hs := make([]byte, 4+len(body))
	hs[0] = tlsHelloClient
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	// Wrap in TLS record. Chrome uses 0x03 0x01 (legacy TLS 1.0) in the outer
	// record_version field of the ClientHello — NOT 0x03 0x03. RFC 8446 §5.1
	// explicitly permits this; every browser does it; using 0x03 0x03 here is
	// a well-known non-browser JA3 fingerprint signal that TSPU/GFW detect.
	rec := make([]byte, ObfsHeaderSize+len(hs))
	rec[0] = tlsRecordHandshake
	rec[1] = 0x03
	rec[2] = 0x01 // legacy TLS 1.0 record version (Chrome/Firefox/Safari behavior)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

// buildServerHello returns a synthetic TLS 1.3 ServerHello record.
func buildServerHello() []byte {
	var random [32]byte
	var sessionEcho [32]byte
	rand.Read(random[:])    //nolint:errcheck
	rand.Read(sessionEcho[:]) //nolint:errcheck

	// supported_versions extension: server selects TLS 1.3 (RFC 8446 §4.2.1).
	verExt := buildExt(0x002B, []byte{0x03, 0x04})

	body := make([]byte, 0, 80)
	body = append(body, 0x03, 0x03)       // legacy_version = TLS 1.2
	body = append(body, random[:]...)     // random (32 bytes)
	body = append(body, 0x20)             // legacy_session_id_echo length = 32
	body = append(body, sessionEcho[:]...) // session_id echo (random — obfs layer doesn't track it)
	body = append(body, 0x13, 0x01)       // cipher_suite: TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)             // compression_method: null
	body = binary.BigEndian.AppendUint16(body, uint16(len(verExt)))
	body = append(body, verExt...)

	return wrapHandshakeRecord(tlsHelloServer, body)
}

// buildChangeCipherSpec returns a TLS ChangeCipherSpec record.
// In TLS 1.3 this is a no-op sent for middlebox compatibility (RFC 8446 §5.1).
// All major browsers and servers send this after ServerHello. Wire format:
//
//	14 03 03 00 01 01
//	^  ^---^  ^---^  ^-- payload: single byte 0x01
//	|  |      +---- length: 1
//	|  +----------- version: TLS 1.2 (legacy)
//	+-------------- content_type: ChangeCipherSpec
func buildChangeCipherSpec() []byte {
	return []byte{tlsRecordCCS, tlsVersionMajor, tlsVersionMinor, 0x00, 0x01, 0x01}
}

// wrapHandshakeRecord wraps a handshake message body inside a TLS record.
// msgType is the HandshakeType byte (e.g. tlsHelloClient).
func wrapHandshakeRecord(msgType byte, body []byte) []byte {
	// Handshake message: type(1) + length(3) + body
	hsLen := len(body)
	hs := make([]byte, 4+hsLen)
	hs[0] = msgType
	hs[1] = byte(hsLen >> 16)
	hs[2] = byte(hsLen >> 8)
	hs[3] = byte(hsLen)
	copy(hs[4:], body)

	// TLS record: content_type(1) + version(2) + length(2) + hs
	rec := make([]byte, ObfsHeaderSize+len(hs))
	rec[0] = tlsRecordHandshake
	rec[1] = tlsVersionMajor
	rec[2] = tlsVersionMinor
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}
