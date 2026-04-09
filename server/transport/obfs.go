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

// buildClientHello returns a synthetic TLS 1.3 ClientHello record.
// The 32-byte random and 32-byte session_id are filled with fresh random bytes
// so that every connection produces a unique on-wire byte sequence.
// Use NewObfsConn(conn).WithSNI(selector) to add an SNI extension.
func buildClientHello() []byte {
	return buildClientHelloCore(nil, nil)
}

// buildClientHelloCore is the unified builder for ClientHello records.
// If sni is non-nil, SNI and supported_versions extensions are included.
// If knockKey is non-nil, session_id = HMAC-SHA256(knockKey, random) for
// relay port-knock authentication (Reality-style, see knock.go).
func buildClientHelloCore(sni *string, knockKey *KnockPSK) []byte {
	var random [32]byte
	var sessionID [32]byte
	rand.Read(random[:]) //nolint:errcheck — rand.Read never errors on Linux

	if knockKey != nil {
		sessionID = ComputeKnockTag(*knockKey, random)
	} else {
		rand.Read(sessionID[:]) //nolint:errcheck
	}

	// Construct the ClientHello body following RFC 8446 §4.1.2 (simplified).
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)      // legacy_version = TLS 1.2
	body = append(body, random[:]...)    // random (32 bytes)
	body = append(body, 0x20)            // legacy_session_id length = 32
	body = append(body, sessionID[:]...) // legacy_session_id
	// cipher_suites: TLS_AES_128_GCM_SHA256(0x1301), TLS_AES_256_GCM_SHA384(0x1302),
	//               TLS_CHACHA20_POLY1305_SHA256(0x1303)
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
	body = append(body, 0x01, 0x00) // compression_methods: length=1, null

	if sni != nil {
		sniExt := buildSNIExtension(*sni)
		verExt := buildSupportedVersionsExtension()
		extensions := append(sniExt, verExt...)
		body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
		body = append(body, extensions...)
	}

	return wrapHandshakeRecord(tlsHelloClient, body)
}

// buildServerHello returns a synthetic TLS 1.3 ServerHello record.
func buildServerHello() []byte {
	var random [32]byte
	rand.Read(random[:]) //nolint:errcheck

	body := make([]byte, 0, 40)
	body = append(body, 0x03, 0x03)   // legacy_version = TLS 1.2
	body = append(body, random[:]...) // random (32 bytes)
	body = append(body, 0x00)         // legacy_session_id_echo length = 0
	body = append(body, 0x13, 0x01)   // cipher_suite: TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)         // compression_method: null

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
