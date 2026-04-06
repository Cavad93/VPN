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

// ClientHandshake sends a synthetic ClientHello and reads the ServerHello.
// If an SNISelector was attached via WithSNI, the ClientHello includes a
// server_name extension for the domain returned by the selector.
// Must be called exactly once before the first Write/Read on the initiator.
func (c *ObfsConn) ClientHandshake() error {
	var hello []byte
	if c.sniSelector != nil {
		hello = buildClientHelloWithSNI(c.sniSelector.Select())
	} else {
		hello = buildClientHello()
	}
	if _, err := c.conn.Write(hello); err != nil {
		return err
	}
	return c.readHandshakeRecord(tlsHelloServer)
}

// ServerHandshake reads the ClientHello and sends a synthetic ServerHello.
// Must be called exactly once before the first Write/Read on the responder.
func (c *ObfsConn) ServerHandshake() error {
	if err := c.readHandshakeRecord(tlsHelloClient); err != nil {
		return err
	}
	_, err := c.conn.Write(buildServerHello())
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
// Single-buffer design: data flows network → bufio.Reader → p with no
// intermediate allocations.  readBufRemaining tracks how many payload bytes
// remain in the current TLS record so that bufio.Reader serves as the sole
// buffer in the system — eliminating the old separate readBuf allocation.
func (c *ObfsConn) Read(p []byte) (int, error) {
	if c.readBufRemaining == 0 {
		// Decode the next TLS record header.
		if _, err := io.ReadFull(c.bufr, c.hdr[:]); err != nil {
			return 0, err
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
func (c *ObfsConn) readRecord(wantType byte) ([]byte, error) {
	if _, err := io.ReadFull(c.bufr, c.hdr[:]); err != nil {
		return nil, err
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
	var random [32]byte
	var sessionID [32]byte
	rand.Read(random[:])    //nolint:errcheck — rand.Read never errors on Linux
	rand.Read(sessionID[:]) //nolint:errcheck

	// Construct the ClientHello body following RFC 8446 §4.1.2 (simplified).
	body := make([]byte, 0, 100)
	body = append(body, 0x03, 0x03)      // legacy_version = TLS 1.2
	body = append(body, random[:]...)    // random (32 bytes)
	body = append(body, 0x20)            // legacy_session_id length = 32
	body = append(body, sessionID[:]...) // legacy_session_id
	// cipher_suites: TLS_AES_128_GCM_SHA256(0x1301), TLS_AES_256_GCM_SHA384(0x1302),
	//               TLS_CHACHA20_POLY1305_SHA256(0x1303)
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
	body = append(body, 0x01, 0x00) // compression_methods: length=1, null

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
