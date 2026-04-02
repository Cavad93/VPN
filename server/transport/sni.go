// Package transport — sni.go implements SNI (Server Name Indication) spoofing
// for the TLS obfuscation layer.
//
// DPI systems often maintain allowlists of trusted hostnames and drop
// connections whose ClientHello SNI extension is absent or unknown.
// By embedding a synthetic SNI for a well-known domain (e.g. www.google.com)
// inside the ClientHello produced by ObfsConn, VPN traffic passes such filters
// without exposing the real destination.
//
// Usage:
//
//	conn := transport.NewObfsConn(raw).WithSNI(transport.NewRandomSNI())
//	if err := conn.ClientHandshake(); err != nil { ... }
//
// The server side performs ServerHandshake() and ignores the SNI value;
// ExtractSNI can be used to inspect or log it for debugging.
package transport

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// defaultSNIDomains is the built-in list of legitimate-looking domains.
// These domains serve enormous global traffic volumes, making DPI fingerprinting
// based on SNI alone ineffective.
var defaultSNIDomains = []string{
	"www.google.com",
	"www.youtube.com",
	"www.cloudflare.com",
	"cdn.cloudflare.com",
	"www.googleapis.com",
	"ajax.googleapis.com",
	"fonts.googleapis.com",
	"clients1.google.com",
	"update.googleapis.com",
	"www.gstatic.com",
}

// SNISelector chooses the hostname to embed in the SNI extension of each
// ClientHello.  Implementations must be safe for concurrent use.
type SNISelector interface {
	// Select returns the hostname to use in the next ClientHello SNI extension.
	Select() string
}

// StaticSNI always returns the same fixed domain.  Useful when the operator
// wants to consistently mimic a single well-known service.
type StaticSNI struct {
	// Domain is the hostname to embed, e.g. "www.google.com".
	Domain string
}

// Select implements SNISelector.
func (s *StaticSNI) Select() string { return s.Domain }

// RandomSNI picks a random hostname from its Domains list on every Select call.
// It is safe for concurrent use; rand.Int is goroutine-safe.
type RandomSNI struct {
	// Domains is the pool of hostnames to choose from.
	Domains []string
}

// NewRandomSNI creates a RandomSNI pre-loaded with the built-in list of
// legitimate-looking domain names.
func NewRandomSNI() *RandomSNI {
	return &RandomSNI{Domains: append([]string(nil), defaultSNIDomains...)}
}

// Select implements SNISelector.  Returns a random element from Domains; falls
// back to "www.google.com" if the list is empty or randomness fails.
func (r *RandomSNI) Select() string {
	if len(r.Domains) == 0 {
		return "www.google.com"
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(r.Domains))))
	if err != nil {
		return r.Domains[0]
	}
	return r.Domains[n.Int64()]
}

// buildSNIExtension encodes a TLS server_name extension (RFC 6066 §3) for host.
//
// Wire layout:
//
//	ext_type   (2 bytes)  — 0x0000 = server_name
//	ext_data_len (2 bytes)
//	  list_len   (2 bytes)
//	    name_type (1 byte) — 0x00 = host_name
//	    name_len  (2 bytes)
//	    name      (N bytes)
func buildSNIExtension(host string) []byte {
	name := []byte(host)
	nameLen := len(name)

	// list entry: name_type(1) + name_len(2) + name
	listEntryLen := 1 + 2 + nameLen
	// extension data: list_len(2) + list_entry
	extDataLen := 2 + listEntryLen

	ext := make([]byte, 0, 4+extDataLen)
	ext = append(ext, 0x00, 0x00)                                  // extension type: server_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(extDataLen))   // extension data length
	ext = binary.BigEndian.AppendUint16(ext, uint16(listEntryLen)) // server name list length
	ext = append(ext, 0x00)                                        // name type: host_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(nameLen))      // name length
	ext = append(ext, name...)                                     // hostname bytes
	return ext
}

// buildSupportedVersionsExtension encodes the supported_versions extension
// (RFC 8446 §4.2.1) advertising TLS 1.3 (0x0304) as the only version.
func buildSupportedVersionsExtension() []byte {
	return []byte{
		0x00, 0x2b, // extension type: supported_versions
		0x00, 0x03, // extension data length: 3
		0x02,       // supported versions list length in bytes: 2
		0x03, 0x04, // TLS 1.3
	}
}

// buildClientHelloWithSNI returns a synthetic TLS 1.3 ClientHello that includes:
//   - server_name extension set to sni
//   - supported_versions extension advertising TLS 1.3
//
// The random and session_id fields are filled with fresh cryptographic randomness
// so every call produces a unique on-wire record.
func buildClientHelloWithSNI(sni string) []byte {
	var random [32]byte
	var sessionID [32]byte
	rand.Read(random[:])    //nolint:errcheck — rand.Read never errors on Linux
	rand.Read(sessionID[:]) //nolint:errcheck

	sniExt := buildSNIExtension(sni)
	verExt := buildSupportedVersionsExtension()
	extensions := append(sniExt, verExt...)

	body := make([]byte, 0, 128+len(extensions))
	body = append(body, 0x03, 0x03)      // legacy_version = TLS 1.2
	body = append(body, random[:]...)    // random (32 bytes)
	body = append(body, 0x20)            // legacy_session_id length = 32
	body = append(body, sessionID[:]...) // legacy_session_id (32 bytes)
	// cipher_suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
	// compression_methods: length=1, null(0x00)
	body = append(body, 0x01, 0x00)
	// extensions
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	return wrapHandshakeRecord(tlsHelloClient, body)
}

// ExtractSNI parses the SNI hostname from the body of a ClientHello handshake
// message.  body must begin immediately after the 4-byte handshake header
// (message type + 3-byte length), i.e. at the legacy_version field.
//
// Returns an empty string if the SNI extension is absent or the record is
// malformed.  This function is useful for server-side logging and debugging.
func ExtractSNI(body []byte) string {
	// Minimum: legacy_version(2) + random(32) + session_id_len(1) = 35 bytes
	if len(body) < 35 {
		return ""
	}

	// Skip legacy_version(2) + random(32) + session_id_len(1) + session_id
	sidLen := int(body[34])
	off := 35 + sidLen
	if off+2 > len(body) {
		return ""
	}

	// Skip cipher_suites
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + csLen
	if off+1 > len(body) {
		return ""
	}

	// Skip compression_methods
	cmLen := int(body[off])
	off += 1 + cmLen

	// Extensions total length
	if off+2 > len(body) {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	end := off + extTotal
	if end > len(body) {
		end = len(body)
	}

	// Scan extensions for server_name (type 0x0000)
	for off+4 <= end {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > end {
			break
		}
		if extType == 0x0000 && extLen >= 5 {
			// server_name data: list_len(2) + name_type(1) + name_len(2) + name
			data := body[off : off+extLen]
			nameLen := int(binary.BigEndian.Uint16(data[3:5]))
			if 5+nameLen <= len(data) {
				return string(data[5 : 5+nameLen])
			}
		}
		off += extLen
	}
	return ""
}
