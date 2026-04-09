// Package transport — knock.go implements Reality-style port knocking via
// HMAC-SHA256 embedded in the TLS ClientHello session_id field.
//
// Design (based on Xray Reality, Frolov & Wustrow NDSS 2019):
//
// The relay authenticates clients BEFORE forwarding to the backend by verifying
// a knock tag in the very first packet. The tag is computed as:
//
//	session_id = HMAC-SHA256(PSK, random)
//
// where:
//   - PSK is a 32-byte pre-shared key known to both client and relay
//   - random is the 32-byte Random field of the same ClientHello
//
// Because HMAC-SHA256 output is computationally indistinguishable from uniform
// random (PRF assumption), the session_id field passes all DPI entropy checks.
// In TLS 1.3, the legacy session_id is specified as opaque random bytes
// (RFC 8446 §4.1.2), so real browsers also fill it with random data — making
// our knock tag invisible to middleboxes.
//
// Replay resistance: each connection uses a fresh random (32 bytes from
// crypto/rand), so the knock tag is unique per connection. A replayed
// ClientHello would need to match both random AND session_id — which only
// works if the exact same bytes are replayed within the TCP connection
// lifetime. The relay can optionally track seen (random, session_id) pairs
// for stronger replay protection, but for our use case the Noise handshake
// on the backend provides definitive replay protection.
//
// Verification requires parsing only the first 76 bytes of the TCP stream:
//
//	[0]      TLS content_type = 0x16
//	[1-2]    TLS version
//	[3-4]    TLS record length
//	[5]      Handshake msg_type = 0x01 (ClientHello)
//	[6-8]    Handshake length
//	[9-10]   ClientHello legacy_version
//	[11-42]  Random (32 bytes)
//	[43]     session_id length (0x20 = 32)
//	[44-75]  session_id (32 bytes)  ← knock tag
package transport

import (
	"crypto/hmac"
	"crypto/sha256"
)

// KnockPSK is a 32-byte pre-shared key for relay port knocking.
type KnockPSK [32]byte

// KnockMinBytes is the minimum number of bytes from the TCP stream needed
// to extract and verify the knock tag (Random + session_id).
const KnockMinBytes = 76

// Byte offsets within the raw TCP stream for the ClientHello fields.
const (
	knockRandomOffset    = 11 // start of Random field
	knockRandomEnd       = 43 // end of Random field (exclusive)
	knockSIDLenOffset    = 43 // session_id_length byte
	knockSessionIDOffset = 44 // start of session_id
	knockSessionIDEnd    = 76 // end of session_id (exclusive)
)

// ComputeKnockTag computes HMAC-SHA256(psk, random) and returns the full
// 32-byte result. This is embedded as the session_id in the ClientHello.
func ComputeKnockTag(psk KnockPSK, random [32]byte) [32]byte {
	mac := hmac.New(sha256.New, psk[:])
	mac.Write(random[:])
	sum := mac.Sum(nil) // 32 bytes
	var tag [32]byte
	copy(tag[:], sum)
	return tag
}

// VerifyKnock checks whether raw TLS ClientHello data contains a valid knock
// tag. data must be at least KnockMinBytes (76) bytes from the start of the
// TCP stream (beginning with the TLS record header).
//
// Returns true if and only if:
//   - data[0] == 0x16 (TLS handshake record)
//   - data[5] == 0x01 (ClientHello message type)
//   - data[43] == 0x20 (session_id length = 32)
//   - data[44:76] == HMAC-SHA256(psk, data[11:43])
func VerifyKnock(psk KnockPSK, data []byte) bool {
	if len(data) < KnockMinBytes {
		return false
	}
	// Structural validation: must be a TLS ClientHello with 32-byte session_id.
	if data[0] != 0x16 || data[5] != 0x01 || data[knockSIDLenOffset] != 0x20 {
		return false
	}

	var random [32]byte
	copy(random[:], data[knockRandomOffset:knockRandomEnd])

	expected := ComputeKnockTag(psk, random)
	return hmac.Equal(expected[:], data[knockSessionIDOffset:knockSessionIDEnd])
}
