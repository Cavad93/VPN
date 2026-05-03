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
	"hash"
	"sync"
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
//
// Sum(tag[:0]) appends the 32-byte digest into the backing array of the
// stack-allocated tag — cap(tag[:0]) == 32 == sha256.Size, so no heap
// allocation occurs. This replaces the two-step Sum(nil)+copy pattern.
func ComputeKnockTag(psk KnockPSK, random [32]byte) [32]byte {
	mac := hmac.New(sha256.New, psk[:])
	mac.Write(random[:])
	var tag [32]byte
	mac.Sum(tag[:0]) // write directly into tag's backing array; zero heap alloc
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
//
// Note: this function allocates a new HMAC hasher on every call (~8 allocs,
// 576 B/op). Use KnockVerifier.Verify for the hot path (relay mode) where
// zero-alloc verification is required under high connection rates.
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

// KnockVerifier holds a pool of pre-keyed HMAC-SHA256 hash states for
// zero-alloc knock tag verification under high connection rates.
//
// Create once with NewKnockVerifier (cheap: allocates pool infrastructure only)
// and reuse across goroutines — the internal sync.Pool handles concurrent access.
// Each Verify call borrows a ready-to-use HMAC hasher from the pool, resets it
// (O(1): clears the SHA-256 accumulator, restores the pre-computed key pads),
// computes the tag, and returns the hasher to the pool.
//
// Alloc profile under pool steady-state: 0 allocs/op vs 8 allocs/576 B for
// the non-pooled VerifyKnock. At 10 000 knock verifications/sec (e.g. during
// a DDoS scan) the savings are ~80 000 allocs/sec and ~5.5 MB/sec heap pressure.
type KnockVerifier struct {
	pool sync.Pool
}

// NewKnockVerifier returns a KnockVerifier keyed to psk.
// The returned verifier is safe for concurrent use.
func NewKnockVerifier(psk KnockPSK) *KnockVerifier {
	v := &KnockVerifier{}
	// Capture psk by value in the closure — pool.New is called when the pool
	// is empty (e.g. first Verify call per goroutine). The closure allocates
	// a new HMAC hasher on demand and pre-computes the key pads once.
	v.pool.New = func() any { return hmac.New(sha256.New, psk[:]) }
	return v
}

// Verify checks whether raw TLS ClientHello data contains a valid knock tag.
// data must be at least KnockMinBytes (76) bytes from the start of the TCP stream.
//
// Returns true if and only if the structural checks pass AND
// data[44:76] == HMAC-SHA256(psk, data[11:43]).
//
// Zero heap allocations in the steady state: the HMAC hasher is borrowed from
// the pool, Reset() restores its pre-keyed state (no re-allocation), and it is
// returned to the pool after use.
func (v *KnockVerifier) Verify(data []byte) bool {
	if len(data) < KnockMinBytes {
		return false
	}
	// Structural validation: TLS handshake record, ClientHello, 32-byte session_id.
	if data[0] != 0x16 || data[5] != 0x01 || data[knockSIDLenOffset] != 0x20 {
		return false
	}

	h := v.pool.Get().(hash.Hash)
	h.Reset()
	h.Write(data[knockRandomOffset:knockRandomEnd])
	var expected [32]byte
	h.Sum(expected[:0]) // append digest into stack array; no heap alloc
	v.pool.Put(h)

	return hmac.Equal(expected[:], data[knockSessionIDOffset:knockSessionIDEnd])
}
