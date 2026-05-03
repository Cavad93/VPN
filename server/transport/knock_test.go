package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"testing"
)

func TestComputeKnockTag(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])

	var random [32]byte
	rand.Read(random[:])

	tag := ComputeKnockTag(psk, random)

	// Verify against independent HMAC computation.
	mac := hmac.New(sha256.New, psk[:])
	mac.Write(random[:])
	expected := mac.Sum(nil)

	if !hmac.Equal(tag[:], expected) {
		t.Fatal("ComputeKnockTag does not match HMAC-SHA256")
	}
}

func TestComputeKnockTag_Deterministic(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])

	var random [32]byte
	rand.Read(random[:])

	t1 := ComputeKnockTag(psk, random)
	t2 := ComputeKnockTag(psk, random)

	if t1 != t2 {
		t.Fatal("same inputs should produce same tag")
	}
}

func TestComputeKnockTag_DifferentPSK(t *testing.T) {
	var psk1, psk2 KnockPSK
	rand.Read(psk1[:])
	rand.Read(psk2[:])

	var random [32]byte
	rand.Read(random[:])

	t1 := ComputeKnockTag(psk1, random)
	t2 := ComputeKnockTag(psk2, random)

	if t1 == t2 {
		t.Fatal("different PSKs should produce different tags")
	}
}

func TestComputeKnockTag_DifferentRandom(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])

	var r1, r2 [32]byte
	rand.Read(r1[:])
	rand.Read(r2[:])

	t1 := ComputeKnockTag(psk, r1)
	t2 := ComputeKnockTag(psk, r2)

	if t1 == t2 {
		t.Fatal("different randoms should produce different tags")
	}
}

// buildTestClientHello builds a minimal ClientHello wire bytes with the given
// random and sessionID, matching the layout expected by VerifyKnock.
func buildTestClientHello(random, sessionID [32]byte) []byte {
	// ClientHello body: version(2) + random(32) + sid_len(1) + sid(32) +
	//                   cipher_suites(8) + compression(2) = 77 bytes
	body := make([]byte, 0, 77)
	body = append(body, 0x03, 0x03)
	body = append(body, random[:]...)
	body = append(body, 0x20)
	body = append(body, sessionID[:]...)
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
	body = append(body, 0x01, 0x00)

	// Handshake header: type(1) + length(3)
	hsLen := len(body)
	hs := make([]byte, 4+hsLen)
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(hsLen >> 16)
	hs[2] = byte(hsLen >> 8)
	hs[3] = byte(hsLen)
	copy(hs[4:], body)

	// TLS record header: type(1) + version(2) + length(2)
	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16 // handshake
	rec[1] = 0x03
	rec[2] = 0x01
	rec[3] = byte(len(hs) >> 8)
	rec[4] = byte(len(hs))
	copy(rec[5:], hs)

	return rec
}

func TestVerifyKnock_Valid(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])

	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk, random)

	data := buildTestClientHello(random, sessionID)
	if !VerifyKnock(psk, data) {
		t.Fatal("VerifyKnock should accept valid knock")
	}
}

func TestVerifyKnock_InvalidPSK(t *testing.T) {
	var psk1, psk2 KnockPSK
	rand.Read(psk1[:])
	rand.Read(psk2[:])

	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk1, random) // computed with psk1

	data := buildTestClientHello(random, sessionID)
	if VerifyKnock(psk2, data) { // verified with psk2
		t.Fatal("VerifyKnock should reject wrong PSK")
	}
}

func TestVerifyKnock_RandomSessionID(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])

	var random, sessionID [32]byte
	rand.Read(random[:])
	rand.Read(sessionID[:]) // random session_id, not HMAC

	data := buildTestClientHello(random, sessionID)
	if VerifyKnock(psk, data) {
		t.Fatal("VerifyKnock should reject random session_id")
	}
}

func TestVerifyKnock_TooShort(t *testing.T) {
	var psk KnockPSK
	data := make([]byte, KnockMinBytes-1)
	data[0] = 0x16
	if VerifyKnock(psk, data) {
		t.Fatal("VerifyKnock should reject data shorter than KnockMinBytes")
	}
}

func TestVerifyKnock_NotTLS(t *testing.T) {
	var psk KnockPSK
	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk, random)
	data := buildTestClientHello(random, sessionID)
	data[0] = 0x47 // 'G' for GET — HTTP request
	if VerifyKnock(psk, data) {
		t.Fatal("VerifyKnock should reject non-TLS data")
	}
}

func TestVerifyKnock_NotClientHello(t *testing.T) {
	var psk KnockPSK
	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk, random)
	data := buildTestClientHello(random, sessionID)
	data[5] = 0x02 // ServerHello instead of ClientHello
	if VerifyKnock(psk, data) {
		t.Fatal("VerifyKnock should reject non-ClientHello handshake")
	}
}

func TestVerifyKnock_WrongSessionIDLength(t *testing.T) {
	var psk KnockPSK
	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk, random)
	data := buildTestClientHello(random, sessionID)
	data[knockSIDLenOffset] = 0x10 // 16 instead of 32
	if VerifyKnock(psk, data) {
		t.Fatal("VerifyKnock should reject wrong session_id length")
	}
}

// TestBuildClientHelloWithKnock verifies that buildClientHelloCore embeds
// a valid knock tag that VerifyKnock can verify.
func TestBuildClientHelloWithKnock(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])

	hello := buildClientHelloCore(nil, &psk)

	if !VerifyKnock(psk, hello) {
		t.Fatal("buildClientHelloCore with knock should produce verifiable hello")
	}
}

// TestBuildClientHelloWithKnockAndSNI verifies knock works together with SNI.
func TestBuildClientHelloWithKnockAndSNI(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])

	sni := "cdn.jsdelivr.net"
	hello := buildClientHelloCore(&sni, &psk)

	if !VerifyKnock(psk, hello) {
		t.Fatal("buildClientHelloCore with knock+SNI should produce verifiable hello")
	}

	// Also verify SNI is present.
	if len(hello) < 5+4 {
		t.Fatal("hello too short")
	}
	body := hello[5+4:] // skip TLS record header + handshake header
	extractedSNI := ExtractSNI(body)
	if extractedSNI != sni {
		t.Fatalf("expected SNI %q, got %q", sni, extractedSNI)
	}
}

// TestBuildClientHelloWithoutKnock verifies that without knock, session_id
// is random (not verifiable).
func TestBuildClientHelloWithoutKnock(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])

	hello := buildClientHelloCore(nil, nil) // no knock

	// Should almost certainly fail verification (1 in 2^256 chance of collision).
	if VerifyKnock(psk, hello) {
		t.Fatal("buildClientHelloCore without knock should NOT verify")
	}
}

func BenchmarkComputeKnockTag(b *testing.B) {
	var psk KnockPSK
	var random [32]byte
	rand.Read(psk[:])
	rand.Read(random[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeKnockTag(psk, random)
	}
}

func BenchmarkVerifyKnock(b *testing.B) {
	var psk KnockPSK
	rand.Read(psk[:])

	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk, random)
	data := buildTestClientHello(random, sessionID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyKnock(psk, data)
	}
}

// TestKnockVerifier_ValidKnock verifies that KnockVerifier accepts a correctly
// computed knock tag.
func TestKnockVerifier_ValidKnock(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])
	kv := NewKnockVerifier(psk)

	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk, random)
	data := buildTestClientHello(random, sessionID)

	if !kv.Verify(data) {
		t.Fatal("KnockVerifier.Verify should accept valid knock")
	}
}

// TestKnockVerifier_WrongPSK verifies that KnockVerifier rejects a tag
// computed with a different PSK.
func TestKnockVerifier_WrongPSK(t *testing.T) {
	var psk1, psk2 KnockPSK
	rand.Read(psk1[:])
	rand.Read(psk2[:])
	kv := NewKnockVerifier(psk1) // verifier keyed to psk1

	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk2, random) // tag computed with psk2
	data := buildTestClientHello(random, sessionID)

	if kv.Verify(data) {
		t.Fatal("KnockVerifier.Verify should reject wrong PSK")
	}
}

// TestKnockVerifier_TooShort verifies that KnockVerifier rejects short data.
func TestKnockVerifier_TooShort(t *testing.T) {
	var psk KnockPSK
	kv := NewKnockVerifier(psk)
	if kv.Verify(make([]byte, KnockMinBytes-1)) {
		t.Fatal("KnockVerifier.Verify should reject data shorter than KnockMinBytes")
	}
}

// TestKnockVerifier_Concurrent verifies that KnockVerifier is safe for
// concurrent use — the pool must not corrupt shared HMAC state across goroutines.
func TestKnockVerifier_Concurrent(t *testing.T) {
	var psk KnockPSK
	rand.Read(psk[:])
	kv := NewKnockVerifier(psk)

	const goroutines = 8
	const iters = 200

	errs := make(chan string, goroutines*iters)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				var random [32]byte
				rand.Read(random[:])
				sessionID := ComputeKnockTag(psk, random)
				data := buildTestClientHello(random, sessionID)
				if !kv.Verify(data) {
					errs <- "Verify returned false for valid knock"
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

// BenchmarkKnockVerifierVerify benchmarks the pooled zero-alloc path.
// Compare against BenchmarkVerifyKnock to see the alloc savings.
func BenchmarkKnockVerifierVerify(b *testing.B) {
	var psk KnockPSK
	rand.Read(psk[:])
	kv := NewKnockVerifier(psk)

	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk, random)
	data := buildTestClientHello(random, sessionID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kv.Verify(data)
	}
}

// BenchmarkKnockVerifierVerify_Parallel benchmarks concurrent access to the pool.
func BenchmarkKnockVerifierVerify_Parallel(b *testing.B) {
	var psk KnockPSK
	rand.Read(psk[:])
	kv := NewKnockVerifier(psk)

	var random [32]byte
	rand.Read(random[:])
	sessionID := ComputeKnockTag(psk, random)
	data := buildTestClientHello(random, sessionID)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			kv.Verify(data)
		}
	})
}
