package crypto_test

// Benchmarks for crypto layer throughput.
//
// Run:
//   cd server && go test ./crypto/ -bench=. -benchtime=3s -benchmem

import (
	"crypto/rand"
	"testing"

	"github.com/cavad93/vpn/server/crypto"
)

// BenchmarkEncrypt1400 measures ChaCha20-Poly1305 encryption throughput
// for typical VPN packet size (1400 bytes = inner IP MTU).
func BenchmarkEncrypt1400(b *testing.B) {
	benchEncrypt(b, 1400)
}

// BenchmarkEncrypt64 measures small packet encryption (DNS, ACKs).
func BenchmarkEncrypt64(b *testing.B) {
	benchEncrypt(b, 64)
}

// BenchmarkDecrypt1400 measures decryption throughput for VPN packets.
func BenchmarkDecrypt1400(b *testing.B) {
	benchDecrypt(b, 1400)
}

// BenchmarkDecrypt64 measures small packet decryption.
func BenchmarkDecrypt64(b *testing.B) {
	benchDecrypt(b, 64)
}

// BenchmarkEncryptTo1400 measures zero-alloc encryption (hot path pattern).
func BenchmarkEncryptTo1400(b *testing.B) {
	benchEncryptTo(b, 1400)
}

// BenchmarkDecryptTo1400 measures zero-alloc decryption (hot path pattern).
func BenchmarkDecryptTo1400(b *testing.B) {
	benchDecryptTo(b, 1400)
}

// BenchmarkHandshake measures full Noise_XX handshake throughput.
func BenchmarkHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {
		setupSessions(b)
	}
}

func benchEncrypt(b *testing.B, size int) {
	sender, _ := setupSessions(b)
	plaintext := make([]byte, size)
	rand.Read(plaintext)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sender.SendCipher.Encrypt(plaintext, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func benchDecrypt(b *testing.B, size int) {
	sender, receiver := setupSessions(b)
	plaintext := make([]byte, size)
	rand.Read(plaintext)

	// Pre-encrypt with initiator's SendCipher → decrypt with responder's RecvCipher.
	packets := make([][]byte, b.N)
	for i := range packets {
		ct, err := sender.SendCipher.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
		packets[i] = ct
	}

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := receiver.RecvCipher.Decrypt(packets[i], nil); err != nil {
			b.Fatal(err)
		}
	}
}

func benchEncryptTo(b *testing.B, size int) {
	sender, _ := setupSessions(b)
	plaintext := make([]byte, size)
	rand.Read(plaintext)
	dst := make([]byte, 0, size+crypto.Overhead)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sender.SendCipher.EncryptTo(dst, plaintext, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func benchDecryptTo(b *testing.B, size int) {
	sender, receiver := setupSessions(b)
	plaintext := make([]byte, size)
	rand.Read(plaintext)

	packets := make([][]byte, b.N)
	for i := range packets {
		ct, err := sender.SendCipher.Encrypt(plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
		packets[i] = ct
	}

	dst := make([]byte, 0, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := receiver.RecvCipher.DecryptTo(dst, packets[i], nil); err != nil {
			b.Fatal(err)
		}
	}
}

// setupSessions performs a full Noise_XX handshake and returns both sides' sessions.
// Initiator's SendCipher corresponds to Responder's RecvCipher and vice versa.
func setupSessions(b testing.TB) (initiator, responder *crypto.Session) {
	b.Helper()
	ikp, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	rkp, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	init, err := crypto.NewHandshake(crypto.Initiator, ikp)
	if err != nil {
		b.Fatal(err)
	}
	resp, err := crypto.NewHandshake(crypto.Responder, rkp)
	if err != nil {
		b.Fatal(err)
	}
	m1, err := init.WriteMessage1()
	if err != nil {
		b.Fatal(err)
	}
	if err := resp.ReadMessage1(m1); err != nil {
		b.Fatal(err)
	}
	m2, err := resp.WriteMessage2()
	if err != nil {
		b.Fatal(err)
	}
	if err := init.ReadMessage2(m2); err != nil {
		b.Fatal(err)
	}
	m3, iSess, err := init.WriteMessage3()
	if err != nil {
		b.Fatal(err)
	}
	rSess, err := resp.ReadMessage3(m3)
	if err != nil {
		b.Fatal(err)
	}
	return iSess, rSess
}
