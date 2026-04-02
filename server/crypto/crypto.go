// Package crypto реализует криптографическое ядро VPN:
// X25519 Diffie-Hellman обмен ключами и ChaCha20-Poly1305 AEAD шифрование.
//
// Использование:
//
//	kp, _ := crypto.GenerateKeyPair()
//	shared, _ := crypto.DiffieHellman(kp.PrivateKey, peerPublicKey)
//	cipher, _ := crypto.NewCipher(shared)
//	ciphertext, _ := cipher.Encrypt(nonce, plaintext, additionalData)
//	plaintext, _ := cipher.Decrypt(nonce, ciphertext, additionalData)
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// KeySize — размер ключа X25519 и ChaCha20-Poly1305 в байтах.
	KeySize = 32
	// NonceSize — размер nonce для ChaCha20-Poly1305.
	NonceSize = chacha20poly1305.NonceSize
	// Overhead — накладные расходы AEAD тега аутентификации.
	Overhead = chacha20poly1305.Overhead
)

// KeyPair содержит пару ключей X25519.
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// Cipher реализует симметричное AEAD шифрование ChaCha20-Poly1305.
type Cipher struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
}

// GenerateKeyPair генерирует новую пару ключей X25519 используя криптографически
// стойкий генератор случайных чисел.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.PrivateKey[:]); err != nil {
		return nil, fmt.Errorf("crypto: не удалось сгенерировать приватный ключ: %w", err)
	}
	// Clamp приватного ключа согласно RFC 7748
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("crypto: не удалось вычислить публичный ключ: %w", err)
	}
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// KeyPairFromPrivate derives a KeyPair from a raw 32-byte private key.
// The public key is computed as X25519(privateKey, Basepoint).
func KeyPairFromPrivate(priv []byte) (*KeyPair, error) {
	if len(priv) != KeySize {
		return nil, fmt.Errorf("crypto: private key must be %d bytes", KeySize)
	}
	kp := &KeyPair{}
	copy(kp.PrivateKey[:], priv)
	// RFC 7748 clamp
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64
	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive public key: %w", err)
	}
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// DiffieHellman выполняет X25519 Diffie-Hellman операцию.
// Возвращает общий секрет длиной KeySize байт.
func DiffieHellman(privateKey, peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	shared, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("crypto: X25519 DH ошибка: %w", err)
	}
	// Проверка на слабые точки (all-zero результат)
	var zero [KeySize]byte
	result := [KeySize]byte{}
	copy(result[:], shared)
	if result == zero {
		return [KeySize]byte{}, errors.New("crypto: DH результат является нулевой точкой (слабый ключ)")
	}
	return result, nil
}

// NewCipher создаёт новый ChaCha20-Poly1305 шифр из 32-байтового ключа.
func NewCipher(key [KeySize]byte) (*Cipher, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: не удалось создать ChaCha20-Poly1305 шифр: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt шифрует plaintext с аутентификацией additionalData.
// nonce должен быть уникальным для каждого вызова с одним ключом.
// Возвращает ciphertext + 16-байтный тег аутентификации.
func (c *Cipher) Encrypt(nonce [NonceSize]byte, plaintext, additionalData []byte) ([]byte, error) {
	dst := make([]byte, 0, len(plaintext)+Overhead)
	result := c.aead.Seal(dst, nonce[:], plaintext, additionalData)
	return result, nil
}

// Decrypt расшифровывает и верифицирует ciphertext.
// Возвращает ошибку если тег аутентификации не совпадает.
func (c *Cipher) Decrypt(nonce [NonceSize]byte, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, errors.New("crypto: ciphertext слишком короткий")
	}
	dst := make([]byte, 0, len(ciphertext)-Overhead)
	plaintext, err := c.aead.Open(dst, nonce[:], ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("crypto: расшифровка не удалась (неверный тег или повреждённые данные): %w", err)
	}
	return plaintext, nil
}

// GenerateNonce генерирует криптографически случайный nonce.
func GenerateNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return [NonceSize]byte{}, fmt.Errorf("crypto: не удалось сгенерировать nonce: %w", err)
	}
	return nonce, nil
}
