package crypto_test

import (
	"bytes"
	"testing"

	"github.com/cavad93/vpn/server/crypto"
)

// TestGenerateKeyPair проверяет генерацию ключевой пары.
func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()
	kp1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() ошибка: %v", err)
	}

	// Публичный ключ не должен быть нулевым
	var zero [crypto.KeySize]byte
	if kp1.PublicKey == zero {
		t.Error("PublicKey не должен быть нулевым")
	}
	if kp1.PrivateKey == zero {
		t.Error("PrivateKey не должен быть нулевым")
	}

	// Два разных вызова должны давать разные ключи
	kp2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() ошибка: %v", err)
	}
	if kp1.PublicKey == kp2.PublicKey {
		t.Error("Два разных KeyPair не должны иметь одинаковые публичные ключи")
	}
}

// TestDiffieHellman проверяет корректность X25519 DH обмена.
func TestDiffieHellman(t *testing.T) {
	t.Parallel()
	// Генерируем два ключевых пары (клиент и сервер)
	server, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(server): %v", err)
	}
	client, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(client): %v", err)
	}

	// server вычисляет shared secret используя свой приватный и публичный клиента
	serverShared, err := crypto.DiffieHellman(server.PrivateKey, client.PublicKey)
	if err != nil {
		t.Fatalf("DiffieHellman(server): %v", err)
	}

	// client вычисляет shared secret используя свой приватный и публичный сервера
	clientShared, err := crypto.DiffieHellman(client.PrivateKey, server.PublicKey)
	if err != nil {
		t.Fatalf("DiffieHellman(client): %v", err)
	}

	// Оба shared secret должны совпадать
	if serverShared != clientShared {
		t.Errorf("DH shared secrets не совпадают:\nserver: %x\nclient: %x", serverShared, clientShared)
	}

	// Shared secret не должен быть нулевым
	var zero [crypto.KeySize]byte
	if serverShared == zero {
		t.Error("Shared secret не должен быть нулевым")
	}
}

// TestNewCipher проверяет создание шифра.
func TestNewCipher(t *testing.T) {
	t.Parallel()
	var key [crypto.KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x42}, crypto.KeySize))

	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() ошибка: %v", err)
	}
	if cipher == nil {
		t.Fatal("NewCipher() вернул nil")
	}
}

// TestEncryptDecrypt проверяет полный цикл шифрования и расшифровки.
func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()
	var key [crypto.KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x01}, crypto.KeySize))

	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher(): %v", err)
	}

	plaintext := []byte("Секретное VPN сообщение 12345")
	additionalData := []byte("VPN-header-v1")

	nonce, err := crypto.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce(): %v", err)
	}

	// Шифрование
	ciphertext, err := cipher.Encrypt(nonce, plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encrypt(): %v", err)
	}

	// Ciphertext должен быть длиннее plaintext на Overhead байт
	if len(ciphertext) != len(plaintext)+crypto.Overhead {
		t.Errorf("Длина ciphertext: %d, ожидалось: %d", len(ciphertext), len(plaintext)+crypto.Overhead)
	}

	// Ciphertext не должен совпадать с plaintext
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Error("Ciphertext не должен совпадать с plaintext")
	}

	// Расшифровка
	decrypted, err := cipher.Decrypt(nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Decrypt(): %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Расшифрованный текст не совпадает:\nПолучено: %s\nОжидалось: %s", decrypted, plaintext)
	}
}

// TestDecryptTampered проверяет что изменение ciphertext вызывает ошибку.
func TestDecryptTampered(t *testing.T) {
	t.Parallel()
	var key [crypto.KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x02}, crypto.KeySize))

	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher(): %v", err)
	}

	nonce, _ := crypto.GenerateNonce()
	plaintext := []byte("Тестовое сообщение")
	ciphertext, _ := cipher.Encrypt(nonce, plaintext, nil)

	// Портим ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err = cipher.Decrypt(nonce, tampered, nil)
	if err == nil {
		t.Error("Decrypt() должен вернуть ошибку для повреждённого ciphertext")
	}
}

// TestDecryptWrongKey проверяет что неверный ключ вызывает ошибку расшифровки.
func TestDecryptWrongKey(t *testing.T) {
	t.Parallel()
	var key1 [crypto.KeySize]byte
	copy(key1[:], bytes.Repeat([]byte{0x01}, crypto.KeySize))
	var key2 [crypto.KeySize]byte
	copy(key2[:], bytes.Repeat([]byte{0x02}, crypto.KeySize))

	cipher1, _ := crypto.NewCipher(key1)
	cipher2, _ := crypto.NewCipher(key2)

	nonce, _ := crypto.GenerateNonce()
	plaintext := []byte("Секретное сообщение")
	ciphertext, _ := cipher1.Encrypt(nonce, plaintext, nil)

	_, err := cipher2.Decrypt(nonce, ciphertext, nil)
	if err == nil {
		t.Error("Decrypt() с неверным ключом должен вернуть ошибку")
	}
}

// TestDecryptWrongNonce проверяет что неверный nonce вызывает ошибку.
func TestDecryptWrongNonce(t *testing.T) {
	t.Parallel()
	var key [crypto.KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x03}, crypto.KeySize))

	cipher, _ := crypto.NewCipher(key)

	nonce1, _ := crypto.GenerateNonce()
	nonce2, _ := crypto.GenerateNonce()

	plaintext := []byte("Сообщение")
	ciphertext, _ := cipher.Encrypt(nonce1, plaintext, nil)

	_, err := cipher.Decrypt(nonce2, ciphertext, nil)
	if err == nil {
		t.Error("Decrypt() с неверным nonce должен вернуть ошибку")
	}
}

// TestDecryptWrongAAD проверяет что неверные additional data вызывают ошибку.
func TestDecryptWrongAAD(t *testing.T) {
	t.Parallel()
	var key [crypto.KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x04}, crypto.KeySize))

	cipher, _ := crypto.NewCipher(key)

	nonce, _ := crypto.GenerateNonce()
	plaintext := []byte("Сообщение с AAD")
	ciphertext, _ := cipher.Encrypt(nonce, plaintext, []byte("correct-aad"))

	_, err := cipher.Decrypt(nonce, ciphertext, []byte("wrong-aad"))
	if err == nil {
		t.Error("Decrypt() с неверными AAD должен вернуть ошибку")
	}
}

// TestDiffieHellmanIntegration проверяет полный DH + шифрование цикл.
func TestDiffieHellmanIntegration(t *testing.T) {
	t.Parallel()
	// Генерируем ключи для обеих сторон
	serverKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(server): %v", err)
	}
	clientKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(client): %v", err)
	}

	// Обе стороны вычисляют одинаковый shared secret
	serverSecret, _ := crypto.DiffieHellman(serverKP.PrivateKey, clientKP.PublicKey)
	clientSecret, _ := crypto.DiffieHellman(clientKP.PrivateKey, serverKP.PublicKey)

	// Создаём шифры на основе shared secret
	serverCipher, err := crypto.NewCipher(serverSecret)
	if err != nil {
		t.Fatalf("NewCipher(server): %v", err)
	}
	clientCipher, err := crypto.NewCipher(clientSecret)
	if err != nil {
		t.Fatalf("NewCipher(client): %v", err)
	}

	// Сервер шифрует сообщение для клиента
	message := []byte("Привет от сервера!")
	aad := []byte("session-id-42")
	nonce, _ := crypto.GenerateNonce()

	encrypted, err := serverCipher.Encrypt(nonce, message, aad)
	if err != nil {
		t.Fatalf("serverCipher.Encrypt(): %v", err)
	}

	// Клиент расшифровывает
	decrypted, err := clientCipher.Decrypt(nonce, encrypted, aad)
	if err != nil {
		t.Fatalf("clientCipher.Decrypt(): %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Errorf("Интеграционный тест: расшифрованное != оригинал\nПолучено: %s\nОжидалось: %s", decrypted, message)
	}
}

// TestGenerateNonce проверяет что нonce генерируются случайными.
func TestGenerateNonce(t *testing.T) {
	t.Parallel()
	nonce1, err := crypto.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce(): %v", err)
	}
	nonce2, err := crypto.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce(): %v", err)
	}

	if nonce1 == nonce2 {
		t.Error("Два последовательных nonce не должны совпадать")
	}

	var zero [crypto.NonceSize]byte
	if nonce1 == zero {
		t.Error("Nonce не должен быть нулевым")
	}
}

// TestEncryptEmptyPlaintext проверяет шифрование пустого сообщения.
func TestEncryptEmptyPlaintext(t *testing.T) {
	t.Parallel()
	var key [crypto.KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x05}, crypto.KeySize))
	cipher, _ := crypto.NewCipher(key)
	nonce, _ := crypto.GenerateNonce()

	ciphertext, err := cipher.Encrypt(nonce, []byte{}, nil)
	if err != nil {
		t.Fatalf("Encrypt(empty): %v", err)
	}
	// Только тег аутентификации
	if len(ciphertext) != crypto.Overhead {
		t.Errorf("Длина ciphertext для пустого plaintext: %d, ожидалось: %d", len(ciphertext), crypto.Overhead)
	}

	decrypted, err := cipher.Decrypt(nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt(empty): %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("Расшифрованный текст для пустого plaintext должен быть пустым, получено: %d байт", len(decrypted))
	}
}
