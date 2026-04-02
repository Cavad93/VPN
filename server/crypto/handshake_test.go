package crypto_test

import (
	"bytes"
	"testing"

	"github.com/cavad93/vpn/server/crypto"
)

// runHandshake выполняет полный Noise_XX handshake между инициатором и ответчиком.
// Возвращает сессии обеих сторон.
func runHandshake(t *testing.T, initiatorKP, responderKP *crypto.KeyPair) (*crypto.Session, *crypto.Session) {
	t.Helper()

	// Создаём handshake states
	hcInit, err := crypto.NewHandshake(crypto.Initiator, initiatorKP)
	if err != nil {
		t.Fatalf("NewHandshake(Initiator): %v", err)
	}
	hcResp, err := crypto.NewHandshake(crypto.Responder, responderKP)
	if err != nil {
		t.Fatalf("NewHandshake(Responder): %v", err)
	}

	// Шаг 1: -> e (инициатор → ответчик)
	msg1, err := hcInit.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if err := hcResp.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}

	// Шаг 2: <- e, ee, s, es (ответчик → инициатор)
	msg2, err := hcResp.WriteMessage2()
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}
	if err := hcInit.ReadMessage2(msg2); err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}

	// Шаг 3: -> s, se (инициатор → ответчик)
	msg3, initiatorSession, err := hcInit.WriteMessage3()
	if err != nil {
		t.Fatalf("WriteMessage3: %v", err)
	}
	responderSession, err := hcResp.ReadMessage3(msg3)
	if err != nil {
		t.Fatalf("ReadMessage3: %v", err)
	}

	return initiatorSession, responderSession
}

// TestHandshakeComplete проверяет успешный полный handshake.
func TestHandshakeComplete(t *testing.T) {
	initiatorKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(initiator): %v", err)
	}
	responderKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(responder): %v", err)
	}

	initiatorSess, responderSess := runHandshake(t, initiatorKP, responderKP)

	if initiatorSess == nil {
		t.Fatal("initiatorSession не должен быть nil")
	}
	if responderSess == nil {
		t.Fatal("responderSession не должен быть nil")
	}
}

// TestHandshakeRemoteStaticKeys проверяет что обе стороны верно идентифицируют
// публичные статические ключи друг друга после handshake.
func TestHandshakeRemoteStaticKeys(t *testing.T) {
	initiatorKP, _ := crypto.GenerateKeyPair()
	responderKP, _ := crypto.GenerateKeyPair()

	initiatorSess, responderSess := runHandshake(t, initiatorKP, responderKP)

	// Инициатор должен знать публичный ключ ответчика
	if initiatorSess.RemoteStatic != responderKP.PublicKey {
		t.Errorf("Инициатор: неверный RemoteStatic\nПолучено:  %x\nОжидалось: %x",
			initiatorSess.RemoteStatic, responderKP.PublicKey)
	}

	// Ответчик должен знать публичный ключ инициатора
	if responderSess.RemoteStatic != initiatorKP.PublicKey {
		t.Errorf("Ответчик: неверный RemoteStatic\nПолучено:  %x\nОжидалось: %x",
			responderSess.RemoteStatic, initiatorKP.PublicKey)
	}
}

// TestHandshakeEncryptDecrypt проверяет двунаправленную передачу данных
// после handshake.
func TestHandshakeEncryptDecrypt(t *testing.T) {
	initiatorKP, _ := crypto.GenerateKeyPair()
	responderKP, _ := crypto.GenerateKeyPair()

	initiatorSess, responderSess := runHandshake(t, initiatorKP, responderKP)

	// Инициатор → Ответчик
	msg := []byte("Привет, сервер! Это тестовый VPN пакет.")
	encrypted, err := initiatorSess.SendCipher.Encrypt(msg, nil)
	if err != nil {
		t.Fatalf("initiator SendCipher.Encrypt: %v", err)
	}
	decrypted, err := responderSess.RecvCipher.Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("responder RecvCipher.Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, msg) {
		t.Errorf("Инициатор→Ответчик: расшифрованное != оригинал\nПолучено: %s\nОжидалось: %s",
			decrypted, msg)
	}

	// Ответчик → Инициатор
	reply := []byte("Привет, клиент! Соединение установлено.")
	encrypted2, err := responderSess.SendCipher.Encrypt(reply, nil)
	if err != nil {
		t.Fatalf("responder SendCipher.Encrypt: %v", err)
	}
	decrypted2, err := initiatorSess.RecvCipher.Decrypt(encrypted2, nil)
	if err != nil {
		t.Fatalf("initiator RecvCipher.Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted2, reply) {
		t.Errorf("Ответчик→Инициатор: расшифрованное != оригинал\nПолучено: %s\nОжидалось: %s",
			decrypted2, reply)
	}
}

// TestHandshakeEncryptWithAAD проверяет шифрование с дополнительными данными.
func TestHandshakeEncryptWithAAD(t *testing.T) {
	initiatorKP, _ := crypto.GenerateKeyPair()
	responderKP, _ := crypto.GenerateKeyPair()

	initiatorSess, responderSess := runHandshake(t, initiatorKP, responderKP)

	msg := []byte("Данные VPN пакета")
	aad := []byte("vpn-packet-header-v1")

	encrypted, err := initiatorSess.SendCipher.Encrypt(msg, aad)
	if err != nil {
		t.Fatalf("Encrypt с AAD: %v", err)
	}

	// Правильный AAD — расшифровка должна пройти
	decrypted, err := responderSess.RecvCipher.Decrypt(encrypted, aad)
	if err != nil {
		t.Fatalf("Decrypt с правильным AAD: %v", err)
	}
	if !bytes.Equal(decrypted, msg) {
		t.Error("Расшифрованное не совпадает с оригиналом")
	}

	// Неверный AAD — расшифровка должна завершиться ошибкой
	// Нужно создать новые сессии для корректного состояния nonce
	initiatorKP2, _ := crypto.GenerateKeyPair()
	responderKP2, _ := crypto.GenerateKeyPair()
	initiatorSess2, responderSess2 := runHandshake(t, initiatorKP2, responderKP2)

	encrypted2, _ := initiatorSess2.SendCipher.Encrypt(msg, aad)
	_, err = responderSess2.RecvCipher.Decrypt(encrypted2, []byte("wrong-header"))
	if err == nil {
		t.Error("Decrypt с неверным AAD должен вернуть ошибку")
	}
}

// TestHandshakeTamperedMessage проверяет что подмена handshake сообщений
// вызывает ошибку.
func TestHandshakeTamperedMessage2(t *testing.T) {
	initiatorKP, _ := crypto.GenerateKeyPair()
	responderKP, _ := crypto.GenerateKeyPair()

	hcInit, _ := crypto.NewHandshake(crypto.Initiator, initiatorKP)
	hcResp, _ := crypto.NewHandshake(crypto.Responder, responderKP)

	msg1, _ := hcInit.WriteMessage1()
	hcResp.ReadMessage1(msg1) //nolint:errcheck
	msg2, _ := hcResp.WriteMessage2()

	// Портим зашифрованный статический ключ в msg2
	tampered := make([]byte, len(msg2))
	copy(tampered, msg2)
	// msg2 = e(32) + EncryptAndHash(s)(48) = 80 байт
	// Портим байт в зашифрованном статическом ключе
	tampered[33] ^= 0xFF

	err := hcInit.ReadMessage2(tampered)
	if err == nil {
		t.Error("ReadMessage2 с повреждённым сообщением должен вернуть ошибку")
	}
}

// TestHandshakeWrongRole проверяет что вызов методов в неправильной роли
// возвращает ошибку.
func TestHandshakeWrongRole(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	// Ответчик не может вызвать WriteMessage1
	hsResp, _ := crypto.NewHandshake(crypto.Responder, kp)
	_, err := hsResp.WriteMessage1()
	if err == nil {
		t.Error("Ответчик не должен иметь возможность вызвать WriteMessage1")
	}

	// Инициатор не может вызвать ReadMessage1
	hsInit, _ := crypto.NewHandshake(crypto.Initiator, kp)
	err = hsInit.ReadMessage1(make([]byte, crypto.KeySize))
	if err == nil {
		t.Error("Инициатор не должен иметь возможность вызвать ReadMessage1")
	}

	// Ответчик не может вызвать WriteMessage3
	hsResp2, _ := crypto.NewHandshake(crypto.Responder, kp)
	_, _, err = hsResp2.WriteMessage3()
	if err == nil {
		t.Error("Ответчик не должен иметь возможность вызвать WriteMessage3")
	}
}

// TestHandshakeNilKeyPair проверяет что nil keypair вызывает ошибку.
func TestHandshakeNilKeyPair(t *testing.T) {
	_, err := crypto.NewHandshake(crypto.Initiator, nil)
	if err == nil {
		t.Error("NewHandshake с nil keypair должен вернуть ошибку")
	}
}

// TestHandshakeMessageTooShort проверяет обработку слишком коротких сообщений.
func TestHandshakeMessageTooShort(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	// ReadMessage1 с коротким сообщением
	hs, _ := crypto.NewHandshake(crypto.Responder, kp)
	err := hs.ReadMessage1(make([]byte, 10))
	if err == nil {
		t.Error("ReadMessage1 с коротким сообщением должен вернуть ошибку")
	}
}

// TestHandshakeMultipleSessions проверяет что каждый handshake порождает
// уникальные cipher states.
func TestHandshakeMultipleSessions(t *testing.T) {
	initiatorKP, _ := crypto.GenerateKeyPair()
	responderKP, _ := crypto.GenerateKeyPair()

	sess1Init, sess1Resp := runHandshake(t, initiatorKP, responderKP)
	sess2Init, sess2Resp := runHandshake(t, initiatorKP, responderKP)

	msg := []byte("Тестовое сообщение")

	enc1, err := sess1Init.SendCipher.Encrypt(msg, nil)
	if err != nil {
		t.Fatalf("sess1 Encrypt: %v", err)
	}
	enc2, err := sess2Init.SendCipher.Encrypt(msg, nil)
	if err != nil {
		t.Fatalf("sess2 Encrypt: %v", err)
	}

	// Cipher states разные — зашифрованные сообщения должны отличаться
	if bytes.Equal(enc1, enc2) {
		t.Error("Два разных сеанса не должны давать одинаковые ciphertext")
	}

	// Каждая сессия работает независимо
	dec1, err := sess1Resp.RecvCipher.Decrypt(enc1, nil)
	if err != nil {
		t.Fatalf("sess1 Decrypt: %v", err)
	}
	if !bytes.Equal(dec1, msg) {
		t.Error("sess1: расшифрованное != оригинал")
	}

	dec2, err := sess2Resp.RecvCipher.Decrypt(enc2, nil)
	if err != nil {
		t.Fatalf("sess2 Decrypt: %v", err)
	}
	if !bytes.Equal(dec2, msg) {
		t.Error("sess2: расшифрованное != оригинал")
	}
}

// TestHandshakeWrongStep проверяет защиту от вызовов методов в неверном порядке.
func TestHandshakeWrongStep(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	// Инициатор пытается вызвать WriteMessage2 сразу
	hsInit, _ := crypto.NewHandshake(crypto.Initiator, kp)
	_, err := hsInit.WriteMessage2()
	if err == nil {
		t.Error("Инициатор не должен вызывать WriteMessage2")
	}

	// Ответчик пытается вызвать WriteMessage2 без ReadMessage1
	hsResp, _ := crypto.NewHandshake(crypto.Responder, kp)
	_, err = hsResp.WriteMessage2()
	if err == nil {
		t.Error("Ответчик не должен вызывать WriteMessage2 без ReadMessage1")
	}

	// Ответчик пытается вызвать ReadMessage3 без WriteMessage2
	hsResp2, _ := crypto.NewHandshake(crypto.Responder, kp)
	_, err = hsResp2.ReadMessage3(make([]byte, crypto.KeySize+crypto.Overhead))
	if err == nil {
		t.Error("Ответчик не должен вызывать ReadMessage3 без WriteMessage2")
	}

	// Инициатор пытается вызвать WriteMessage3 без ReadMessage2
	hsInit2, _ := crypto.NewHandshake(crypto.Initiator, kp)
	_, _, err = hsInit2.WriteMessage3()
	if err == nil {
		t.Error("Инициатор не должен вызывать WriteMessage3 без ReadMessage2")
	}
}

// TestHandshakeSequentialMessages проверяет что счётчик nonce корректно
// инкрементируется для последовательных сообщений.
func TestHandshakeSequentialMessages(t *testing.T) {
	initiatorKP, _ := crypto.GenerateKeyPair()
	responderKP, _ := crypto.GenerateKeyPair()

	initiatorSess, responderSess := runHandshake(t, initiatorKP, responderKP)

	messages := [][]byte{
		[]byte("Первое сообщение"),
		[]byte("Второе сообщение"),
		[]byte("Третье сообщение"),
		[]byte("Четвёртое сообщение"),
		[]byte("Пятое сообщение"),
	}

	for i, msg := range messages {
		encrypted, err := initiatorSess.SendCipher.Encrypt(msg, nil)
		if err != nil {
			t.Fatalf("Encrypt сообщение %d: %v", i+1, err)
		}
		decrypted, err := responderSess.RecvCipher.Decrypt(encrypted, nil)
		if err != nil {
			t.Fatalf("Decrypt сообщение %d: %v", i+1, err)
		}
		if !bytes.Equal(decrypted, msg) {
			t.Errorf("Сообщение %d: расшифрованное != оригинал", i+1)
		}
	}
}
