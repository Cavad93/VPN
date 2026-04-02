// Package crypto — реализация Noise_XX handshake протокола.
//
// Noise_XX обеспечивает mutual authentication: обе стороны аутентифицируют
// друг друга через статические X25519 ключи. Паттерн:
//
//	-> e
//	<- e, ee, s, es
//	-> s, se
//
// После handshake обе стороны получают независимые cipher states
// для шифрования трафика в каждом направлении.
//
// Использование:
//
//	serverKP, _ := crypto.GenerateKeyPair()
//	hs, _ := crypto.NewHandshake(crypto.Responder, serverKP)
//
//	clientKP, _ := crypto.GenerateKeyPair()
//	hc, _ := crypto.NewHandshake(crypto.Initiator, clientKP)
//
//	msg1, _ := hc.WriteMessage1()
//	hs.ReadMessage1(msg1)
//	msg2, _ := hs.WriteMessage2()
//	hc.ReadMessage2(msg2)
//	msg3, serverSession, _ := hc.WriteMessage3()
//	clientSession, _ := hs.ReadMessage3(msg3)
package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// ProtocolName — идентификатор Noise протокола.
	ProtocolName = "Noise_XX_25519_ChaChaPoly_SHA256"

	// HashSize — размер SHA-256 хеша в байтах.
	HashSize = 32
)

// HandshakeRole определяет роль участника в handshake.
type HandshakeRole bool

const (
	// Initiator — инициатор соединения (клиент).
	Initiator HandshakeRole = true
	// Responder — принимающая сторона (сервер).
	Responder HandshakeRole = false
)

// noiseHKDF выполняет HKDF функцию Noise протокола на основе HMAC-SHA256.
// Возвращает numOutputs 32-байтовых выходов (2 или 3).
func noiseHKDF(chainingKey, inputKeyMaterial []byte, numOutputs int) ([][HashSize]byte, error) {
	if numOutputs < 2 || numOutputs > 3 {
		return nil, errors.New("noiseHKDF: numOutputs должен быть 2 или 3")
	}

	// temp_key = HMAC-SHA256(chaining_key, input_key_material)
	mac := hmac.New(sha256.New, chainingKey)
	mac.Write(inputKeyMaterial)
	tempKey := mac.Sum(nil)

	outputs := make([][HashSize]byte, numOutputs)

	// output1 = HMAC-SHA256(temp_key, 0x01)
	mac = hmac.New(sha256.New, tempKey)
	mac.Write([]byte{0x01})
	copy(outputs[0][:], mac.Sum(nil))

	// output2 = HMAC-SHA256(temp_key, output1 || 0x02)
	mac = hmac.New(sha256.New, tempKey)
	mac.Write(outputs[0][:])
	mac.Write([]byte{0x02})
	copy(outputs[1][:], mac.Sum(nil))

	if numOutputs == 3 {
		// output3 = HMAC-SHA256(temp_key, output2 || 0x03)
		mac = hmac.New(sha256.New, tempKey)
		mac.Write(outputs[1][:])
		mac.Write([]byte{0x03})
		copy(outputs[2][:], mac.Sum(nil))
	}

	return outputs, nil
}

// noiseCipherState управляет ключом и счётчиком nonce для одного направления.
type noiseCipherState struct {
	k      [KeySize]byte
	n      uint64
	hasKey bool
	aead   cipher.AEAD // инициализируется один раз в initializeKey, переиспользуется для всех пакетов
}

func (cs *noiseCipherState) initializeKey(key [KeySize]byte) {
	cs.k = key
	cs.n = 0
	cs.hasKey = true
	aead, err := chacha20poly1305.New(cs.k[:])
	if err != nil {
		panic(fmt.Sprintf("noiseCipherState initializeKey: %v", err))
	}
	cs.aead = aead
}

// encryptWithAD шифрует plaintext с дополнительными данными.
// Если ключ не установлен — возвращает plaintext без изменений.
func (cs *noiseCipherState) encryptWithAD(ad, plaintext []byte) ([]byte, error) {
	if !cs.hasKey {
		result := make([]byte, len(plaintext))
		copy(result, plaintext)
		return result, nil
	}
	// Noise spec: nonce = 4 нулевых байта + 8-байтный little-endian счётчик
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], cs.n)
	cs.n++
	return cs.aead.Seal(nil, nonce[:], plaintext, ad), nil
}

// decryptWithAD расшифровывает ciphertext с проверкой тега аутентификации.
func (cs *noiseCipherState) decryptWithAD(ad, ciphertext []byte) ([]byte, error) {
	if !cs.hasKey {
		result := make([]byte, len(ciphertext))
		copy(result, ciphertext)
		return result, nil
	}
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], cs.n)
	cs.n++
	plaintext, err := cs.aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("noiseCipherState decrypt: аутентификация не прошла: %w", err)
	}
	return plaintext, nil
}

// decryptWithADTo расшифровывает в предоставленный буфер dst[:0],
// позволяя повторно использовать выделенную память.
func (cs *noiseCipherState) decryptWithADTo(dst, ad, ciphertext []byte) ([]byte, error) {
	if !cs.hasKey {
		result := append(dst[:0], ciphertext...)
		return result, nil
	}
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], cs.n)
	cs.n++
	plaintext, err := cs.aead.Open(dst[:0], nonce[:], ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("noiseCipherState decrypt: аутентификация не прошла: %w", err)
	}
	return plaintext, nil
}

// noiseSymmetricState управляет chaining key и хешем во время handshake.
type noiseSymmetricState struct {
	cs noiseCipherState
	ck [HashSize]byte // chaining key
	h  [HashSize]byte // transcript hash
}

func newNoiseSymmetricState(protocolName string) *noiseSymmetricState {
	ss := &noiseSymmetricState{}
	nameBytes := []byte(protocolName)
	if len(nameBytes) <= HashSize {
		copy(ss.h[:], nameBytes)
	} else {
		ss.h = sha256.Sum256(nameBytes)
	}
	ss.ck = ss.h
	return ss
}

// mixKey обновляет chaining key и инициализирует cipher state.
func (ss *noiseSymmetricState) mixKey(inputKeyMaterial []byte) error {
	outputs, err := noiseHKDF(ss.ck[:], inputKeyMaterial, 2)
	if err != nil {
		return fmt.Errorf("mixKey: %w", err)
	}
	ss.ck = outputs[0]
	ss.cs.initializeKey(outputs[1])
	return nil
}

// mixHash добавляет данные в transcript хеш.
func (ss *noiseSymmetricState) mixHash(data []byte) {
	h := sha256.New()
	h.Write(ss.h[:])
	h.Write(data)
	copy(ss.h[:], h.Sum(nil))
}

// encryptAndHash шифрует данные и добавляет ciphertext в хеш.
func (ss *noiseSymmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := ss.cs.encryptWithAD(ss.h[:], plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryptAndHash: %w", err)
	}
	ss.mixHash(ciphertext)
	return ciphertext, nil
}

// decryptAndHash расшифровывает данные и добавляет ciphertext в хеш.
func (ss *noiseSymmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := ss.cs.decryptWithAD(ss.h[:], ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryptAndHash: %w", err)
	}
	ss.mixHash(ciphertext)
	return plaintext, nil
}

// split завершает handshake и возвращает два cipher state для трафика.
// c1 — для инициатора (отправка), c2 — для ответчика (отправка).
func (ss *noiseSymmetricState) split() (*noiseCipherState, *noiseCipherState, error) {
	// HKDF с пустым input_key_material
	outputs, err := noiseHKDF(ss.ck[:], []byte{}, 2)
	if err != nil {
		return nil, nil, fmt.Errorf("split: %w", err)
	}
	c1 := &noiseCipherState{}
	c1.initializeKey(outputs[0])
	c2 := &noiseCipherState{}
	c2.initializeKey(outputs[1])
	return c1, c2, nil
}

// HandshakeState реализует Noise_XX handshake.
type HandshakeState struct {
	ss   *noiseSymmetricState
	s    *KeyPair       // наша статическая ключевая пара
	e    *KeyPair       // наша эфемерная ключевая пара
	rs   [KeySize]byte  // публичный статический ключ удалённой стороны
	re   [KeySize]byte  // публичный эфемерный ключ удалённой стороны
	role HandshakeRole
	step int // 0=сообщение1, 1=сообщение2, 2=сообщение3, 3=завершён
}

// Session содержит cipher states после успешного handshake.
type Session struct {
	// SendCipher используется для шифрования исходящих сообщений.
	SendCipher *SessionCipher
	// RecvCipher используется для расшифровки входящих сообщений.
	RecvCipher *SessionCipher
	// RemoteStatic — верифицированный публичный ключ удалённой стороны.
	RemoteStatic [KeySize]byte
}

// SessionCipher обёртка над cipher state для использования после handshake.
type SessionCipher struct {
	cs *noiseCipherState
}

// Encrypt шифрует plaintext с опциональными дополнительными данными.
func (sc *SessionCipher) Encrypt(plaintext, ad []byte) ([]byte, error) {
	return sc.cs.encryptWithAD(ad, plaintext)
}

// Decrypt расшифровывает ciphertext с проверкой аутентификации.
func (sc *SessionCipher) Decrypt(ciphertext, ad []byte) ([]byte, error) {
	return sc.cs.decryptWithAD(ad, ciphertext)
}

// DecryptTo расшифровывает ciphertext в предоставленный буфер dst,
// избегая выделения памяти на каждый пакет. dst должен иметь достаточный
// cap для plaintext (len(ciphertext) - 16 байт AEAD overhead).
// Возвращает слайс plaintext из dst.
func (sc *SessionCipher) DecryptTo(dst, ciphertext, ad []byte) ([]byte, error) {
	return sc.cs.decryptWithADTo(dst, ad, ciphertext)
}

// NewHandshake создаёт новый HandshakeState для Noise_XX.
// staticKP — долгосрочная статическая ключевая пара данной стороны.
func NewHandshake(role HandshakeRole, staticKP *KeyPair) (*HandshakeState, error) {
	if staticKP == nil {
		return nil, errors.New("handshake: статическая ключевая пара обязательна")
	}
	hs := &HandshakeState{
		ss:   newNoiseSymmetricState(ProtocolName),
		s:    staticKP,
		role: role,
		step: 0,
	}
	// MixHash(prologue) — пустой пролог
	hs.ss.mixHash([]byte{})
	return hs, nil
}

// WriteMessage1 формирует первое сообщение handshake (только инициатор).
//
// Паттерн: -> e
// Возвращает байты для отправки ответчику.
func (hs *HandshakeState) WriteMessage1() ([]byte, error) {
	if hs.role != Initiator || hs.step != 0 {
		return nil, errors.New("handshake: WriteMessage1 доступен только инициатору на шаге 0")
	}

	// Генерируем эфемерную ключевую пару
	e, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("handshake WriteMessage1: %w", err)
	}
	hs.e = e

	// -> e: отправляем эфемерный публичный ключ
	hs.ss.mixHash(hs.e.PublicKey[:])

	msg := make([]byte, KeySize)
	copy(msg, hs.e.PublicKey[:])

	hs.step = 1
	return msg, nil
}

// ReadMessage1 обрабатывает первое сообщение handshake (только ответчик).
//
// Паттерн: -> e
func (hs *HandshakeState) ReadMessage1(msg []byte) error {
	if hs.role != Responder || hs.step != 0 {
		return errors.New("handshake: ReadMessage1 доступен только ответчику на шаге 0")
	}
	if len(msg) < KeySize {
		return fmt.Errorf("handshake ReadMessage1: сообщение слишком короткое (%d байт, нужно %d)", len(msg), KeySize)
	}

	// Читаем эфемерный публичный ключ инициатора
	copy(hs.re[:], msg[:KeySize])
	hs.ss.mixHash(hs.re[:])

	hs.step = 1
	return nil
}

// WriteMessage2 формирует второе сообщение handshake (только ответчик).
//
// Паттерн: <- e, ee, s, es
// Возвращает байты для отправки инициатору.
func (hs *HandshakeState) WriteMessage2() ([]byte, error) {
	if hs.role != Responder || hs.step != 1 {
		return nil, errors.New("handshake: WriteMessage2 доступен только ответчику на шаге 1")
	}

	// Генерируем эфемерную ключевую пару ответчика
	e, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("handshake WriteMessage2: %w", err)
	}
	hs.e = e

	var msg []byte

	// <- e: отправляем эфемерный публичный ключ ответчика
	hs.ss.mixHash(hs.e.PublicKey[:])
	msg = append(msg, hs.e.PublicKey[:]...)

	// ee: DH(e_responder, e_initiator)
	ee, err := DiffieHellman(hs.e.PrivateKey, hs.re)
	if err != nil {
		return nil, fmt.Errorf("handshake WriteMessage2 ee: %w", err)
	}
	if err := hs.ss.mixKey(ee[:]); err != nil {
		return nil, fmt.Errorf("handshake WriteMessage2 mixKey(ee): %w", err)
	}

	// s: зашифровываем статический публичный ключ ответчика
	encS, err := hs.ss.encryptAndHash(hs.s.PublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("handshake WriteMessage2 encrypt(s): %w", err)
	}
	msg = append(msg, encS...)

	// es: DH(s_responder, e_initiator)
	es, err := DiffieHellman(hs.s.PrivateKey, hs.re)
	if err != nil {
		return nil, fmt.Errorf("handshake WriteMessage2 es: %w", err)
	}
	if err := hs.ss.mixKey(es[:]); err != nil {
		return nil, fmt.Errorf("handshake WriteMessage2 mixKey(es): %w", err)
	}

	hs.step = 2
	return msg, nil
}

// ReadMessage2 обрабатывает второе сообщение handshake (только инициатор).
//
// Паттерн: <- e, ee, s, es
func (hs *HandshakeState) ReadMessage2(msg []byte) error {
	if hs.role != Initiator || hs.step != 1 {
		return errors.New("handshake: ReadMessage2 доступен только инициатору на шаге 1")
	}
	// e(32) + EncryptAndHash(s)(32 + 16 тег) = 80 байт минимум
	minLen := KeySize + KeySize + Overhead
	if len(msg) < minLen {
		return fmt.Errorf("handshake ReadMessage2: сообщение слишком короткое (%d байт, нужно %d)", len(msg), minLen)
	}

	// <- e: читаем эфемерный публичный ключ ответчика
	copy(hs.re[:], msg[:KeySize])
	hs.ss.mixHash(hs.re[:])
	msg = msg[KeySize:]

	// ee: DH(e_initiator, e_responder)
	ee, err := DiffieHellman(hs.e.PrivateKey, hs.re)
	if err != nil {
		return fmt.Errorf("handshake ReadMessage2 ee: %w", err)
	}
	if err := hs.ss.mixKey(ee[:]); err != nil {
		return fmt.Errorf("handshake ReadMessage2 mixKey(ee): %w", err)
	}

	// s: расшифровываем статический ключ ответчика
	encS := msg[:KeySize+Overhead]
	plainS, err := hs.ss.decryptAndHash(encS)
	if err != nil {
		return fmt.Errorf("handshake ReadMessage2 decrypt(s): %w", err)
	}
	copy(hs.rs[:], plainS)

	// es: DH(e_initiator, s_responder)
	es, err := DiffieHellman(hs.e.PrivateKey, hs.rs)
	if err != nil {
		return fmt.Errorf("handshake ReadMessage2 es: %w", err)
	}
	if err := hs.ss.mixKey(es[:]); err != nil {
		return fmt.Errorf("handshake ReadMessage2 mixKey(es): %w", err)
	}

	hs.step = 2
	return nil
}

// WriteMessage3 формирует третье сообщение handshake (только инициатор).
//
// Паттерн: -> s, se
// Возвращает байты для отправки и Session с cipher states.
func (hs *HandshakeState) WriteMessage3() ([]byte, *Session, error) {
	if hs.role != Initiator || hs.step != 2 {
		return nil, nil, errors.New("handshake: WriteMessage3 доступен только инициатору на шаге 2")
	}

	var msg []byte

	// s: зашифровываем статический публичный ключ инициатора
	encS, err := hs.ss.encryptAndHash(hs.s.PublicKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("handshake WriteMessage3 encrypt(s): %w", err)
	}
	msg = append(msg, encS...)

	// se: DH(s_initiator, e_responder)
	se, err := DiffieHellman(hs.s.PrivateKey, hs.re)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake WriteMessage3 se: %w", err)
	}
	if err := hs.ss.mixKey(se[:]); err != nil {
		return nil, nil, fmt.Errorf("handshake WriteMessage3 mixKey(se): %w", err)
	}

	// Split: c1 — инициатор отправляет, c2 — ответчик отправляет
	c1, c2, err := hs.ss.split()
	if err != nil {
		return nil, nil, fmt.Errorf("handshake WriteMessage3 split: %w", err)
	}

	session := &Session{
		SendCipher:   &SessionCipher{cs: c1},
		RecvCipher:   &SessionCipher{cs: c2},
		RemoteStatic: hs.rs,
	}

	hs.step = 3
	return msg, session, nil
}

// ReadMessage3 обрабатывает третье сообщение handshake (только ответчик).
//
// Паттерн: -> s, se
// Возвращает Session с cipher states.
func (hs *HandshakeState) ReadMessage3(msg []byte) (*Session, error) {
	if hs.role != Responder || hs.step != 2 {
		return nil, errors.New("handshake: ReadMessage3 доступен только ответчику на шаге 2")
	}
	// EncryptAndHash(s) = 32 + 16 = 48 байт
	minLen := KeySize + Overhead
	if len(msg) < minLen {
		return nil, fmt.Errorf("handshake ReadMessage3: сообщение слишком короткое (%d байт, нужно %d)", len(msg), minLen)
	}

	// s: расшифровываем статический ключ инициатора
	encS := msg[:KeySize+Overhead]
	plainS, err := hs.ss.decryptAndHash(encS)
	if err != nil {
		return nil, fmt.Errorf("handshake ReadMessage3 decrypt(s): %w", err)
	}
	copy(hs.rs[:], plainS)

	// se: DH(e_responder, s_initiator)
	se, err := DiffieHellman(hs.e.PrivateKey, hs.rs)
	if err != nil {
		return nil, fmt.Errorf("handshake ReadMessage3 se: %w", err)
	}
	if err := hs.ss.mixKey(se[:]); err != nil {
		return nil, fmt.Errorf("handshake ReadMessage3 mixKey(se): %w", err)
	}

	// Split: c1 — инициатор отправляет (мы получаем), c2 — ответчик отправляет
	c1, c2, err := hs.ss.split()
	if err != nil {
		return nil, fmt.Errorf("handshake ReadMessage3 split: %w", err)
	}

	session := &Session{
		SendCipher:   &SessionCipher{cs: c2},
		RecvCipher:   &SessionCipher{cs: c1},
		RemoteStatic: hs.rs,
	}

	hs.step = 3
	return session, nil
}
