# server/crypto

Криптографическое ядро VPN сервера.

## Возможности

- **X25519 Diffie-Hellman**: безопасный обмен ключами по RFC 7748
- **ChaCha20-Poly1305**: аутентифицированное шифрование (AEAD) по RFC 8439
- Защита от слабых ключей (all-zero DH результат)
- Clamp приватных ключей согласно стандарту

## Использование

```go
import "github.com/cavad93/vpn/server/crypto"

// Генерация ключевых пар на обеих сторонах
serverKP, _ := crypto.GenerateKeyPair()
clientKP, _ := crypto.GenerateKeyPair()

// DH обмен — обе стороны получают одинаковый shared secret
serverShared, _ := crypto.DiffieHellman(serverKP.PrivateKey, clientKP.PublicKey)
clientShared, _ := crypto.DiffieHellman(clientKP.PrivateKey, serverKP.PublicKey)
// serverShared == clientShared

// Создание шифра из shared secret
cipher, _ := crypto.NewCipher(serverShared)

// Шифрование
nonce, _ := crypto.GenerateNonce()
ciphertext, _ := cipher.Encrypt(nonce, []byte("секрет"), []byte("aad"))

// Расшифровка
plaintext, _ := cipher.Decrypt(nonce, ciphertext, []byte("aad"))
```

## Запуск тестов

```bash
go test ./crypto/ -v -cover
```

Покрытие: 81.6%
