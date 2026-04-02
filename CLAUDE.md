# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

This is a VPN (Virtual Private Network) project.

## Development Guidelines

- Follow secure coding practices — this project handles sensitive network traffic and credentials
- Never hardcode secrets, keys, or passwords in source files
- Validate all user input at system boundaries
- Prefer explicit error handling over silent failures

## Common Commands

```bash
# Запуск тестов сервера
cd server && go test ./... -v -cover

# Запуск тестов только crypto модуля
cd server && go test ./crypto/ -v -cover
```

## Architecture

```
server/
├── go.mod
├── crypto/
│   ├── crypto.go       — X25519 DH + ChaCha20-Poly1305 AEAD
│   ├── crypto_test.go  — 11 unit тестов (покрытие 81.6%)
│   └── README.md
```

## Прогресс задач

### ЗАДАЧА 1 — ВЫПОЛНЕНО (2026-04-02)
**Файл:** `server/crypto/crypto.go`

Реализовано криптографическое ядро:
- `GenerateKeyPair()` — X25519 ключевая пара с RFC 7748 clamp
- `DiffieHellman(priv, pub)` — X25519 DH обмен, защита от слабых ключей
- `NewCipher(key)` — ChaCha20-Poly1305 AEAD шифр
- `Encrypt(nonce, plaintext, aad)` — шифрование с аутентификацией
- `Decrypt(nonce, ciphertext, aad)` — расшифровка с проверкой тега
- `GenerateNonce()` — криптографически случайный nonce

**Тесты:** 11 тестов, покрытие 81.6%  
**Зависимость:** `golang.org/x/crypto@v0.32.0`  
**Запуск:** `cd server && go test ./crypto/ -v`
