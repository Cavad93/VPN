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
│   ├── crypto.go        — X25519 DH + ChaCha20-Poly1305 AEAD
│   ├── crypto_test.go   — unit тесты crypto.go
│   ├── handshake.go     — Noise_XX handshake протокол
│   ├── handshake_test.go — unit тесты handshake
│   ├── replay.go        — защита от replay атак (nonce + timestamp window)
│   ├── replay_test.go   — unit тесты replay.go
│   └── README.md
├── transport/
│   ├── udp.go           — надёжный UDP транспорт (ACK, retransmit, ordering, congestion)
│   └── udp_test.go      — unit + integration тесты транспорта
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

### ЗАДАЧА 2 — ВЫПОЛНЕНО (2026-04-02)
**Файл:** `server/crypto/handshake.go`

Реализован Noise_XX handshake протокол (mutual authentication):
- `NewHandshake(role, staticKP)` — создание HandshakeState для инициатора или ответчика
- `WriteMessage1() / ReadMessage1(msg)` — обмен эфемерным ключом инициатора (-> e)
- `WriteMessage2() / ReadMessage2(msg)` — ответчик отправляет ephemeral + encrypted static (<- e, ee, s, es)
- `WriteMessage3() / ReadMessage3(msg)` — инициатор отправляет encrypted static + DH (-> s, se)
- `Session{SendCipher, RecvCipher, RemoteStatic}` — результат handshake, независимые cipher states

Внутренние компоненты: `noiseHKDF` (HMAC-SHA256), `noiseCipherState` (ChaCha20-Poly1305 + nonce counter), `noiseSymmetricState` (chaining key + transcript hash)

**Тесты:** 22 теста суммарно, покрытие 80.4%  
**Запуск:** `cd server && go test ./crypto/ -v -cover`

### ЗАДАЧА 3 — ВЫПОЛНЕНО (2026-04-02)
**Файл:** `server/crypto/replay.go`

Реализована защита от replay атак:
- `PacketHeader{Timestamp, Nonce}` — заголовок пакета (20 байт: 8 timestamp + 12 nonce)
- `NewPacketHeader()` — создание заголовка с текущим временем и случайным nonce
- `PacketHeader.Encode()` — сериализация в байты (big-endian)
- `DecodePacketHeader(data)` — десериализация заголовка
- `ReplayFilter` — потокобезопасный фильтр с скользящим окном ±90 секунд
- `NewReplayFilter()` — конструктор фильтра
- `ReplayFilter.Check(header)` — проверка и регистрация пакета; отклоняет устаревшие/будущие/повторные

Алгоритм: nonce хранятся в map[timestamp_second → set[nonce]], автоочистка устаревших bucket'ов при каждом Check.

**Тесты:** 41 тест суммарно, покрытие 82.9%  
**Запуск:** `cd server && go test ./crypto/ -v -cover`

### ЗАДАЧА 4 — ВЫПОЛНЕНО (2026-04-02)
**Файл:** `server/transport/udp.go`

Реализован надёжный UDP транспорт:
- `Packet{Type, SeqNum, AckNum, Payload}` — PDU с encode/decode (11-байтный заголовок)
- `Conn` — надёжное соединение: `Write`, `Read(ctx)`, `Close`
- `processData(pkt)` — упорядочивание пакетов, sliding receive buffer, cumulative ACK
- `processACK(ackNum)` — освобождение pending пакетов, рост окна (slow start / congestion avoidance)
- `doRetransmit()` — повторная отправка пакетов по таймауту, multiplicative decrease
- `Listen(addr)` — UDP-сервер с демультиплексингом по remote-адресу
- `Listener.Accept(ctx)` — принятие новых соединений
- `Dial(addr)` — клиентское подключение к серверу

Алгоритм congestion control: TCP Reno-style — slow start до ssthresh, linear increase после, halvingwindow при потере.

**Тесты:** 25 тестов, покрытие 90.7%  
**Запуск:** `cd server && go test ./transport/ -v -cover`
