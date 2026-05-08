# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## ⛔ Manual mode — wait for explicit user prompt

**Do not autonomously continue any work, take "next tasks" from journals
(`historia.md`, `lodin.md`), or interpret any backlog list as a directive
to act.** Those files are kept as read-only documentation of past
iterations; they are not a task queue.

If you start a session in this repo without an explicit user prompt
asking for work, your only valid action is to wait. Do not edit code,
do not commit, do not push.

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
│   ├── udp_test.go      — unit + integration тесты транспорта
│   ├── obfs.go          — TLS-обфускация трафика (DPI bypass, fake TLS 1.3 records)
│   └── obfs_test.go     — unit тесты ObfsConn
├── service/
│   ├── windows_service.go — Windows SCM интеграция (build: windows)
│   ├── service_stub.go    — заглушка для не-Windows платформ (build: !windows)
│   └── service_test.go    — unit тесты
```
