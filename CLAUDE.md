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
│   ├── udp_test.go      — unit + integration тесты транспорта
│   ├── obfs.go          — TLS-обфускация трафика (DPI bypass, fake TLS 1.3 records)
│   └── obfs_test.go     — unit тесты ObfsConn
├── service/
│   ├── windows_service.go — Windows SCM интеграция (build: windows)
│   ├── service_stub.go    — заглушка для не-Windows платформ (build: !windows)
│   └── service_test.go    — unit тесты
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

### ЗАДАЧА 5 — ВЫПОЛНЕНО (2026-04-02)
**Файл:** `server/transport/obfs.go`

Реализована TLS-обфускация трафика (DPI bypass):
- `ObfsConn` — враппер net.Conn с TLS-подобным фреймингом
- `NewObfsConn(conn)` — создание ObfsConn поверх существующего соединения
- `ClientHandshake()` — отправка синтетического ClientHello + чтение ServerHello
- `ServerHandshake()` — чтение ClientHello + отправка синтетического ServerHello
- `Write(p)` — фрагментация данных в TLS application_data records (content_type=0x17)
- `Read(p)` — чтение и дефрагментация TLS records с внутренним буфером
- `buildClientHello()` / `buildServerHello()` — синтетические TLS 1.3 handshake сообщения с рандомными полями
- Реализует полный net.Conn интерфейс (SetDeadline, LocalAddr, RemoteAddr, Close)

Wire format: TLS record header (5 байт: content_type + version 0x0303 + length) + payload.
Каждое соединение уникально: random[32] и session_id[32] заполняются crypto/rand.

**Тесты:** 15 тестов, покрытие пакета transport 90.8%  
**Запуск:** `cd server && go test ./transport/ -v -cover`

### ЗАДАЧА 6 — ВЫПОЛНЕНО (2026-04-02)
**Файл:** `server/transport/mux.go`

Реализован мультиплексор виртуальных потоков:
- `NewMux(conn, isClient)` — обёртка над net.Conn; клиент использует чётные stream ID (2,4,6…), сервер — нечётные (1,3,5…)
- `Mux.OpenStream()` — открыть исходящий Stream (отправляет FrameSYN)
- `Mux.AcceptStream(ctx)` — принять входящий Stream (блокирует до прихода SYN)
- `Mux.Close()` — закрыть все Stream и соединение
- `Stream.Write(p)` — запись данных (фрагментация при >65535 байт)
- `Stream.Read(p)` — чтение данных; возвращает io.EOF при получении FrameFIN
- `Stream.Close()` — отправляет FrameFIN, удаляет поток из карты

Wire format: 7-байтный заголовок (streamID uint32 + type uint8 + length uint16) + payload.  
Потокобезопасность: `writeMu` сериализует запись фреймов, `streamsMu` защищает карту потоков.

**Тесты:** 14 тестов mux, покрытие пакета transport 90.0%  
**Запуск:** `cd server && go test ./transport/ -v -cover`

### ЗАДАЧА 7 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `server/main.go`, `server/tun_linux.go`, `server/tun_stub.go`

Реализован VPN сервер:
- `Server{cfg, staticKP, sessions, pool, tun}` — основная структура сервера
- `NewServer(cfg, kp, tun, allowedKeys, logger)` — конструктор с валидацией
- `Server.Run(ctx)` — TCP listener + routeFromTun + accept loop
- `Server.Sessions()` — статистика активных сессий
- `Server.DisconnectSession(id)` — принудительное отключение клиента
- `handleConn(ctx, conn)` — ObfsConn.ServerHandshake → Noise_XX → noiseConn → Mux → stream loop
- `handleControlStream` — протокол IP assignment (ctlHello/ctlAssign, 10 байт)
- `handleDataStream` — чтение IP пакетов от клиента → TUN
- `routeFromTun` — чтение пакетов из TUN → маршрутизация к клиенту по dst IP
- `noiseConn` — net.Conn обёртка с Noise session шифрованием (SendCipher/RecvCipher + 2-byte framing)
- `ipPool` — аллокатор IPv4 адресов из CIDR подсети
- `loadOrGenerateKeyPair` — загрузка/генерация статического ключа сервера
- `OpenTun` — Linux: /dev/net/tun + ioctl TUNSETIFF; stub для остальных платформ

**Тесты:** покрытие 80.4%  
**Запуск:** `cd server && go test . -v -cover`

### ЗАДАЧА 8 — ВЫПОЛНЕНО (2026-04-02)
**Файл:** `server/api/api.go`

Реализован REST API для управления VPN-сервером:
- `SessionInfo{ID, RemoteKey, AssignedIP, BytesIn, BytesOut, ConnectedAt, Duration}` — структура статистики сессии
- `ServerIface` — интерфейс для взаимодействия API с VPN-сервером (Sessions, DisconnectSession, AddAllowedKey, RemoveAllowedKey, AllowedKeys)
- `APIServer` — HTTP сервер (`NewAPIServer`, `Run`, `Handler`)
- `Config{ListenAddr, APIToken}` — конфигурация API
- Авторизация: Bearer-токен (`Authorization: Bearer <token>`) или `X-API-Key` заголовок

Эндпоинты:
- `GET  /api/v1/health`           — health check (без авторизации)
- `GET  /api/v1/sessions`         — список активных сессий
- `GET  /api/v1/sessions/{id}`    — одна сессия по ID
- `DELETE /api/v1/sessions/{id}`  — отключить клиента
- `GET  /api/v1/keys`             — список разрешённых ключей
- `POST /api/v1/keys`             — добавить ключ `{"key":"<hex>"}`
- `DELETE /api/v1/keys/{key}`     — удалить ключ
- `GET  /api/v1/stats`            — агрегированная статистика трафика

В `server/main.go` добавлены: `AddAllowedKey`/`RemoveAllowedKey`/`AllowedKeys` методы в `Server`, `SessionStats = api.SessionInfo` (type alias), helper `startAPIServer()`, флаги `-api-addr` и `-api-token`.

**Тесты:** 27 тестов api + 7 новых тестов main, покрытие api 87.2%, main 80.4%  
**Запуск:** `cd server && go test ./api/ -v -cover`

### ЗАДАЧА 9 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `server/service/windows_service.go`, `server/service/service_stub.go`

Реализован Windows Service враппер:
- `RunFunc` — тип функции запуска VPN сервера `func(ctx context.Context) error`
- `vpnService` — реализует `svc.Handler`, мост между Windows SCM и context-based shutdown
- `RunAsService(name, run, logger)` — запуск под управлением Windows SCM (блокирует до остановки)
- `IsWindowsService()` — определяет, запущен ли процесс как служба Windows
- `Install(name, displayName, description, exePath)` — регистрация службы в SCM (требует admin)
- `Remove(name)` — удаление службы из SCM (требует admin)
- `ErrNotWindows` — sentinel error для не-Windows платформ

Логика `Execute`: SCM → Stop/Shutdown → отмена context → ожидание завершения сервера (таймаут 30с). Ошибка сервера → Win32 exit code 1. SCM → Interrogate → echo текущего статуса.
Константы: `DefaultServiceName="CavadVPN"`, `DefaultDisplayName`, `DefaultDescription`.

На не-Windows платформах `service_stub.go` (build: !windows) возвращает `ErrNotWindows` для всех операций SCM.

**Тесты:** 9 тестов, покрытие 100%  
**Запуск:** `cd server && go test ./service/ -v -cover`

### ЗАДАЧА 10 — ВЫПОЛНЕНО (2026-04-02)
**Файл:** `server/config/config.go`

Реализована YAML-конфигурация сервера с генерацией ключей при первом запуске:
- `ServerConfig{Listen, TunCIDR, PrivateKeyFile, AllowedKeys, API, Log}` — полная конфигурация сервера
- `APIConfig{Listen, Token}` — настройки REST API
- `LogConfig{Level, Format}` — настройки логирования (debug/info/warn/error, text/json)
- `Default()` — значения по умолчанию (0.0.0.0:443, 10.8.0.1/24, info/text)
- `Load(path)` — загрузка YAML файла; если файл отсутствует — создаёт его с defaults
- `Save(path, cfg)` — сохранение конфигурации в YAML (режим 0600, создаёт директории)
- `Validate()` — проверка корректности полей (listen, tun_cidr, log level/format, hex ключи)
- `ParseAllowedKeys()` — декодирование AllowedKeys из hex строк в [][32]byte
- `EnsureKeyFile(path)` — загрузка или генерация X25519 приватного ключа (RFC 7748 clamp, режим 0600)

Зависимость: `gopkg.in/yaml.v3 v3.0.1`

**Тесты:** 24 теста, покрытие 85.3%  
**Запуск:** `cd server && go test ./config/ -v -cover`

### ЗАДАЧА 11 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `client/core.py`, `client/test_core.py`, `client/requirements.txt`

Реализован Python клиент VPN — полный стек протокола:
- `KeyPair` + `generate_key_pair()` + `load_key_pair_from_file(path)` — X25519 ключевые пары (RFC 7748)
- `dh(priv, pub_bytes)` — X25519 Diffie-Hellman, защита от нулевого ключа
- `noise_hkdf(ck, ikm, n)` — HKDF функция Noise протокола (HMAC-SHA256, 2 или 3 выхода)
- `NoiseCipherState` — ChaCha20-Poly1305 с nonce = 4 нулевых байта + 8-байт LE счётчик
- `NoiseSymmetricState` — mixHash, mixKey, encryptAndHash, decryptAndHash, split
- `NoiseHandshake` — инициатор Noise_XX (write_message1, read_message2, write_message3)
- `ObfsConn` — TLS-обфускация (client_handshake, server_handshake, read/write)
- `NoiseConn` — шифрование трафика с 2-байт BE length prefix поверх ObfsConn
- `MuxStream` — виртуальный поток (read, write, read_exactly, close, FIN handling)
- `ClientMux` — мультиплексор с чётными stream ID (2,4,6…), фоновый read_loop
- `RouteInfo` — IP assignment (assigned_ip, prefix_len, gateway, cidr, network)
- `VPNConfig` + `VPNClient` — полный клиент (connect, disconnect, send_packet, recv_packet)

Зависимости: `cryptography>=41.0.0`, `structlog>=23.0.0`

**Тесты:** 58 тестов, покрытие 91%  
**Запуск:** `cd client && python3 -m pytest test_core.py -v`
