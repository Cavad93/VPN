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

### ЗАДАЧА 12 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `client/tun_macos.py`, `client/test_tun_macos.py`

Реализован TUN интерфейс для macOS:
- `TunInterface.open(unit)` — открытие utun устройства через AF_SYSTEM/SYSPROTO_CONTROL socket + CTLIOCGINFO ioctl + connect(sockaddr_ctl). Ядро автоматически присваивает имя интерфейса (utun0, utun1, …)
- `TunInterface.configure(local_ip, peer_ip, prefix_len, mtu)` — конфигурация интерфейса через `ifconfig <name> <local> <peer> mtu <mtu> up`
- `TunInterface.read_packet(max_size)` — чтение raw IPv4 пакета; снимает 4-байтный utun-заголовок (AF_INET = 0x00000002 big-endian)
- `TunInterface.write_packet(packet)` — запись raw IPv4 пакета с добавлением utun-заголовка
- `TunInterface.add_route(network, gateway)` / `delete_route(...)` — управление маршрутами через `route -n add/delete -net ... -netmask ... gateway`
- `TunInterface.add_default_route(gateway)` / `delete_default_route(gateway)` — перенаправление всего трафика через VPN
- `get_default_gateway()` — парсинг текущего шлюза по умолчанию из вывода `netstat -rn`
- `get_interface_mtu(iface)` — парсинг MTU из вывода `ifconfig`
- Потокобезопасность: `_read_lock` и `_write_lock` (threading.Lock)
- Context manager (`with TunInterface.open() as tun: ...`)

Wire format: каждый пакет на utun предваряется 4-байтным заголовком `\x00\x00\x00\x02` (AF_INET в big-endian).

**Тесты:** 36 тестов, 100% pass  
**Запуск:** `cd client && python3 -m pytest test_tun_macos.py -v`

### ЗАДАЧА 13 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `client/dns.py`, `client/test_dns.py`

Реализована DNS leak protection для macOS:
- `InterfaceDNS{interface, servers, search_domains}` — сохранённая конфигурация DNS одного интерфейса
- `DNSSnapshot{interfaces, resolv_conf}` — полный снимок DNS всех активных сетевых служб
- `take_snapshot(interfaces)` — захват текущей конфигурации DNS через `networksetup`
- `restore_snapshot(snapshot)` — восстановление оригинальной конфигурации + сброс кеша
- `_get_active_interfaces()` — перечисление активных служб через `networksetup -listallnetworkservices`
- `_get_interface_dns(iface)` / `_set_interface_dns(iface, servers, search_domains)` — чтение/запись DNS серверов и search domains
- `_build_resolv_conf()` / `_read_resolv_conf()` / `_write_resolv_conf()` — управление `/etc/resolv.conf`
- `_flush_dns_cache()` — сброс кеша через `dscacheutil -flushcache` + `killall -HUP mDNSResponder`
- `DNSLeakProtection` — основной класс: `start()`, `stop()`, `update_servers()`, context manager, потокобезопасен
- `dns_protection_for_vpn(gateway_ip)` — фабрика: создаёт DNSLeakProtection используя VPN gateway как DNS сервер

**Тесты:** 45 тестов, все pass  
**Запуск:** `cd client && python3 -m pytest test_dns.py -v`

### ЗАДАЧА 14 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `client/killswitch.py`, `client/test_killswitch.py`

Реализован VPN Kill Switch для macOS:
- `KillSwitch` — основной класс управления блокировкой трафика
- `KillSwitch.start(vpn_interface, server_ip)` — активация kill switch: загрузка PF anchor правил, блокировка всего трафика кроме разрешённых
- `KillSwitch.stop()` — деактивация: очистка anchor, восстановление PF в исходное состояние
- `KillSwitch.update(vpn_interface, server_ip)` — обновление правил без перезапуска
- `KillSwitch.get_current_rules()` — чтение текущих правил из anchor
- `create_kill_switch()` — фабричная функция

Механизм: PF anchor `com.cavadvpn.killswitch` через `pfctl`. Разрешённый трафик при активном kill switch:
- Loopback (lo0)
- DHCP (UDP порты 67/68) для сохранения LAN адреса
- Трафик к/от IP адреса VPN сервера (для переподключения)
- Весь трафик через VPN tunnel интерфейс (utunX)

Потокобезопасность: `threading.Lock`. Context manager: `with KillSwitch() as ks: ...`

**Тесты:** 49 тестов, все pass  
**Запуск:** `cd client && python3 -m pytest test_killswitch.py -v`

### ЗАДАЧА 15 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `client/reconnect.py`, `client/test_reconnect.py`

Реализован авто-реконнект с exponential backoff и health check:
- `ReconnectConfig{initial_delay, max_delay, backoff_factor, jitter, max_attempts, health_check_interval, health_check_timeout}` — конфигурация
- `ConnectionState` — перечисление состояний (DISCONNECTED/CONNECTING/CONNECTED/RECONNECTING/STOPPED)
- `ExponentialBackoff` — вычисление задержки с экспоненциальным ростом, кэпом и jitter; методы `next_delay()`, `reset()`
- `HealthChecker` — фоновый поток, каждые interval секунд проверяет `_connected`, `_mux._closed`, `_data_stream._closed`; при сбое вызывает `on_failure`
- `AutoReconnect` — главный класс: `start()`, `stop()`, `wait_connected(timeout)`, `state`, `route_info`; колбэки `on_connected`, `on_disconnected`, `on_reconnecting`; потокобезопасное управление состоянием; автоматический перезапуск при потере соединения
- `create_auto_reconnect(server_addr, ...)` — фабричная функция

Алгоритм: при обрыве соединения (health check failure или закрытие mux) — HealthChecker останавливается, VPNClient отключается, запускается цикл переподключения с exponential backoff (с jitter). При успехе — backoff сбрасывается, запускается новый HealthChecker.

**Тесты:** 37 тестов, все pass  
**Запуск:** `cd client && python3 -m pytest test_reconnect.py -v`

### ЗАДАЧА 16 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `client/traffic_shaping.py`, `client/test_traffic_shaping.py`

Реализован traffic shaping модуль для Anti-DPI — имитация паттернов браузерного HTTPS трафика:
- `TrafficProfile{name, size_buckets, min/max_inter_chunk_ms, burst_count, burst_pause_min/max_ms, padding_probability, max_padding_bytes}` — конфигурация профиля трафика
- `_sample_from_buckets(buckets)` — взвешенная случайная выборка размера пакета из кумулятивных вероятностных bucket'ов
- `encode_chunk(data, padding)` / `decode_chunk(chunk)` — wire format с 2-байтным BE заголовком длины padding; обе стороны используют одинаковый формат
- `TrafficShaper` — основной класс: `fragment(data)` фрагментирует данные согласно профилю, `encode_with_padding(chunk)` добавляет случайный padding, `shape_outgoing(data)` = fragment + encode для всех чанков, `inter_chunk_delay()` возвращает задержку с burst logic (межчанковая пауза или пауза после burst), `wait_inter_chunk()` выполняет sleep, `reset_burst()` сбрасывает счётчик, `stats()` — статистика; потокобезопасен
- `ShapedConn` — прозрачная обёртка над socket-like соединением: `write(data)` фрагментирует + кодирует + отправляет с опциональным timing, `read(max_size)` читает один shaped chunk и снимает padding, `close()` закрывает соединение
- Три встроенных профиля: `browser_profile()` (Chrome/Firefox HTTPS: 64–16383 байт, задержки 1–15 мс, burst по 8 чанков), `streaming_profile()` (YouTube/Netflix: крупные пакеты 512–16383 байт, паузы 10–50 мс), `idle_profile()` (keep-alive: 32–512 байт, паузы 500–5000 мс)
- `create_shaper(name)` — фабричная функция по имени профиля ("browser"/"streaming"/"idle")

**Тесты:** 57 тестов, все pass  
**Запуск:** `cd client && python3 -m pytest test_traffic_shaping.py -v`

### ЗАДАЧА 17 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `client/padding.py`, `client/test_padding.py`

Реализован модуль advanced padding и timing randomization против статистического анализа трафика:
- `encode_frame(data, flag, padding_len)` / `decode_frame(body)` — wire format: 4-байтный length prefix + 1-байтный flag (FLAG_DATA=0x00/FLAG_COVER=0x01/FLAG_KEEPALIVE=0x02) + 2-байтный padding_len + data + random padding
- `FixedBucketPadder(buckets)` — паддинг пакетов до ближайшего fixed bucket (TLS-aligned: 64/128/256/512/1024/1448/2896/4096/8192/16384 байт); нормализует распределение размеров для защиты от size fingerprinting; `target_frame_size(data_len)`, `compute_padding(data_len)`, поддержка кастомных bucket'ов
- `JitterConfig(distribution, min_ms, max_ms, mean_ms, std_ms)` — семплирование timing jitter из трёх распределений: UNIFORM (random.uniform), GAUSSIAN (random.gauss с зажимом), EXPONENTIAL (random.expovariate с зажимом); методы `sample_ms()`, `sample_seconds()`, `wait()`
- `CoverTrafficConfig(enabled, idle_threshold_ms, interval_ms, min_size, max_size)` — конфигурация cover-трафика
- `StatisticalObfuscator(conn, padder, jitter, cover_config)` — главный класс: `write(data)` применяет jitter + bucket padding + FLAG_DATA frame; `read()` пропускает FLAG_COVER/FLAG_KEEPALIVE и возвращает только FLAG_DATA; фоновый daemon-поток инжектирует cover-пакеты (FLAG_COVER) во время idle > threshold; `stats()` возвращает counters и overhead_ratio; потокобезопасен (_write_lock); `close()` останавливает cover-поток
- `create_obfuscator(conn, mode)` — три пресета: "light" (uniform 0–5 мс, без cover, ~5-15% overhead), "balanced" (Gaussian mean=10 мс std=5 мс + cover 200 мс threshold, ~20-40% overhead), "paranoid" (exponential mean=20 мс + cover 50 мс threshold + fine buckets до 32 байт, ~50-100% overhead)

Wire format обеспечивает статистическую неразличимость cover и реального трафика по размерам: cover-пакеты паддируются до тех же bucket'ов, что и реальные пакеты соответствующего размера.

**Тесты:** 64 теста, все pass  
**Запуск:** `cd client && python3 -m pytest test_padding.py -v`

### ЗАДАЧА 18 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `server/transport/sni.go`, `server/transport/sni_test.go`, `client/sni_spoof.py`, `client/test_sni_spoof.py`, `server/transport/obfs_test.go`

Реализован SNI spoofing — полный стек для обеих сторон:

**Go (сервер):** `server/transport/sni.go`
- `SNISelector` — интерфейс выбора домена (`Select() string`)
- `StaticSNI{Domain}` — всегда возвращает фиксированный домен
- `RandomSNI{Domains}` + `NewRandomSNI()` — случайный выбор из пула 10 легитимных доменов
- `buildSNIExtension(host)` — кодирует TLS server_name extension (RFC 6066 §3)
- `buildSupportedVersionsExtension()` — extension supported_versions с TLS 1.3
- `buildClientHelloWithSNI(sni)` — ClientHello с SNI + supported_versions
- `ExtractSNI(body)` — парсинг SNI из тела ClientHello (для логирования)
- `ObfsConn.WithSNI(selector) *ObfsConn` — builder pattern; `ClientHandshake()` включает SNI если selector установлен

**Python (клиент):** `client/sni_spoof.py`
- `DOMAIN_POOL` — 30 доменов (YouTube, Google, Cloudflare, Apple, Microsoft, GitHub, Netflix и др.)
- `RotationPolicy` — стратегия ротации: RANDOM/SEQUENTIAL/FIXED
- `SNIConfig{domains, rotation_policy, fixed_domain, alpn_protocols, include_session_ticket}` + `validate()`
- `DomainSelector` — `next_domain()` по политике
- TLS extension builders: `build_sni_extension`, `build_supported_versions_extension`, `build_supported_groups_extension`, `build_ec_point_formats_extension`, `build_alpn_extension`, `build_signature_algorithms_extension`, `build_session_ticket_extension`, `build_renegotiation_info_extension`
- `build_client_hello(sni, alpn, include_session_ticket)` — полный Chrome 120 fingerprint: 9 cipher suites, TLS 1.3+1.2, X25519/P-256/P-384, h2/http/1.1 ALPN
- `parse_server_hello(data)` — диагностический парсинг ServerHello
- `SNISpoofConn` — drop-in замена ObfsConn (client_handshake, server_handshake, write, read, read_exactly, close, active_sni)
- `create_sni_conn(sock, config)` — фабричная функция

**Тесты:** 26 тестов Go SNI + 86 тестов Python, все pass  
**Запуск (Go):** `cd server && go test ./transport/ -v -cover`  
**Запуск (Python):** `cd client && python3 -m pytest test_sni_spoof.py -v`

### ЗАДАЧА 19 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `client/menubar.py`, `client/test_menubar.py`

Реализовано macOS menubar приложение на PyObjC:
- `VPNStatus` — перечисление состояний (DISCONNECTED/CONNECTING/CONNECTED/DISCONNECTING/ERROR)
- `TrafficStats` — счётчики трафика и метаданные соединения: `bytes_in`, `bytes_out`, `connected_since`, `server_ip`, `assigned_ip`; методы `format_bytes()`, `uptime`, `ingress_label`, `egress_label`, `reset()`
- `VPNStatusModel` — потокобезопасная модель состояния: `set_status()`, `update_traffic()`, `set_server_info()`, `clear_server_info()`; регистрация колбэков `on_status_change`/`on_stats_update`; UI-хелперы `status_label()`, `menu_bar_title()`, `can_connect()`, `can_disconnect()`
- `VPNMenuBarController(NSObject)` — NSStatusItem с NSMenu; 1-секундный NSTimer обновляет иконку и все лейблы; `toggleVPN_` запускает connect/disconnect в фоновом потоке; `quitApp_` завершает приложение; `teardown()` удаляет status item
- `VPNMenuBarAppDelegate(NSObject)` — NSApplicationDelegate; устанавливает `NSApplicationActivationPolicyAccessory` (нет dock-иконки); вызывает `controller.setup()` после запуска
- `run_menubar_app(model, connect_action, disconnect_action)` — точка входа; поднимает RuntimeError на не-macOS платформах

Меню включает: заголовок со статусом, кнопку Connect/Disconnect, секцию Traffic (↓ bytes, ↑ bytes, Uptime), секцию с адресом сервера и назначенным IP, Quit CavadVPN.

**Зависимости:** `pyobjc-core>=10.0`, `pyobjc-framework-Cocoa>=10.0` (только macOS, условная установка)  
**Тесты:** 47 тестов, все pass  
**Запуск:** `cd client && python3 -m pytest test_menubar.py -v`

### ЗАДАЧА 20 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `server/api/dashboard.go`, `server/api/web/index.html`, `server/api/dashboard_test.go`

Реализована веб-панель управления VPN-сервером:
- `LogEntry{Time, Level, Message, Attrs}` — структура записи журнала (JSON-сериализуемая)
- `LogBuffer` — потокобезопасный кольцевой буфер записей лога фиксированной ёмкости; при переполнении перезаписывает самые старые записи; `NewLogBuffer(cap)`, `Add(e)`, `Entries(limit)` — чтение в хронологическом порядке
- `LogBuffer.Handler()` — возвращает `slog.Handler` (log/slog), записывающий в буфер; поддерживает `WithAttrs`, `WithGroup`, все уровни (debug/info/warn/error), типизированные атрибуты (bool, int64, float64, duration)
- `APIServer.SetLogBuffer(lb)` — подключает LogBuffer к API серверу
- `GET /api/v1/logs?limit=N` — новый аутентифицированный эндпоинт; возвращает JSON-массив LogEntry; лимит 1–1000; если буфер не задан — пустой массив
- `GET /` — веб-дашборд (HTML встроен через `//go:embed web`); не требует авторизации для загрузки статики

Веб-панель (одностраничное приложение, ванильный JS без зависимостей):
- Статус-индикатор сервера (онлайн/оффлайн, пинг /api/v1/health)
- 4 карточки статистики: активные сессии, входящий/исходящий трафик (в KiB/MiB/GiB), количество разрешённых ключей
- Таблица активных сессий: ID, назначенный IP, публичный ключ (усечённый), байты ↓↑, время подключения, длительность, кнопка «Отключить»
- Управление белым списком ключей: добавить (с валидацией 64 hex символов), удалить, индикатор «онлайн/оффлайн»
- Журнал логов: последние 200 записей, фильтр по уровню (все/error/warn/info), прокрутка с автоследованием за хвостом
- Поле ввода Bearer-токена для аутентификации запросов
- Авто-обновление каждые 5 секунд (переключаемое)

**Тесты:** 36 новых тестов (63 суммарно), покрытие пакета api 89.1%  
**Запуск:** `cd server && go test ./api/ -v -cover`

### ЗАДАЧА 21 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `scripts/install_server.ps1`, `scripts/install_server.Tests.ps1`

Реализован PowerShell автоустановщик VPN сервера для Windows Server 2019/2022:
- `Write-Log` — структурированное логирование в консоль + файл (уровни INFO/WARN/ERROR/SUCCESS)
- `Test-AdminRights` — проверка прав администратора через WindowsPrincipal
- `Get-RandomToken` — криптографически случайный hex-токен (RNGCryptoServiceProvider)
- `Test-CommandExists` — проверка наличия команды в PATH
- `Install-Go` — тихая установка Go 1.22 (MSI `/qn`) с обновлением PATH сессии
- `Install-Git` — тихая установка Git (`/VERYSILENT`) с обновлением PATH
- `Get-Repository` — git clone или git reset --hard для обновления репозитория
- `Build-Server` — компиляция сервера (`go build`, `GOOS=windows GOARCH=amd64 CGO_ENABLED=0`, с `-ldflags "-s -w"`)
- `New-ServerConfig` — генерация `config.yaml` с параметрами; не перезаписывает существующий файл
- `Install-Service` — `sc.exe create` + автозапуск + failure actions (restart 30/60/120 сек)
- `Set-FirewallRules` — `New-NetFirewallRule` для портов 443 TCP, 443 UDP, 8080 TCP
- `Enable-IPRouting` — `IPEnableRouter=1` в реестре для пересылки пакетов через TUN
- `Install-TAP` — проверка наличия TAP адаптера + предупреждение об установке Wintun/TAP-Windows
- `Start-VPNService` — запуск сервиса с проверкой статуса
- `Uninstall-Server` — stop + `sc.exe delete` + удаление правил фаервола (файлы сохраняются)
- `Show-Summary` — итоговый вывод: директория, конфиг, токен, инструкции для следующих шагов

Параметры командной строки: `-InstallDir`, `-RepoURL`, `-ListenAddr`, `-TunCIDR`, `-APIAddr`, `-APIToken`, `-SkipBuild`, `-Uninstall`. Поддерживает `-WhatIf` (SupportsShouldProcess).

**Тесты (Pester 5.x):** `scripts/install_server.Tests.ps1` — тесты всех вспомогательных функций без реальной установки  
**Запуск установщика:** `.\install_server.ps1` (от имени администратора)  
**Запуск тестов:** `Invoke-Pester .\scripts\install_server.Tests.ps1 -Output Detailed`
