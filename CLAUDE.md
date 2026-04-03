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

### ЗАДАЧА 22 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `scripts/install_client.sh`, `scripts/macos_pkg/`, `client/cavadvpn_cli.py`

Реализован macOS .pkg установщик VPN клиента:
- `install_client.sh` — основной bash скрипт сборки .pkg (требует macOS + Xcode CLT)
- `parse_args` — разбор аргументов: `--version`, `--output-dir`, `--repo-path`, `--sign-identity`, `--notarize`, `--apple-id`, `--apple-password`, `--team-id`
- `validate_args` — валидация: проверка наличия client/ директории, обязательных полей для нотаризации
- `prepare_dirs` — создание временных директорий payload/scripts/resources
- `copy_client_files` — копирование Python модулей клиента в `/Applications/CavadVPN/`
- `build_component_pkg` — `pkgbuild` — компонентный пакет с payload + scripts
- `build_distribution_pkg` — `productbuild` — финальный .pkg с UI ресурсами
- `notarize_pkg` — `xcrun notarytool submit` + `xcrun stapler staple` (опционально)
- `verify_pkg` — `pkgutil --check-signature` + листинг содержимого

**Инсталляционные скрипты** (`scripts/macos_pkg/scripts/`):
- `preinstall` — проверяет macOS 12+, arch x86_64/arm64, Python 3.11+
- `postinstall` — создаёт venv, `pip install -r requirements.txt`, CLI wrapper `/usr/local/bin/cavadvpn`, LaunchAgent `~/Library/LaunchAgents/com.cavadvpn.client.plist`
- `preuninstall` — выгружает LaunchAgent, удаляет CLI wrapper, останавливает процессы

**Ресурсы установщика** (`scripts/macos_pkg/resources/`):
- `welcome.html`, `readme.html`, `license.html`, `conclusion.html` — экраны installer GUI
- `distribution.xml` — описание пакета для productbuild (минимальная macOS 12, x86_64+arm64)

**CLI точка входа** (`client/cavadvpn_cli.py`):
- Команды: `connect [--server HOST:PORT]`, `disconnect`, `status`, `config [--set KEY=VAL]`, `version`
- Читает/пишет конфиг `~/.config/cavadvpn/config.yaml`
- PID-файл для отслеживания активного соединения

**Тесты:** 70 тестов, все pass (работают на Linux без macOS-специфичных инструментов)  
**Запуск тестов:** `bash scripts/test_install_client.sh`  
**Сборка .pkg (только macOS):** `bash scripts/install_client.sh --version 1.0.0`

### ЗАДАЧА 23 — ВЫПОЛНЕНО (2026-04-02)
**Файлы:** `android/app/src/main/java/com/cavadvpn/`

Реализован Android VPN стек на Kotlin:
- `crypto/CryptoCore.kt` — X25519 (BouncyCastle) + ChaCha20-Poly1305 AEAD; `generateKeyPair`, `diffieHellman`, `encrypt`, `decrypt`, `generateNonce`
- `crypto/NoiseHandshake.kt` — Noise_XX инициатор; `NoiseCipherState` (nonce: 4 нулевых байта + 8-байт LE счётчик), `NoiseSymmetricState` (mixHash/mixKey/encryptAndHash/decryptAndHash/split), `NoiseHandshake` (writeMessage1/readMessage2/writeMessage3), `NoiseSession`
- `crypto/ReplayFilter.kt` — `PacketHeader` (encode/decode, 20 байт), `ReplayFilter` (скользящее окно ±90с, synchronized)
- `transport/ObfsConn.kt` — TLS-обфускация: синтетические ClientHello/ServerHello, фрагментация в TLS app_data records (max 16383 байт), read-буферизация
- `transport/MuxConn.kt` — `NoiseConn` (2-байт BE length + шифрование), `MuxStream` (BlockingQueue, readExactly), `ClientMux` (чётные stream ID, фоновый read-loop, writeFrame)
- `config/VpnConfig.kt` — `VpnConfig` data class, `RouteInfo` (assignedIp/prefixLen/gateway/cidr/network)
- `vpn/VpnClient.kt` — полный стек: TCP → ObfsConn → Noise_XX → NoiseConn → ClientMux → control stream (ctlHello/ctlAssign) → data stream; `connect()`, `sendPacket()`, `recvPacket()`, `disconnect()`
- `vpn/CavadVpnService.kt` — Android `VpnService`; `setupTunnel()` (VpnService.Builder + addAddress/addRoute/addDnsServer), `runTunnel()` (bidirectional coroutine forwarding), foreground notification

Протокол wire-совместим с Go сервером (ObfsConn, Noise framing, Mux frame format, control protocol).

**Тесты:** 39 тестов (CryptoCoreTest×11, NoiseHandshakeTest×9, ReplayFilterTest×9, ObfsConnTest×5, MuxConnTest×5)  
**Запуск:** `cd android && ./gradlew test`

### ЗАДАЧА 29 — ВЫПОЛНЕНО (2026-04-03)
**Файлы:** `server/api/qr.go`, `server/api/qr_test.go`

Реализован QR-код генератор на сервере для раздачи конфигов клиентам:
- `QRServerIface{PublicKey() [32]byte, VPNListenAddr() string}` — интерфейс, который реализует `*Server`
- `ClientConfig{Host, Port, PrivateKey, ServerKey, DNS}` — конфиг клиента (JSON-сериализуемый)
- `configURI(cfg)` — строит `cavadvpn://config?...` URI совместимый с Android/iOS парсерами
- `APIServer.SetQRServer(qrs)` — подключает QR сервер и регистрирует маршруты
- `POST /api/v1/qr/generate` — генерирует новую X25519 пару ключей, добавляет публичный ключ в allowlist, возвращает QR-код PNG (256×256, github.com/skip2/go-qrcode)
- `GET /api/v1/qr/generate` — то же самое (удобно открывать из браузера)
- `GET /api/v1/qr/generate?format=json` — возвращает JSON конфиг вместо PNG
- `GET /api/v1/qr/generate?dns=8.8.8.8` — кастомный DNS сервер
- `GET /api/v1/qr/server-info` — публичный ключ и адрес сервера без генерации клиентского ключа
- Все эндпоинты защищены Bearer-токеном/X-API-Key (если настроен APIToken)
- В `Server` добавлены: `PublicKey() [32]byte`, `VPNListenAddr() string`
- В `startAPIServer()` автоматически вызывается `apiSrv.SetQRServer(srv)`
- `splitHostPort()` нормализует wildcard адреса (0.0.0.0, ::) в пустую строку

**Сценарий использования:** Admin открывает `GET /api/v1/qr/generate` в браузере → сканирует QR телефоном → VPN автоматически настроен.

**Зависимость:** `github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e`  
**Тесты:** 14 новых тестов, покрытие пакета api 83.5%  
**Запуск:** `cd server && go test ./api/ -v -cover`

### ОПТИМИЗАЦИЯ СКОРОСТИ — ВЫПОЛНЕНО (2026-04-03)
**Файл:** `server/transport/mux.go`

Два улучшения производительности mux слоя:

1. **sync.Pool для mux фреймов** — `writeFrame` использует пул pre-allocated буферов (muxHeaderSize+1500 байт) вместо `make()` на каждый пакет. Пакеты размером ≤1500 байт (типичный MTU VPN) берутся из пула без выделения памяти. Оценочный выигрыш: -1 heap alloc per IP packet, снижение давления на GC при 10 Mbps трафике.

2. **Zero-copy readBuf в consumeData** — остаток пакета при частичном `Read` теперь сохраняется как sub-slice (zero-copy) вместо `make+copy`. Каждый буфер из `readLoop` — отдельный fresh alloc, aliasing отсутствует. Экономия: -1 alloc per partial read.

### ЗАДАЧА 30 — ВЫПОЛНЕНО (2026-04-03)
**Файл:** `server/api/invite.go`, `server/api/invite_test.go`

Реализована система пригласительных ссылок:
- `InviteRecord{Token, URL, Config, CreatedAt, ExpiresAt, Uses, MaxUses, Note}` — запись приглашения
- `InviteStore` — потокобезопасное in-memory хранилище (RWMutex + map)
- `generateInviteToken()` — crypto/rand 32-байтный hex токен (64 символа)
- `APIServer.SetInviteServer()` — регистрирует все маршруты системы приглашений

Эндпоинты (с аутентификацией):
- `POST /api/v1/invites` — создать приглашение; генерирует клиентский X25519 ключ, добавляет в allowlist, возвращает запись с URL
- `GET /api/v1/invites` — список всех приглашений
- `DELETE /api/v1/invites/{token}` — отозвать приглашение

Публичные эндпоинты (без аутентификации):
- `GET /join/{token}` — HTML страница с определением платформы (iOS/Android/macOS/Windows/Universal) по User-Agent; содержит cavadvpn:// deep link, кнопку скачивания JSON конфига, QR-код
- `GET /join/{token}/config.json` — JSON конфиг для ручного импорта (attachment download)
- `GET /join/{token}/qr.png` — QR-код PNG с cavadvpn:// URI

Функции HTML страницы: определение платформы по UA, HTML escape XSS-защита, cavadvpn:// deep link, QR-код, мета-информация (сервер/DNS/срок/счётчик открытий), раздел с технической ссылкой, адаптивный дизайн.

Параметры приглашения: `ttl_hours` (срок действия), `max_uses` (лимит использований), `note` (заметка), `dns` (DNS сервер клиента).

**Тесты:** 17 новых тестов, покрытие пакета api 83.1%  
**Запуск:** `cd server && go test ./api/ -v -cover`

### ОПТИМИЗАЦИЯ СКОРОСТИ — ВЫПОЛНЕНО (2026-04-03)
**Файл:** `server/transport/udp.go`

Два улучшения производительности UDP транспорта:

1. **sync.Pool для ACK буферов** — `ackBufPool` poolит 11-байтные буферы для pure ACK пакетов. `sendACK()` берёт буфер из пула, заполняет и возвращает — устраняет одно heap-выделение на каждый входящий DATA пакет. Оценочный выигрыш: -1 alloc/packet, снижение GC при 10 Mbps трафике.

2. **Delayed ACK coalescing (RFC 1122 §4.2.3.2)** — вместо немедленной отправки ACK после каждого DATA пакета, планируется `time.AfterFunc(1ms)`. Несколько пакетов, пришедших в одном burst, получают единый кумулятивный ACK. Экономия: до -50% ACK пакетов при устойчивой загрузке канала, освобождение пропускной способности для данных. При Close() таймер останавливается и финальный ACK отправляется синхронно.

### ЗАДАЧА 31 — ВЫПОЛНЕНО (2026-04-03)
**Файлы:** `server/notify/notify.go`, `server/notify/notify_test.go`, `server/api/notify_api.go`

Реализованы push уведомления на телефон для событий VPN:
- `NtfyNotifier` — отправка через ntfy.sh (или self-hosted инстанс). Пользователь устанавливает бесплатное приложение ntfy и подписывается на уникальный топик. Не требует Apple/Google аккаунтов.
- `WebhookNotifier` — POST JSON-уведомление на произвольный HTTP endpoint с опциональным `X-Webhook-Secret` заголовком.
- `Notification{Title, Message, Priority, Tags}` — единый тип сообщения для всех бэкендов.
- `NotificationService` — управляет подписчиками (RWMutex), асинхронная очередь (256 буфер), `worker()` горутина; методы: `AddSubscriber`, `RemoveSubscriber`, `Subscribers`, `GetSubscriber`, `SendTest`, `Notify`, `NotifySessionConnected`, `NotifySessionDisconnected`, `NotifyServerDown`, `Stop`.
- Интеграция в `server/main.go`: `Server.notifSvc` создаётся в `startAPIServer()`; события fire-and-forget — никогда не блокируют VPN data path; нотификация о подключении — после IP assignment в `handleControlStream`; нотификация об отключении — в defer `handleConn`.
- REST API (все с аутентификацией): `GET /api/v1/notifications`, `POST /api/v1/notifications`, `DELETE /api/v1/notifications/{id}`, `POST /api/v1/notifications/{id}/test`.

**Тесты:** 24 теста, покрытие 96.5%
**Запуск:** `cd server && go test ./notify/ -v -cover`

### ОПТИМИЗАЦИЯ СКОРОСТИ — ВЫПОЛНЕНО (2026-04-03)
**Файлы:** `server/notify/notify.go`, `server/main.go`

Два улучшения производительности:

1. **Параллельная доставка уведомлений** — вместо последовательной отправки по подписчикам, каждый получает горутину (fire-and-forget). Медленный webhook не блокирует остальных и не блокирует очередь. Worker мгновенно переходит к следующему событию — VPN data path никогда не затрагивается.

2. **sync.Pool для 64 KB буферов в handleDataStream** — `streamReadBufPool` пулит 65536-байтные буферы чтения. До оптимизации: каждая сессия делала `make([]byte, 65536)` при старте — при мобильных клиентах с частыми reconnect это создаёт GC pressure. После: буфер берётся из пула и возвращается при завершении сессии. Экономия: -1 heap alloc per session, снижение пауз GC при 50+ одновременных клиентах.

### ЗАДАЧА 32 — ВЫПОЛНЕНО (2026-04-03)
**Файлы:** `client/autoupdate.py`, `client/test_autoupdate.py`, `server/api/update_api.go`, `server/api/update_api_test.go`

Реализовано автообновление клиента без участия пользователя:
- `UpdateInfo{version, download_url, sha256, release_notes, min_os_version}` — метаданные обновления; `is_newer_than(current)` — семантическое сравнение версий
- `UpdateConfig` — конфигурация: update_url, check_interval_s, timeout_s, auto_install, колбэки on_update_available/installed/error
- `UpdateState` — состояния жизненного цикла: IDLE/CHECKING/DOWNLOADING/INSTALLING/RESTART_PENDING/UP_TO_DATE/ERROR
- `_VersionParser` — парсинг JSON версии с endpoint
- `_Downloader` — потоковая загрузка чанками 64 KB с SHA-256 верификацией на лету (не держит весь файл в памяти)
- `_Installer` — macOS .pkg через `installer -pkg` или .zip с атомарной заменой файлов (backup → replace → cleanup)
- `AutoUpdater` — фоновый daemon thread: `start()`, `stop()`, `check_now()`, `install_pending()`; 60-секундная задержка перед первой проверкой чтобы не конкурировать со стартом VPN
- `create_auto_updater()` — фабричная функция

Сервер (Go): `ClientVersionInfo` (JSON структура), `updateStore` (RWMutex), `GET /api/v1/client/version` — публичный endpoint, `POST /api/v1/client/version` — защищённый endpoint для обновления версии

**Тесты:** 46 тестов Python + 6 тестов Go, все pass
**Запуск:** `cd client && python3 -m pytest test_autoupdate.py -v`; `cd server && go test ./api/ -v -cover`

### ЗАДАЧА 33 — ВЫПОЛНЕНО (2026-04-03)
**Файлы:** `client/multiserver.py`, `client/test_multiserver.py`

Реализована multi-server поддержка с автоматическим переключением:
- `ServerEndpoint{addr, name, connect_timeout}` — одна запись в пуле серверов; `to_vpn_config(key_pair)` — строит VPNConfig для подключения
- `SelectionPolicy` — стратегия выбора: PRIORITY (всегда с 0-го, advance при failures), ROUND_ROBIN (циклический), FASTEST (по измеренной latency)
- `MultiServerConfig` — конфигурация: servers, policy, probe_timeout, initial_delay, max_delay, backoff_factor, max_attempts_per_server, health_check_interval
- `_probe_latency(addr, timeout)` — TCP-замер RTT; возвращает float('inf') при недоступности
- `_probe_all(servers, timeout)` — параллельные замеры (daemon thread на каждый сервер), возвращает отсортированный список (fastest first)
- `ServerSelector` — потокобезопасный выбор сервера: `prime()` — latency probe для FASTEST (идемпотентен), `reprobe()` — сброс кеша, `get(failure_count)` — следующий сервер согласно политике, `current_index(failure_count)` — индекс без объекта
- `MultiServerState` — состояния: IDLE/CONNECTING/CONNECTED/RECONNECTING/STOPPED
- `MultiServerManager(config, key_pair)` — основной класс: `start()`, `stop()`, `wait_connected(timeout)`, `active_endpoint`, `route_info`; колбэки `on_connected(ep, route)`, `on_disconnected(ep, exc)`, `on_switching(old_ep, new_ep, attempt)`; exponential backoff между попытками; фоновый health-check поток
- `create_multi_server_manager(addrs, ...)` — фабричная функция по списку host:port строк

**Perf 1:** `_get_cached_vpn_config` — кеш VPNConfig объектов по (endpoint_id, key_pair_id) — zero alloc на hot reconnect path при reconnect storms (> 10 Hz).
**Perf 2:** `ServerSelector.get()` снимает lock за O(1) (snapshot ссылки на список вместо копии), вычисляет индекс сервера вне critical section — исключает lock contention при одновременных вызовах из reconnect loop.

**Тесты:** 42 теста, все pass
**Запуск:** `cd client && python3 -m pytest test_multiserver.py -v`

### ОПТИМИЗАЦИЯ СКОРОСТИ — ВЫПОЛНЕНО (2026-04-03)
**Файлы:** `client/autoupdate.py`

Два улучшения производительности:

1. **60-секундная задержка первой проверки** — `_run_loop` ждёт 60 с перед первым обращением к update_url. VPN-туннель успевает полностью подняться прежде чем появится любой фоновый HTTP-трафик обновлений. Задержка прерывается через `stop_event.wait()` — `stop()` немедленно завершает поток.

2. **Стриминговая загрузка 64 KB чанками** — `_Downloader.download()` читает ответ чанками `_DOWNLOAD_CHUNK_SIZE = 65536` байт, совпадающими с `streamReadBufPool` на сервере. SHA-256 обновляется инкрементально на лету — весь файл обновления никогда не находится в памяти целиком. Это устраняет GC pause при загрузке обновления во время активного VPN-соединения.

### ЗАДАЧА 34 — ВЫПОЛНЕНО (2026-04-03)
**Файлы:** `client/split_tunnel.py`, `client/test_split_tunnel.py`

Реализован split tunneling — выбор каких приложений/подсетей идут через VPN, каких напрямую:
- `SplitTunnelMode` — режим работы: EXCLUDE (перечисленные приложения обходят VPN), INCLUDE (только перечисленные используют VPN)
- `AppRule{process_name, bundle_id}` — правило для одного приложения (подстрока имени процесса или macOS bundle ID)
- `SplitTunnelConfig{mode, apps, bypass_subnets, scan_interval}` — полная конфигурация
- `_PrefixIndex` — отсортированный список `IPv4Network` для O(log n) проверки принадлежности IP к bypass-подсети; используется для skip-оптимизации при добавлении динамических маршрутов
- `_RouteManager(gateway, interface)` — управление маршрутами: `add_bypass_host(ip)`, `add_bypass_subnet(cidr)`, `remove_host(ip)`, `remove_all()`; идемпотентные операции; обрабатывает "File exists" как успех
- `_ProcessMonitor` — мониторинг процессов: `pids_for_rule(rule)` через `pgrep`/`osascript`; `connection_ips(rule)` — `lsof -i 4 -p PID` для получения remote IPs; встроенный PID-кеш исключает повторные `lsof` вызовы при неизменном наборе PIDs
- `SplitTunnel(config, vpn_interface, original_gateway, original_interface)` — главный класс: `start()`, `stop()`, `add_app(rule)`, `remove_app(process_name)`, `add_bypass_subnet(cidr)`; фоновый daemon-поток сканирует соединения приложений
- `_get_default_gateway()` — парсинг текущего шлюза из `netstat -rn`
- `create_split_tunnel(mode, apps, bypass_subnets, vpn_interface, ...)` — фабричная функция

Алгоритм: VPN устанавливает маршрут по умолчанию через туннель. Для bypassed IP/подсетей добавляются более специфичные маршруты через оригинальный LAN-шлюз — ядро автоматически предпочитает более специфичный маршрут.

**Два улучшения производительности:**
1. **`_PrefixIndex` — O(log n) lookup подсетей** — при каждом добавлении динамического bypass-маршрута проверяем, не покрыт ли IP уже статической bypass-подсетью. `_PrefixIndex` хранит сети в отсортированном виде (prefixlen DESC, network_address ASC) для быстрого поиска. Без этого — O(n) линейный скан по всем bypass_subnets на каждый обнаруженный IP.
2. **PID-cache в `_ProcessMonitor`** — `lsof` — тяжёлый системный вызов (~50 мс). `connection_ips()` сначала запускает `pgrep` (~1 мс) и сравнивает PID set с кешем. Если PIDs не изменились — возвращает кешированные IPs без запуска `lsof`. Экономия: для стабильных долго-живущих приложений (браузер, банковское приложение) — 0 вызовов `lsof` после первого скана.

**Тесты:** 54 теста, все pass
**Запуск:** `cd client && python3 -m pytest test_split_tunnel.py -v`
