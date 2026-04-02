# VPN Development Agent — Промпт для итеративной разработки

## Рабочая среда
- **Репозиторий:** `cavad93/vpn`
- **Ветка:** `claude/create-claude-md-zT6Gk`
- **Рабочая директория:** `/home/user/VPN`
- **Все изменения коммитить и пушить в эту ветку после каждой задачи**

## Git инструкция для агента
```bash
# Перед началом работы — всегда синхронизируйся
git fetch origin claude/create-claude-md-zT6Gk
git checkout claude/create-claude-md-zT6Gk
git pull origin claude/create-claude-md-zT6Gk

# После выполнения задачи — коммит и пуш
git add -A
git commit -m "feat(vpn): Task N — <название задачи>"
git push -u origin claude/create-claude-md-zT6Gk
```

---

## Проект
Разработка профессионального кастомного VPN с нуля.
- **Язык сервера:** Go 1.22+
- **Язык клиента:** Python 3.11+
- **Сервер:** Windows Server 2019 (IP: 193.124.93.240, Астана, Казахстан)
- **Клиент:** macOS Intel
- **Цель:** трафик из России маршрутизируется через сервер в Казахстане. Сайты видят казахстанский IP.

## Архитектура
```
┌─────────────────────────────────────────────────────────┐
│  CLIENT (macOS/Питер)        SERVER (Windows/Астана)     │
│                                                          │
│  ┌──────────┐                ┌──────────────────────┐   │
│  │ TUN/TAP  │                │  VPN Engine (Go)     │   │
│  │Interface │                │  - Crypto core       │   │
│  └────┬─────┘                │  - Auth & sessions   │   │
│       │                      │  - Traffic routing   │   │
│  ┌────▼──────┐  TLS1.3+QUIC  │  - DPI obfuscation   │   │
│  │ VPN Core  ├───────────────►                      │   │
│  │ (Python)  │  Port 443     └──────────┬───────────┘   │
│  │ - Crypto  │  Obfuscated              │               │
│  │ - Routes  │  traffic                 ▼               │
│  │ - DNS     │               ┌──────────────────────┐   │
│  └──────────┘                │  youtube.com,        │   │
│                              │  instagram.com etc.  │   │
└─────────────────────────────────────────────────────────┘
```

## Структура репозитория
```
/home/user/VPN/
├── VPN_AGENT_PROMPT.md     ← этот файл (статус задач)
├── CLAUDE.md               ← инструкции для Claude
├── server/                 ← Go сервер
│   ├── crypto/
│   ├── transport/
│   ├── api/
│   └── service/
├── client/                 ← Python клиент macOS
│   ├── core.py
│   ├── tun_macos.py
│   ├── dns.py
│   └── killswitch.py
├── ui/                     ← macOS menubar app
└── scripts/                ← установщики
```

## Стек технологий
- Go 1.22+ — сервер (высокая производительность, нативная компиляция под Windows)
- Python 3.11+ — клиент macOS (простота установки без Xcode)
- TLS 1.3 + X25519 — шифрование
- QUIC/UDP — транспорт (обходит TCP блокировки)
- Noise Protocol Framework — handshake (как в WireGuard)
- ChaCha20-Poly1305 — симметричное шифрование

---

## Очередь задач

### ФАЗА 1: Ядро (Crypto Layer)
- [x] **ЗАДАЧА 1:** Реализовать X25519 key exchange + ChaCha20-Poly1305 шифрование на Go. Unit тесты. `server/crypto/crypto.go`
  > Выполнено: `server/crypto/crypto.go` + тесты (11 тестов, покрытие 81.6%). Функции: GenerateKeyPair, DiffieHellman, NewCipher, Encrypt, Decrypt, GenerateNonce. Зависимость: golang.org/x/crypto@v0.32.0. Запуск: `go test ./crypto/ -v`
- [x] **ЗАДАЧА 2:** Noise_XX handshake протокол. Mutual authentication сервер↔клиент. `server/crypto/handshake.go`
  > Выполнено: `server/crypto/handshake.go` + тесты (22 теста суммарно, покрытие 80.4%). Реализован полный Noise_XX паттерн (-> e, <- e,ee,s,es, -> s,se) с mutual authentication. Функции: NewHandshake, WriteMessage1/2/3, ReadMessage1/2/3. Возвращает Session с SendCipher/RecvCipher для двунаправленного шифрования. Запуск: `cd server && go test ./crypto/ -v -cover`
- [x] **ЗАДАЧА 3:** Защита от replay атак (nonce + timestamp window 90s). `server/crypto/replay.go`
  > Выполнено: `server/crypto/replay.go` + тесты (19 тестов replay, 41 тест суммарно, покрытие 82.9%). Реализованы: PacketHeader (timestamp + nonce, encode/decode), ReplayFilter с скользящим окном ±90с. Потокобезопасен (sync.Mutex). Автоочистка устаревших bucket'ов. Запуск: `cd server && go test ./crypto/ -v -cover`

### ФАЗА 2: Транспорт (Transport Layer)
- [x] **ЗАДАЧА 4:** UDP транспорт с надёжностью (ACK, retransmit, ordering, congestion control). `server/transport/udp.go`
  > Выполнено: `server/transport/udp.go` + тесты (25 тестов, покрытие 90.7%). Реализованы: Packet (Encode/DecodePacket), Conn (Write/Read/Close + processData/processACK/doRetransmit), Listener (Listen/Accept), Dial. Congestion control: TCP Reno-style slow start + multiplicative decrease. Ordering: sliding receive buffer с дренажём. Запуск: `cd server && go test ./transport/ -v -cover`
- [x] **ЗАДАЧА 5:** Обфускация под HTTPS/TLS — трафик неотличим от браузерного HTTPS для DPI. `server/transport/obfs.go`
  > Выполнено: `server/transport/obfs.go` + тесты (15 тестов, покрытие 90.8% пакет transport). Реализованы: ObfsConn (NewObfsConn, ClientHandshake, ServerHandshake, Write, Read, Close + net.Conn deadline интерфейс), buildClientHello/buildServerHello (синтетические TLS 1.3 записи с рандомными полями random/session_id), buildAppDataRecord, wrapHandshakeRecord. Трафик выглядит как TLS 1.2/1.3 для DPI: content_type=0x17, version=0x0303, big-endian length. Поддержка фрагментации больших сообщений (>16383 байт) и буферизация частичных Read. Запуск: `cd server && go test ./transport/ -v -cover`
- [x] **ЗАДАЧА 6:** Multiplexing — несколько виртуальных каналов в одном UDP соединении. `server/transport/mux.go`
  > Выполнено: `server/transport/mux.go` + тесты (14 тестов mux, 90.0% coverage пакет transport). Реализованы: Mux (NewMux, OpenStream, AcceptStream, Close, writeFrame, readLoop), Stream (Write, Read, Close, ID). Клиент использует чётные stream ID (2,4,6…), сервер — нечётные (1,3,5…). Wire format: 7-байтный заголовок (streamID uint32 + type uint8 + length uint16). Фреймы: FrameSYN (открытие), FrameData (данные), FrameFIN (закрытие). Фрагментация больших сообщений (>65535 байт). Потокобезопасность: writeMu для записи, streamsMu для map. Запуск: `cd server && go test ./transport/ -v -cover`

### ФАЗА 3: Сервер Go
- [x] **ЗАДАЧА 7:** VPN сервер — принимает соединения, аутентифицирует, маршрутизирует трафик. `server/main.go`
  > Выполнено: `server/main.go` + `server/tun_linux.go` + `server/tun_stub.go` + тесты (покрытие 80.2%). Реализованы: Server (Run, Sessions, DisconnectSession), handleConn (ObfsConn + Noise_XX handshake + noiseConn + Mux), handleControlStream (IP assignment с протоколом ctlHello/ctlAssign), handleDataStream (чтение IP пакетов → TUN), routeFromTun (TUN → client data stream), ipPool (аллокация/релиз IPv4 адресов), noiseConn (шифрование всего трафика через Noise session cipher), loadOrGenerateKeyPair. Linux TUN через /dev/net/tun + ioctl TUNSETIFF. Запуск: `cd server && go test . -v -cover`
- [x] **ЗАДАЧА 8:** Управление клиентами через REST API (добавление/удаление/статистика). `server/api/api.go`
  > Выполнено: `server/api/api.go` + тесты (27 тестов, покрытие 87.2%). Реализованы: `SessionInfo` (тип сессии), `ServerIface` (интерфейс VPN-сервера для API), `APIServer` (NewAPIServer, Run, Handler). Эндпоинты: GET /health (без авторизации), GET/DELETE /sessions, GET/DELETE /sessions/{id}, GET /keys, POST /keys, DELETE /keys/{key}, GET /stats. Авторизация: Bearer-токен (Authorization: Bearer <token>) или X-API-Key заголовок. В `server/main.go` добавлены методы AddAllowedKey/RemoveAllowedKey/AllowedKeys к Server, SessionStats = api.SessionInfo (type alias), startAPIServer() helper, флаги -api-addr и -api-token. Запуск: `cd server && go test ./api/ -v -cover`
- [x] **ЗАДАЧА 9:** Windows Service враппер — запуск как служба Windows. `server/service/windows_service.go`
  > Выполнено: `server/service/windows_service.go` (build tag: windows) + `server/service/service_stub.go` (build tag: !windows) + тесты (9 тестов, покрытие 100%). Реализованы: `RunFunc` (тип функции запуска сервера), `vpnService` (implements svc.Handler), `RunAsService(name, run, logger)` — запуск под управлением SCM, `IsWindowsService()` — определение режима запуска, `Install(name, displayName, description, exePath)` — регистрация службы в SCM, `Remove(name)` — удаление службы. Логика: SCM посылает Stop/Shutdown → отменяется context → сервер останавливается (таймаут 30с). Ошибка запуска сервера → Win32 exit code 1. Константы: DefaultServiceName="CavadVPN", DefaultDisplayName, DefaultDescription. Зависимость: `golang.org/x/sys/windows/svc`. На не-Windows платформах все функции возвращают `ErrNotWindows`. Запуск: `cd server && go test ./service/ -v -cover`
- [x] **ЗАДАЧА 10:** Конфигурация через YAML, генерация ключей при первом запуске. `server/config/config.go`
  > Выполнено: `server/config/config.go` + тесты (24 теста, покрытие 85.3%). Реализованы: `ServerConfig` (Listen, TunCIDR, PrivateKeyFile, AllowedKeys, API, Log), `APIConfig` (Listen, Token), `LogConfig` (Level, Format). Функции: `Default()` — значения по умолчанию, `Load(path)` — чтение YAML (создаёт файл с defaults если отсутствует), `Save(path, cfg)` — сохранение YAML (режим 0600, создаёт директории), `Validate()` — проверка полей, `ParseAllowedKeys()` — декодирование hex ключей в [32]byte, `EnsureKeyFile(path)` — генерация/загрузка X25519 приватного ключа (RFC 7748 clamp, режим 0600). Зависимость: `gopkg.in/yaml.v3 v3.0.1`. Запуск: `cd server && go test ./config/ -v -cover`

### ФАЗА 4: Клиент Python (macOS)
- [x] **ЗАДАЧА 11:** Подключение к серверу, Noise handshake, получение маршрутов. `client/core.py`
  > Выполнено: `client/core.py` + `client/test_core.py` + `client/requirements.txt` (58 тестов, покрытие 91%). Реализованы: `KeyPair` (generate_key_pair, load_key_pair_from_file, dh), `noise_hkdf` (HMAC-SHA256, 2 или 3 выхода), `NoiseCipherState` (ChaCha20-Poly1305, нonce = 4 нулевых + 8-байт LE счётчик), `NoiseSymmetricState` (mixHash, mixKey, encryptAndHash, decryptAndHash, split), `NoiseHandshake` (инициатор Noise_XX: write_message1/read_message2/write_message3), `ObfsConn` (клиент TLS obfuscation: client_handshake, read, write, server_handshake), `NoiseConn` (шифрование с 2-байт BE length prefix), `MuxStream` (read, write, read_exactly, close, поддержка FIN), `ClientMux` (четные stream ID 2,4,6…, фоновый read_loop), `RouteInfo` (assigned_ip, prefix_len, gateway, cidr, network), `VPNConfig`, `VPNClient` (connect, disconnect, send_packet, recv_packet). Зависимости: cryptography>=41.0.0, structlog>=23.0.0. Запуск: `cd client && python3 -m pytest test_core.py -v`
- [x] **ЗАДАЧА 12:** TUN интерфейс на macOS — перехват всего системного трафика. `client/tun_macos.py`
  > Выполнено: `client/tun_macos.py` + `client/test_tun_macos.py` (36 тестов, 100% pass). Реализованы: `TunInterface` (open, configure, read_packet, write_packet, add_route, delete_route, add_default_route, delete_default_route, close, context manager), `get_default_gateway()` — парсинг вывода netstat, `get_interface_mtu()` — парсинг ifconfig. Интерфейс открывается через AF_SYSTEM/SYSPROTO_CONTROL socket + CTLIOCGINFO ioctl + connect(sockaddr_ctl). Чтение/запись с 4-байтным utun-заголовком (AF_INET = 0x00000002). Конфигурация через ifconfig и route команды. Потокобезопасность: read_lock и write_lock. Запуск: `cd client && python3 -m pytest test_tun_macos.py -v`
- [x] **ЗАДАЧА 13:** DNS leak protection — все DNS запросы через туннель. `client/dns.py`
  > Выполнено: `client/dns.py` + `client/test_dns.py` (45 тестов, все pass). Реализованы: `InterfaceDNS` / `DNSSnapshot` (сохранение конфигурации DNS по интерфейсам), `take_snapshot()` / `restore_snapshot()` — сохранение и восстановление настроек всех сетевых служб через `networksetup`, `_get_active_interfaces()` — обнаружение активных служб, `_get_interface_dns()` / `_set_interface_dns()` — чтение/запись DNS для конкретного интерфейса, `_build_resolv_conf()` / `_read_resolv_conf()` / `_write_resolv_conf()` — управление `/etc/resolv.conf`, `_flush_dns_cache()` — сброс кеша через `dscacheutil` + `killall -HUP mDNSResponder`, `DNSLeakProtection` — основной класс (start/stop/update_servers, context manager, thread-safe), `dns_protection_for_vpn(gateway_ip)` — фабричная функция. Запуск: `cd client && python3 -m pytest test_dns.py -v`
- [x] **ЗАДАЧА 14:** Kill switch — полная блокировка трафика при обрыве VPN. `client/killswitch.py`
  > Выполнено: `client/killswitch.py` + `client/test_killswitch.py` (49 тестов, все pass). Реализованы: `KillSwitch` — основной класс (start, stop, update, get_current_rules, context manager, thread-safe), `create_kill_switch()` — фабричная функция. Механизм: PF anchor `com.cavadvpn.killswitch` через `pfctl`. При `start(vpn_iface, server_ip)` загружаются правила блокирующие весь трафик кроме: loopback (lo0), DHCP (UDP 67/68), трафика к/от VPN сервера, трафика через TUN интерфейс. При `stop()` anchor очищается, PF отключается если был выключен до старта. `update()` обновляет правила без полного перезапуска. Запуск: `cd client && python3 -m pytest test_killswitch.py -v`
- [x] **ЗАДАЧА 15:** Auto-reconnect с exponential backoff + health check. `client/reconnect.py`
  > Выполнено: `client/reconnect.py` + `client/test_reconnect.py` (37 тестов, все pass). Реализованы: `ReconnectConfig` (initial_delay, max_delay, backoff_factor, jitter, max_attempts, health_check_interval, health_check_timeout), `ConnectionState` (DISCONNECTED/CONNECTING/CONNECTED/RECONNECTING/STOPPED), `ExponentialBackoff` (next_delay, reset, attempt; задержка с кэпом и jitter), `HealthChecker` (фоновый поток, проверяет _connected/_mux/_data_stream каждые interval секунд, вызывает on_failure при сбое), `AutoReconnect` (start/stop/wait_connected, on_connected/on_disconnected/on_reconnecting колбэки, потокобезопасное управление состоянием, автоперезапуск при потере соединения), `create_auto_reconnect()` — фабричная функция. Запуск: `cd client && python3 -m pytest test_reconnect.py -v`

### ФАЗА 5: Anti-DPI обфускация
- [x] **ЗАДАЧА 16:** Traffic shaping — имитация паттернов браузерного трафика (размеры пакетов, задержки).
  > Выполнено: `client/traffic_shaping.py` + `client/test_traffic_shaping.py` (57 тестов, все pass). Реализованы: `TrafficProfile` (name, size_buckets, inter-chunk delays, burst parameters, padding probability), `_sample_from_buckets()` — взвешенная выборка размера пакета из вероятностных bucket'ов, `encode_chunk(data, padding)` / `decode_chunk(chunk)` — wire format с 2-байтным BE заголовком длины padding, `TrafficShaper` (fragment, encode_with_padding, shape_outgoing, inter_chunk_delay, wait_inter_chunk, reset_burst, stats — потокобезопасен), `ShapedConn` — прозрачная обёртка над socket-like соединением (write с фрагментацией + timing, read со снятием padding), три встроенных профиля: `browser_profile()` (имитирует Chrome/Firefox: 64–16383 байт, задержки 1–15 мс, bursts по 8), `streaming_profile()` (YouTube/Netflix: крупные пакеты, минимальные задержки), `idle_profile()` (keep-alive: маленькие пакеты, длинные паузы), `create_shaper(name)` — фабричная функция. Запуск: `cd client && python3 -m pytest test_traffic_shaping.py -v`
- [x] **ЗАДАЧА 17:** Padding и timing рандомизация против статистического анализа трафика.
  > Выполнено: `client/padding.py` + `client/test_padding.py` (64 теста, все pass). Реализованы: `encode_frame(data, flag, padding_len)` / `decode_frame(body)` — wire format с 4-байтным length prefix + 1-байтным flag (FLAG_DATA/FLAG_COVER/FLAG_KEEPALIVE) + 2-байтным padding_len; `FixedBucketPadder(buckets)` — паддинг до ближайшего fixed bucket (TLS-aligned: 64/128/256/512/1024/1448/… байт), полностью нормализует распределение размеров пакетов; `JitterConfig(distribution, min_ms, max_ms, mean_ms, std_ms)` — семплирование задержки из трёх распределений (UNIFORM, GAUSSIAN, EXPONENTIAL) с зажимом в [min, max]; `CoverTrafficConfig` — параметры фонового cover-трафика (idle_threshold_ms, interval_ms, min/max_size); `StatisticalObfuscator(conn, padder, jitter, cover_config)` — основной класс: `write(data)` добавляет jitter + bucket padding + FLAG_DATA, `read()` пропускает FLAG_COVER/FLAG_KEEPALIVE и возвращает только реальные данные, фоновый поток инжектирует cover-пакеты во время простоя, `stats()` возвращает метрики overhead; `create_obfuscator(conn, mode)` — три пресета: "light" (uniform jitter 0–5 мс, без cover), "balanced" (Gaussian jitter + cover каждые 500 мс), "paranoid" (exponential jitter + cover каждые 100 мс, мелкие buckets). Запуск: `cd client && python3 -m pytest test_padding.py -v`
- [ ] **ЗАДАЧА 18:** SNI spoofing — подделка Server Name Indication под легитимные домены.

### ФАЗА 6: UI и удобство
- [ ] **ЗАДАЧА 19:** macOS menubar иконка на PyObjC (вкл/выкл, статус, статистика трафика).
- [ ] **ЗАДАЧА 20:** Веб-панель управления сервером (статистика, логи, управление клиентами).
- [ ] **ЗАДАЧА 21:** Автоустановщик сервера (PowerShell скрипт для Windows).
- [ ] **ЗАДАЧА 22:** Автоустановщик клиента (.pkg установщик для macOS).

---

## Инструкция для агента при каждом запуске

1. Прочитай этот файл (`VPN_AGENT_PROMPT.md`)
2. Найди **первую** задачу с `[ ]` (не выполненную)
3. Реализуй её **полностью** — код, тесты, документация
4. Убедись что код **компилируется и тесты проходят**
5. Отметь задачу как `[x]` в этом файле
6. Запиши краткий отчёт под задачей: что сделано, как запустить
7. Сделай **git commit и git push** в ветку `claude/create-claude-md-zT6Gk`
8. **Останови работу** — следующую задачу возьмёт следующий запуск

## Стандарты кода
- **Go:** gofmt, golint, покрытие тестами >80%, structured logging (zerolog)
- **Python:** black formatter, type hints везде, docstrings, structlog
- Все ошибки обрабатываются явно — никаких `panic`, никаких `except: pass`
- Конфигурация только через YAML файлы — никакого хардкода
- Секреты (ключи, пароли) — только через env переменные или файлы с правами 600
- Каждый модуль имеет README с описанием и примером использования
