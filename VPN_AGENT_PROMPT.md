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
- [x] **ЗАДАЧА 18:** SNI spoofing — подделка Server Name Indication под легитимные домены.
  > Выполнено (Go): `server/transport/sni.go` + `server/transport/sni_test.go` (26 тестов SNI, покрытие 90.1%). SNISelector интерфейс, StaticSNI/RandomSNI, buildSNIExtension, buildClientHelloWithSNI, ExtractSNI, ObfsConn.WithSNI builder. Запуск: `cd server && go test ./transport/ -v -cover`
  > Выполнено (Python): `client/sni_spoof.py` + `client/test_sni_spoof.py` (86 тестов, все pass). DOMAIN_POOL (30 доменов), RotationPolicy, SNIConfig, DomainSelector, TLS extension builders, build_client_hello (Chrome 120 fingerprint), SNISpoofConn drop-in замена ObfsConn, create_sni_conn. Запуск: `cd client && python3 -m pytest test_sni_spoof.py -v`

### ФАЗА 6: UI и удобство
- [x] **ЗАДАЧА 19:** macOS menubar иконка на PyObjC (вкл/выкл, статус, статистика трафика).
  > Выполнено: `client/menubar.py` + `client/test_menubar.py` (47 тестов, все pass). Реализованы: `VPNStatus` (DISCONNECTED/CONNECTING/CONNECTED/DISCONNECTING/ERROR), `TrafficStats` (bytes_in/out, connected_since, format_bytes, uptime, ingress_label/egress_label, reset), `VPNStatusModel` — потокобезопасная модель состояния (set_status, update_traffic, set_server_info, clear_server_info, on_status_change/on_stats_update колбэки, status_label, menu_bar_title, can_connect/can_disconnect). Под PyObjC (macOS): `VPNMenuBarController(NSObject)` — NSStatusItem с NSMenu, timer 1с для обновления статистики, toggleVPN_/quitApp_ actions; `VPNMenuBarAppDelegate(NSObject)` — ApplicationDelegate без dock иконки (NSApplicationActivationPolicyAccessory); `run_menubar_app(model, connect_action, disconnect_action)` — главная точка входа. Меню: статус, Connect/Disconnect кнопка, ↓/↑ трафик, аптайм, адрес сервера, назначенный IP, Quit. Зависимости: pyobjc-core>=10.0, pyobjc-framework-Cocoa>=10.0 (только macOS). Запуск тестов: `cd client && python3 -m pytest test_menubar.py -v`
- [x] **ЗАДАЧА 20:** Веб-панель управления сервером (статистика, логи, управление клиентами).
  > Выполнено: `server/api/dashboard.go` + `server/api/web/index.html` + `server/api/dashboard_test.go` (36 новых тестов, покрытие api 89.1%). Реализованы: `LogEntry{Time, Level, Message, Attrs}` — тип записи лога; `LogBuffer` — потокобезопасный кольцевой буфер (ring buffer) с автозаменой старых записей; `LogBuffer.Add(e)` / `LogBuffer.Entries(limit)` — запись и чтение в хронологическом порядке; `LogBuffer.Handler()` — возвращает `slog.Handler` совместимый с log/slog (уровни debug/info/warn/error, WithAttrs, WithGroup); `APIServer.SetLogBuffer(lb)` — подключает буфер; `GET /api/v1/logs?limit=N` — новый эндпоинт (аутентифицирован, лимит 1–1000); `GET /` — веб-дашборд (встроен через `//go:embed web`). Дашборд: статус сервера (онлайн/оффлайн), 4 статистических карточки (сессии, трафик ↓↑, ключи), таблица активных сессий с кнопкой «Отключить», управление белым списком ключей (добавить/удалить), журнал логов с фильтром по уровню (debug/info/warn/error), авто-обновление каждые 5 секунд, ввод Bearer-токена в браузере. Запуск: `cd server && go test ./api/ -v -cover`
- [x] **ЗАДАЧА 21:** Автоустановщик сервера (PowerShell скрипт для Windows).
  > Выполнено: `scripts/install_server.ps1` + `scripts/install_server.Tests.ps1` (Pester тесты). Реализованы: `Write-Log` (лог в файл + консоль с уровнями INFO/WARN/ERROR/SUCCESS), `Test-AdminRights` (проверка прав), `Get-RandomToken` (крипто-случайный hex токен), `Test-CommandExists` (проверка PATH), `Install-Go` (загрузка + тихая установка Go 1.22 MSI), `Install-Git` (загрузка + тихая установка Git), `Get-Repository` (clone/pull репозитория), `Build-Server` (go build под windows/amd64, CGO_ENABLED=0), `New-ServerConfig` (генерация config.yaml, не перезаписывает существующий), `Install-Service` (sc.exe create + failure actions: restart 30/60/120 сек), `Set-FirewallRules` (New-NetFirewallRule для портов 443 TCP/UDP и 8080 TCP), `Enable-IPRouting` (IPEnableRouter в реестре), `Install-TAP` (проверка TAP адаптера + предупреждение), `Start-VPNService`, `Uninstall-Server` (stop + sc.exe delete + Remove-NetFirewallRule), `Show-Summary` (итоговый вывод с токеном и инструкциями). Параметры: -InstallDir, -RepoURL, -ListenAddr, -TunCIDR, -APIAddr, -APIToken, -SkipBuild, -Uninstall. Запуск: `Invoke-Pester .\install_server.Tests.ps1 -Output Detailed`
- [x] **ЗАДАЧА 22:** Автоустановщик клиента (.pkg установщик для macOS).
  > Выполнено: `scripts/install_client.sh` + `scripts/macos_pkg/` + `scripts/test_install_client.sh` (70 тестов, все pass). Реализованы: `install_client.sh` — основной скрипт сборки .pkg (parse_args, validate_args, prepare_dirs, copy_client_files, copy_scripts, copy_resources, build_component_pkg, build_distribution_pkg, notarize_pkg, verify_pkg, print_summary). Параметры: `--version`, `--output-dir`, `--repo-path`, `--sign-identity`, `--notarize`, `--apple-id`, `--apple-password`, `--team-id`. Инсталляционные скрипты: `preinstall` (проверяет macOS 12+, arch, Python 3.11+), `postinstall` (создаёт venv, устанавливает pip зависимости, создаёт CLI wrapper `/usr/local/bin/cavadvpn`, устанавливает LaunchAgent `com.cavadvpn.client.plist`), `preuninstall` (выгружает LaunchAgent, удаляет CLI wrapper, останавливает процессы). `distribution.xml` — описание установщика для productbuild. Ресурсы: `welcome.html`, `readme.html`, `license.html`, `conclusion.html`. CLI точка входа: `client/cavadvpn_cli.py` (connect/disconnect/status/config/version команды). Запуск тестов: `bash scripts/test_install_client.sh`  Сборка .pkg (только macOS): `bash scripts/install_client.sh --version 1.0.0 --output-dir ./dist`

### ФАЗА 7: Android клиент
- [x] **ЗАДАЧА 23:** Android VPN ядро (Kotlin) — VpnService API, туннель, шифрование. `android/app/`
  > Выполнено: `android/app/` — полный Android VPN стек на Kotlin. Реализованы: `CryptoCore.kt` (X25519 + ChaCha20-Poly1305 через BouncyCastle), `NoiseHandshake.kt` (Noise_XX инициатор, NoiseCipherState, NoiseSymmetricState, noiseHKDF), `ReplayFilter.kt` (скользящее окно ±90с, потокобезопасен), `ObfsConn.kt` (TLS-обфускация: синтетические ClientHello/ServerHello, фрагментация в TLS app_data records), `MuxConn.kt` (NoiseConn с 2-байт BE framing, MuxStream с очередью, ClientMux с фоновым read-loop, чётные stream ID), `VpnConfig.kt` (конфигурация + RouteInfo), `VpnClient.kt` (полный стек: TCP → ObfsConn → Noise_XX → NoiseConn → ClientMux → control stream IP assignment → data stream), `CavadVpnService.kt` (Android VpnService: setupTunnel через VpnService.Builder, двунаправленная пересылка пакетов через coroutines, foreground notification). Протокол wire-совместим с Go сервером. Тесты: CryptoCoreTest (11), NoiseHandshakeTest (9), ReplayFilterTest (9), ObfsConnTest (5), MuxConnTest (5) — всего 39 тестов. Запуск: `cd android && ./gradlew test`
- [x] **ЗАДАЧА 24:** Android UI — экран подключения, QR-код импорт конфига, статистика, иконка в статусбаре. Собирается в APK без Google Play.
  > Выполнено: `android/app/src/main/java/com/cavadvpn/ui/` — полный UI стек. Реализованы: `VpnConnectionState` (sealed class: Disconnected/Connecting/Connected(stats)/Error), `VpnStats` (data class: bytesIn/Out, connectedSinceMs, assignedIp; formatBytes, formatUptime), `ConfigStore` (SharedPreferences обёртка: save/load/clear), `QrConfig` (JSON + URI форматы: parseQrCode, toQrJson), `MainActivity` (экран подключения: статус, connect/disconnect кнопка, трафик ↓↑, аптайм, IP; принимает VPN permission запрос через ActivityResultLauncher; слушает `ACTION_STATS_UPDATE` broadcasts), `SettingsActivity` (настройки: host, port, private key, server public key, DNS; кнопка Generate Key), `QrScanActivity` (CameraX + ZXing: сканирование QR камерой, разбор конфига, возврат результата через Activity result). В `CavadVpnService` добавлены: `bytesIn`/`bytesOut` AtomicLong счётчики (обновляются в runTunnel per-packet, без блокировок), 1-секундный broadcast корутин (`ACTION_STATS_UPDATE`), `ACTION_VPN_STATE_CHANGED` broadcast, нотификация открывает MainActivity по тапу. Зависимости: lifecycle-viewmodel, appcompat, material, CameraX (no GPS), ZXing core (pure Java). Тесты: 32 теста (ConfigStoreTest×9, QrConfigTest×11, VpnStatsTest×12). Запуск тестов: `cd android/test-runner && mvn -s mvn-settings.xml test`

### ФАЗА 8: iOS клиент
- [x] **ЗАДАЧА 25:** iOS VPN ядро (Swift) — Network Extension, PacketTunnelProvider, шифрование. `ios/`
  > Выполнено: `ios/` — полный iOS VPN стек на Swift. Реализованы: `CryptoCore.swift` (X25519 через Curve25519.KeyAgreement, ChaCha20-Poly1305 через ChaChaPoly, HMAC-SHA256, noiseHKDF, NoiseCipherState с nonce 4 нулевых + 8-байт LE счётчик), `NoiseHandshake.swift` (Noise_XX инициатор: NoiseSymmetricState, NoiseHandshake, writeMessage1/readMessage2/writeMessage3, wire-совместим с Go сервером), `ReplayFilter.swift` (PacketHeader 20-байт big-endian, ReplayFilter ±90с через NSLock), `ObfsConn.swift` (TLS-обфускация: синтетические ClientHello/ServerHello, application_data records max 16383 байт, буферизованное чтение), `MuxConn.swift` (NoiseConn 2-байт BE framing, MuxStream DispatchSemaphore, ClientMux чётные stream ID + фоновый Thread read-loop), `VpnConfig.swift` (VpnConfig, RouteInfo, hex helpers), `VpnClient.swift` (полный стек: TCP → ObfsConn → Noise_XX → NoiseConn → ClientMux → control stream → data stream, connect/disconnect/sendPacket/recvPacket), `PacketTunnelProvider.swift` (NEPacketTunnelProvider: парсинг NETunnelProviderProtocol, конфигурация NEPacketTunnelNetworkSettings, двунаправленная пересылка пакетов). Зависимость: apple/swift-crypto 3.x. Тесты: 47 XCTest (CryptoCoreTests/NoiseHandshakeTests/ReplayFilterTests/ObfsConnTests/MuxConnTests/VpnConfigTests) + 49 Python тестов совместимости. Запуск Python тестов: `cd ios/test-runner && python3 -m pytest test_compat.py -v`
- [x] **ЗАДАЧА 26:** iOS UI — экран вкл/выкл, QR-код импорт конфига. Собирается в .ipa совместимый с AltStore (бесплатно, 7-дневная переподпись автоматически по Wi-Fi пока Mac включён).
  > Выполнено: `ios/App/` — полный SwiftUI UI стек. Реализованы: `VpnConnectionState.swift` (enum: disconnected/connecting/connected/disconnecting/error; canConnect/canDisconnect/isTransitioning/symbolName), `VpnStats.swift` (data struct: bytesIn/Out, connectedSinceMs, assignedIP; formatBytes, uptimeFormatted, downloadLabel/uploadLabel), `QRConfig.swift` (парсер QR конфига: JSON и URI `cavadvpn://config?...` форматы; validate host/port/hex keys; ParsedConfig; toQRJson/toQRUri), `ConfigStore.swift` (UserDefaults обёртка: save/load/clear/apply(ParsedConfig); StoredConfig), `ConnectionViewModel.swift` (ObservableObject: loadConfig, applyQRConfig, saveConfig, connect/disconnect; интеграция с NEVPNManager через NETunnelProviderProtocol, vpnStatusChanged через NotificationCenter), `ContentView.swift` (главный экран: статус-иконка с анимацией, Connect/Disconnect кнопка, карточки трафика ↓↑, аптайм, IP, кнопки Settings и Scan QR), `SettingsView.swift` (форма: host, port, private key, server key, DNS, MTU; Generate Key через SecRandomCopyBytes + RFC 7748 clamp), `QRScanView.swift` (камера AVFoundation + AVCaptureMetadataOutput; viewfinder overlay; автоматическое закрытие после сканирования), `CavadVPNApp.swift` (точка входа @main). Конфигурации: `Info.plist` (CFBundleIdentifier com.cavadvpn.ios, NSCameraUsageDescription, cavadvpn:// URL scheme), `CavadVPN.entitlements` + `TunnelExtension.entitlements` (Network Extension packet-tunnel-provider, App Groups group.com.cavadvpn, Keychain). AltStore совместимость: только бесплатные entitlements, iOS 16+, arm64. Тесты: 67 Python тестов (TestQRConfigJSON×14, TestQRConfigURI×8, TestVpnStats×16, TestConfigStore×11, TestVpnConnectionState×15), все pass. Запуск: `cd ios/test-runner && python3 -m pytest test_ui.py -v`

### ФАЗА 9: Windows клиент
- [x] **ЗАДАЧА 27:** Windows клиент (Go + systray) — иконка в трее, автозапуск при входе, kill switch. `windows/`
  > Выполнено: `windows/` — полный Windows VPN клиент на Go. Реализованы: `config.go` (JSON конфиг с load/save/validate/default; путь `%APPDATA%\CavadVPN\config.json`), `state.go` (state machine: Disconnected/Connecting/Connected/Disconnecting/Error; потокобезопасные колбэки OnStateChange; структура StateEvent), `vpnclient.go` (протокольный клиент: TCP+TCP_NODELAY+4MB буферы → ObfsConn.ClientHandshake → Noise_XX → noiseConn с sync.Pool для zero-alloc записи → ClientMux → control stream ctlHello/ctlAssign → data stream), `killswitch.go` + `killswitch_windows.go` (netsh advfirewall: блокировка всего исходящего трафика кроме VPN сервера/loopback/DHCP) + `killswitch_stub.go` (ErrNotWindows), `autostart.go` + `autostart_windows.go` (реестр HKCU\Software\Microsoft\Windows\CurrentVersion\Run через reg.exe: Enable/Disable/IsEnabled) + `autostart_stub.go` (ErrNotWindows), `tray.go` + `tray_windows.go` (Shell_NotifyIcon через golang.org/x/sys/windows: скрытое HWND окно, NIM_ADD/NIM_MODIFY/NIM_DELETE, WM_APP+1 события, контекстное меню с Connect/Disconnect/Autostart/Quit) + `tray_stub.go`, `tun.go` + `tun_windows.go` (интерфейс для Wintun; route/netsh хелперы) + `tun_stub.go` (MockTun для тестов), `main.go` (testable appState: handleConnect/handleDisconnect/handleQuit/shutdown; CLI режим и tray режим). Оптимизации: TCP_NODELAY+4MB socket buffers, sync.Pool для write buffers (zero-alloc AEAD framing). Тесты: 68 тестов (config×11, state×11, killswitch×4, autostart×3, tray×5, tun×8, main×23, vpnclient×21, integration×5), покрытие 85.0%. Запуск: `cd windows && go test ./... -v -cover`
- [x] **ЗАДАЧА 28:** Windows .exe установщик — один файл, всё настраивается автоматически.
  > Выполнено: `windows/installer/` — самостоятельный установщик на Go (компилируется в `cavadvpn-setup.exe`). Реализованы: `installer.go` (InstallOptions, RunInstall, RunUninstall, createInstallDir, copyCurrentExe, writeDefaultConfig, removeInstallDir), `installer_windows.go` (isAdmin через Windows token, registerService/stopAndRemoveService через sc.exe, addFirewallRule/removeFirewallRules через netsh, createStartMenuShortcut через PowerShell WScript.Shell, registerUninstall/removeUninstallEntry через HKLM registry), `installer_stub.go` (заглушки для не-Windows), `main.go` (CLI флаги: --install/--uninstall/--install-dir/--server-addr/--server-key/--service/--silent). Оптимизации: socket buffers 4MB→8MB (`vpnclient.go`), TCP keepalive idle=30s/interval=10s/count=3 (`tcpopt_windows.go`+`tcpopt_stub.go`). Тесты: 9 тестов, все pass. Запуск: `cd windows && go test ./installer/ -v`; Сборка (Windows): `GOOS=windows GOARCH=amd64 go build -o cavadvpn-setup.exe ./installer/`

### ФАЗА 10: Раздача друзьям
- [x] **ЗАДАЧА 29:** QR-код генератор на сервере — генерирует QR с конфигом клиента. Друг сканирует телефоном — всё настроено. `server/api/qr.go`
- [x] **ЗАДАЧА 30:** Пригласительная ссылка — `http://IP/join/ТОКЕН` — открыл ссылку, скачал приложение под свою платформу, конфиг уже внутри.
- [x] **ЗАДАЧА 31:** Push уведомления на телефон — когда VPN отключился или сервер недоступен.
  > Выполнено: `server/notify/notify.go` + `server/notify/notify_test.go` + `server/api/notify_api.go` (24 теста, покрытие 96.5%). Реализованы: `NtfyNotifier` — отправка через ntfy.sh (бесплатный push без Apple/Google аккаунтов; пользователь устанавливает приложение ntfy и подписывается на свой топик), `WebhookNotifier` — POST на произвольный HTTP endpoint, `NotificationService` — асинхронная очередь (256 буфер), параллельная доставка (горутина на подписчика), методы `NotifySessionConnected/NotifySessionDisconnected/NotifyServerDown/SendTest`. Интеграция: `Server.notifSvc` подключается в `startAPIServer()`; нотификации fire-and-forget — никогда не блокируют VPN data path. REST API: `GET /api/v1/notifications` (список), `POST /api/v1/notifications` (добавить ntfy/webhook подписчика), `DELETE /api/v1/notifications/{id}` (удалить), `POST /api/v1/notifications/{id}/test` (тест). **Perf 1:** параллельная доставка нотификаций (горутина на получателя вместо sequential). **Perf 2:** `streamReadBufPool` — пулинг 64 KB буферов в `handleDataStream` — устраняет GC pressure при частых connect/disconnect. Запуск: `cd server && go test ./notify/ -v -cover`
- [x] **ЗАДАЧА 32:** Автообновление клиента — новая версия скачивается и устанавливается без участия пользователя.
  > Выполнено: `client/autoupdate.py` + `client/test_autoupdate.py` (46 тестов, все pass) + `server/api/update_api.go` + `server/api/update_api_test.go` (6 тестов, все pass). Реализованы: `UpdateInfo` (version, download_url, sha256, release_notes, min_os_version; is_newer_than() семантическое сравнение версий), `UpdateConfig` (update_url, current_version, check_interval_s, timeout_s, install_dir, auto_install, on_update_available/installed/error колбэки), `UpdateState` (IDLE/CHECKING/DOWNLOADING/INSTALLING/RESTART_PENDING/UP_TO_DATE/ERROR), `_VersionParser` (парсинг JSON версии с endpoint), `_Downloader` (потоковая загрузка чанками 64 KB с SHA-256 верификацией на лету), `_Installer` (macOS .pkg через `installer` или .zip с атомарной заменой файлов и backup), `AutoUpdater` (фоновый daemon thread: start/stop, check_now, install_pending, потокобезопасные state transitions), `create_auto_updater()` — фабричная функция. Сервер: `ClientVersionInfo` (JSON структура), `updateStore` (RWMutex, get/set), `GET /api/v1/client/version` — публичный endpoint (без авторизации), `POST /api/v1/client/version` — защищённый endpoint для обновления версии. **Perf 1:** Первая проверка задержана на 60 с — не конкурирует со стартом VPN туннеля. **Perf 2:** Загрузка стримингом чанками 64 KB (совпадает с server-side streamReadBufPool) — весь файл никогда не держится в памяти, GC не нагружается. Запуск: `cd client && python3 -m pytest test_autoupdate.py -v`; `cd server && go test ./api/ -v -cover`

### ФАЗА 11: Надёжность и безопасность
- [ ] **ЗАДАЧА 33:** Multi-server поддержка — несколько серверов в конфиге, автопереключение если один упал.
- [ ] **ЗАДАЧА 34:** Split tunneling — выбор каких приложений пускать через VPN, каких напрямую (например банковские приложения напрямую).
- [ ] **ЗАДАЧА 35:** Аудит безопасности — автоматическая проверка всего кода на уязвимости (gosec, bandit).
- [ ] **ЗАДАЧА 36:** Обфускация уровень 2 — трафик имитирует конкретные популярные сайты (ВКонтакте, Яндекс) по статистическим паттернам. **Важно: НЕ YouTube — заблокирован в РФ.**

### ФАЗА 12: Обход белых списков через Яндекс.Облако relay

**Архитектура:** `Mac/Android/iPhone → Яндекс.Облако VM (IP в белом списке РКН) → Казахстанский сервер → Интернет`

Яндекс.Облако даёт IP адреса автоматически включённые в белый список РКН (~300-500 руб/мес за минимальную VM). Используется как на будущее: если РКН заблокирует прямой доступ к казахстанскому серверу.

- [ ] **ЗАДАЧА 37:** Relay сервер на Go — принимает соединение от клиента, пересылает на казахстанский сервер. Поддержка PROXY Protocol v2 для передачи реального IP клиента. `server/relay/relay.go`

- [ ] **ЗАДАЧА 38:** REALITY handshake на Go — проксирование ServerHello от реального сайта (`dl.google.com`), инъекция HMAC токена аутентификации. Пассивный наблюдатель видит легитимный сертификат Google. `server/crypto/reality.go`

- [ ] **ЗАДАЧА 39:** Anti-probe защита — при неверном ключе сервер прозрачно проксирует соединение на настоящий `dl.google.com`. Активный зонд РКН получает реальный ответ Google, сервер не детектируется. `server/crypto/fallback.go`

- [ ] **ЗАДАЧА 40:** Обход 16 КБ троттлинга — разбивка данных на чанки менее 12 КБ, пересоздание TCP сессии до достижения лимита, keepalive пакеты для предотвращения заморозки. `server/transport/antithrottle.go`

- [ ] **ЗАДАЧА 41:** Автоматический выбор маршрута — клиент пробует по порядку: прямое соединение → relay Яндекс.Облако → Cloudflare Workers fallback. Прозрачный failover без участия пользователя. `client/autoselect.py`

- [ ] **ЗАДАЧА 42:** uTLS браузерный fingerprint — TLS handshake неотличим от Chrome 124 на уровне JA3/JA4. Пакет: `github.com/refraction-networking/utls`. `server/crypto/utls.go`

- [ ] **ЗАДАЧА 43:** Статистический камуфляж трафика relay — паттерны пакетов имитируют ВКонтакте/Яндекс. `server/transport/mimic.go`

- [ ] **ЗАДАЧА 44:** Установщик relay на Яндекс.Облако — bash скрипт разворачивает relay на чистой Ubuntu 22.04. Одна команда: скачивает relay, настраивает systemd unit, генерирует ключи, выводит конфиг для клиента. `scripts/install_relay.sh`

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
