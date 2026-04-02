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
- [ ] **ЗАДАЧА 8:** Управление клиентами через REST API (добавление/удаление/статистика). `server/api/api.go`
- [ ] **ЗАДАЧА 9:** Windows Service враппер — запуск как служба Windows. `server/service/windows_service.go`
- [ ] **ЗАДАЧА 10:** Конфигурация через YAML, генерация ключей при первом запуске. `server/config/config.go`

### ФАЗА 4: Клиент Python (macOS)
- [ ] **ЗАДАЧА 11:** Подключение к серверу, Noise handshake, получение маршрутов. `client/core.py`
- [ ] **ЗАДАЧА 12:** TUN интерфейс на macOS — перехват всего системного трафика. `client/tun_macos.py`
- [ ] **ЗАДАЧА 13:** DNS leak protection — все DNS запросы через туннель. `client/dns.py`
- [ ] **ЗАДАЧА 14:** Kill switch — полная блокировка трафика при обрыве VPN. `client/killswitch.py`
- [ ] **ЗАДАЧА 15:** Auto-reconnect с exponential backoff + health check. `client/reconnect.py`

### ФАЗА 5: Anti-DPI обфускация
- [ ] **ЗАДАЧА 16:** Traffic shaping — имитация паттернов браузерного трафика (размеры пакетов, задержки).
- [ ] **ЗАДАЧА 17:** Padding и timing рандомизация против статистического анализа трафика.
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
