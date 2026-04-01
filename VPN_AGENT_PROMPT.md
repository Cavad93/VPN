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
- [ ] **ЗАДАЧА 1:** Реализовать X25519 key exchange + ChaCha20-Poly1305 шифрование на Go. Unit тесты. `server/crypto/crypto.go`
- [ ] **ЗАДАЧА 2:** Noise_XX handshake протокол. Mutual authentication сервер↔клиент. `server/crypto/handshake.go`
- [ ] **ЗАДАЧА 3:** Защита от replay атак (nonce + timestamp window 90s). `server/crypto/replay.go`

### ФАЗА 2: Транспорт (Transport Layer)
- [ ] **ЗАДАЧА 4:** UDP транспорт с надёжностью (ACK, retransmit, ordering, congestion control). `server/transport/udp.go`
- [ ] **ЗАДАЧА 5:** Обфускация под HTTPS/TLS — трафик неотличим от браузерного HTTPS для DPI. `server/transport/obfs.go`
- [ ] **ЗАДАЧА 6:** Multiplexing — несколько виртуальных каналов в одном UDP соединении. `server/transport/mux.go`

### ФАЗА 3: Сервер Go
- [ ] **ЗАДАЧА 7:** VPN сервер — принимает соединения, аутентифицирует, маршрутизирует трафик. `server/main.go`
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
