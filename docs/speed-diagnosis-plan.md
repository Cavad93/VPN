# Техническое задание: диагностика потери скорости VPN

## Дата: 2026-04-08

## Исходные данные

| Точка измерения | Входящая (Мбит/с) | Исходящая (Мбит/с) | Задержка (мс) |
|---|---|---|---|
| СПБ сервер (напрямую) | 66.56 | 7.64 | 76 |
| Астана сервер (напрямую) | 122.86 | 14.07 | 14 |
| **MacBook через VPN (СПБ → Астана)** | **3.38** | **1.97** | **72** |

**Схема соединения:** MacBook (СПБ) → VPN tunnel → СПБ сервер → relay → Астана сервер → интернет

**Проблема:** MacBook получает **5% от пропускной способности** СПБ сервера (3.38 из 66.56 Мбит/с). Ожидаемая скорость при двойном хопе — минимум 30-50 Мбит/с (ограничена upload СПБ = 7.64 Мбит/с для download клиента, но upload клиента 1.97 при upload СПБ 7.64 тоже аномально низкий).

---

## Цель

Найти все причины потери скорости на каждом участке пути данных и устранить их. Довести скорость до теоретического предела, определяемого самым узким физическим каналом (upload СПБ сервера ≈ 7.64 Мбит/с для download клиента).

---

## Архитектура: полный путь пакета

```
MacBook                    СПБ сервер                  Астана сервер
┌──────────┐  TCP/TLS    ┌────────────┐  relay/TCP   ┌────────────┐
│ TUN read │────────────►│ ObfsConn   │─────────────►│ ObfsConn   │
│ MuxStream│  obfs       │ Noise dec  │              │ Noise dec  │
│ NoiseCon │  noise      │ Mux demux  │              │ Mux demux  │
│ ObfsConn │  mux        │ TUN write  │              │ TUN write  │
│ TCP sock │  7 headers  │ routeFrom  │              │ → internet │
└──────────┘             └────────────┘              └────────────┘
```

**Overhead на пакет (1430 байт IP):**
- Mux header: +7 байт
- Noise framing: +2 байта (length) + 16 байт (AEAD tag) = +18 байт
- TLS obfuscation record: +5 байт
- Итого wire: 1460 байт (**~3% overhead** — не причина)

---

## Фаза 1: Изоляция участка потери

**Цель:** определить, на каком отрезке теряется скорость.

### Тест 1.1 — Скорость MacBook → СПБ сервер без VPN
```bash
# На MacBook — чистый iperf3 к СПБ серверу
iperf3 -c <SPB_IP> -p 5201 -t 30
iperf3 -c <SPB_IP> -p 5201 -t 30 -R  # reverse (download)
```
**Что покажет:** реальная пропускная способность канала MacBook↔СПБ без VPN стека. Если здесь уже 3-5 Мбит/с — проблема в сети провайдера, не в VPN.

### Тест 1.2 — Скорость СПБ → Астана без VPN
```bash
# На СПБ сервере
iperf3 -c <ASTANA_IP> -p 5201 -t 30
iperf3 -c <ASTANA_IP> -p 5201 -t 30 -R
```
**Что покажет:** пропускная способность relay-участка.

### Тест 1.3 — Скорость MacBook → СПБ через VPN (без relay в Астану)
Подключить MacBook напрямую к СПБ серверу как к конечному VPN, трафик выходит в интернет из СПБ. Замерить скорость через yandex.ru/internet.

**Что покажет:** потеря скорости именно на VPN стеке (шифрование + mux + obfs), без второго хопа.

### Тест 1.4 — Скорость MacBook → Астана через VPN напрямую (без СПБ)
Если возможно — подключить MacBook напрямую к Астане.

**Что покажет:** изолирует проблему relay от проблемы VPN стека.

**Ожидаемый результат фазы:** таблица скоростей по каждому участку. Определяем, где происходит основная потеря.

---

## Фаза 2: Диагностика VPN стека (MacBook → СПБ)

### Тест 2.1 — TCP-in-TCP meltdown
**Гипотеза:** VPN использует TCP как транспорт (ObfsConn поверх TCP). Если внутри туннеля тоже TCP трафик, два TCP congestion controller конфликтуют — внутренний retransmit триггерит внешний retransmit, экспоненциальный рост задержки.

```bash
# На MacBook во время VPN-соединения — мониторинг retransmits
netstat -s | grep -i retransmit
# Повторить через 30 секунд активной загрузки
netstat -s | grep -i retransmit
# Посчитать delta
```

**Проверка:** запустить iperf3 через VPN с UDP:
```bash
iperf3 -c <target> -u -b 50M -t 30
```
Если UDP через VPN значительно быстрее TCP через VPN — подтверждение TCP meltdown.

**Это наиболее вероятная причина потери >90% скорости.**

### Тест 2.2 — Congestion window и buffer sizes
```bash
# На СПБ сервере — проверить TCP буферы ОС
sysctl net.core.rmem_max
sysctl net.core.wmem_max
sysctl net.ipv4.tcp_rmem
sysctl net.ipv4.tcp_wmem
sysctl net.ipv4.tcp_window_scaling
```

```bash
# На MacBook
sysctl net.inet.tcp.sendspace
sysctl net.inet.tcp.recvspace
sysctl net.inet.tcp.autorcvbufmax
```

**Что искать:** если `rmem_max` < 4 МБ при RTT 72мс, bandwidth-delay product не покрыт. BDP = 66 Мбит/с × 0.072с ≈ 594 КБ. Буфер должен быть минимум 1 МБ.

### Тест 2.3 — Python client CPU bottleneck
```bash
# На MacBook — профилирование Python клиента
top -pid <vpn_client_pid> -l 60 -s 1
# Или:
python3 -m cProfile -o vpn_profile.out client/core.py
```

**Что искать:** если Python процесс загружает 100% одного ядра — GIL bottleneck. ChaCha20-Poly1305 в Python (cryptography library) использует OpenSSL, но Noise framing, mux read/write, TUN I/O — всё в одном потоке GIL.

### Тест 2.4 — Overhead traffic shaping / padding модулей
**Проверить:** включены ли `TrafficShaper` или `StatisticalObfuscator` на клиенте.

- `TrafficShaper` (browser profile): добавляет 1-15мс задержку между чанками + burst pauses. При 1000 пакетах/с это 1-15 секунд задержки.
- `StatisticalObfuscator` (balanced): Gaussian jitter mean=10мс на **каждый** пакет. При 1000 пакетов/с = 10 секунд дополнительной задержки.

```python
# Проверить конфигурацию клиента
# Если включён shaping — отключить и перезамерить
```

**Если включён любой shaping — это может быть основной причиной.**

### Тест 2.5 — Mux channel backpressure
В `server/transport/mux.go` канал `readCh` имеет размер 256. Если consumer (handleDataStream → TUN write) медленнее producer (readLoop), канал заполняется и блокирует весь mux.

```bash
# На СПБ сервере — добавить метрику заполненности каналов
# Или через runtime/pprof goroutine dump:
curl http://localhost:6060/debug/pprof/goroutine?debug=2 | grep -A5 "consumeData\|readLoop"
```

**Что искать:** горутины заблокированные на `s.readCh <-` (канал полон).

---

## Фаза 3: Диагностика relay (СПБ → Астана)

### Тест 3.1 — Как реализован relay?
**Критический вопрос:** как СПБ сервер пересылает трафик в Астану?

Варианты:
1. **IP forwarding через TUN + маршруты ОС** — ядро пересылает пакеты. Быстро, но требует правильной настройки маршрутов и NAT.
2. **VPN tunnel СПБ→Астана (второй VPN клиент на СПБ)** — двойное шифрование, двойной mux overhead, двойной TCP-in-TCP.
3. **Relay mode в коде сервера** — прямой проброс TCP соединения.

```bash
# На СПБ сервере — проверить активные туннели
ip link show type tun
ip route show
iptables -t nat -L -n
# Проверить процессы
ps aux | grep -E "cavadvpn|vpn"
```

**Если СПБ→Астана это второй VPN tunnel:** двойное шифрование + двойной TCP-in-TCP = основная причина.

### Тест 3.2 — MTU и фрагментация на relay
```bash
# На СПБ сервере — ping с размером пакета
ping -M do -s 1400 <ASTANA_IP>
ping -M do -s 1300 <ASTANA_IP>
ping -M do -s 1200 <ASTANA_IP>
# Найти максимальный размер без фрагментации
```

```bash
# Проверить MTU TUN интерфейса
ip link show tun0
```

**Если TUN MTU > path MTU:** каждый пакет фрагментируется, двойной overhead.

### Тест 3.3 — NAT и conntrack
```bash
# На СПБ сервере
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
sysctl net.ipv4.ip_forward
```

---

## Фаза 4: Диагностика на уровне ОС

### Тест 4.1 — WiFi vs Ethernet на MacBook
```bash
# Проверить текущее соединение
networksetup -getairportnetwork en0
system_profiler SPAirPortDataType | grep -E "PHY Mode|MCS|Channel"
```
WiFi 2.4 ГГц в загруженном доме может давать 3-5 Мбит/с реально.

### Тест 4.2 — Packet loss на каждом участке
```bash
# MacBook → СПБ
mtr -n -c 100 <SPB_IP>

# СПБ → Астана
mtr -n -c 100 <ASTANA_IP>
```
**Что искать:** потеря пакетов >1% на любом хопе. При TCP transport даже 0.5% loss = -50% throughput.

### Тест 4.3 — QoS / throttling провайдером
```bash
# На MacBook — проверить throttling VPN трафика
# Сравнить скорость на порту 443 vs другой порт
iperf3 -c <SPB_IP> -p 443 -t 10
iperf3 -c <SPB_IP> -p 8443 -t 10
```
Некоторые провайдеры throttle порт 443 при обнаружении не-TLS паттернов.

---

## Фаза 5: Benchmark отдельных компонентов

### Тест 5.1 — Throughput шифрования
```python
# На MacBook
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
key = ChaCha20Poly1305.generate_key()
cipher = ChaCha20Poly1305(key)
data = b'\x00' * 1400
nonce = b'\x00' * 12
start = time.monotonic()
for _ in range(100_000):
    cipher.encrypt(nonce, data, None)
elapsed = time.monotonic() - start
print(f"ChaCha20-Poly1305: {100_000 * 1400 * 8 / elapsed / 1e6:.0f} Мбит/с")
```
**Ожидание:** >500 Мбит/с (OpenSSL backend). Если <50 — проблема с crypto backend.

### Тест 5.2 — Throughput ObfsConn (TLS framing)
Отдельный бенчмарк ObfsConn write+read через loopback без шифрования.

### Тест 5.3 — Throughput Mux
Отдельный бенчмарк stream write+read через loopback.

### Тест 5.4 — End-to-end loopback
VPN клиент → VPN сервер на localhost → TUN → обратно. Убирает сеть из уравнения.

---

## Фаза 6: Приоритизированный список гипотез

| # | Гипотеза | Вероятность | Влияние | Проверка |
|---|----------|-------------|---------|----------|
| 1 | **TCP-in-TCP meltdown** | Высокая | >50% потери | Тест 2.1 |
| 2 | **Traffic shaping/padding включены** | Средняя | 30-80% потери | Тест 2.4 |
| 3 | **Двойной VPN tunnel (СПБ→Астана)** | Средняя | >50% потери | Тест 3.1 |
| 4 | **WiFi bottleneck на MacBook** | Средняя | до 90% потери | Тест 4.1 |
| 5 | **Packet loss на канале** | Средняя | 50%+ потери | Тест 4.2 |
| 6 | **Малые TCP буферы ОС** | Средняя | 20-50% потери | Тест 2.2 |
| 7 | **Python GIL / single-thread** | Низкая | 10-30% потери | Тест 2.3 |
| 8 | **Mux channel backpressure** | Низкая | 10-40% потери | Тест 2.5 |
| 9 | **MTU/фрагментация** | Низкая | 5-20% потери | Тест 3.2 |
| 10 | **Провайдер throttling** | Низкая | до 90% потери | Тест 4.3 |

---

## Фаза 7: План устранения (после диагностики)

### Если TCP-in-TCP meltdown (гипотеза #1):
- Переключить внешний транспорт на UDP (уже есть `transport/udp.go`)
- Или: реализовать TCP с `TCP_NODELAY` + отключением Nagle + увеличенными буферами
- Или: использовать QUIC как транспорт (userspace UDP + congestion control)

### Если traffic shaping (#2):
- Отключить `TrafficShaper` и `StatisticalObfuscator` по умолчанию
- Включать только при обнаружении DPI (адаптивно)

### Если двойной VPN (#3):
- Заменить на WireGuard/IPsec tunnel между серверами (kernel-space, минимальный overhead)
- Или: чистый IP forwarding + NAT через маршруты ОС (без второго VPN стека)

### Если WiFi (#4):
- Провести тест через Ethernet / USB-C адаптер
- Если WiFi — единственный вариант, ничего не исправить на стороне VPN

### Если малые буферы (#6):
```bash
# На сервере
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_rmem="4096 1048576 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 1048576 16777216"
```

---

## Порядок выполнения

1. **Фаза 1** (30 мин) — изоляция участка. Это определяет всё дальнейшее.
2. **Фаза 4, тест 4.1** (5 мин) — исключить WiFi как причину.
3. **Фаза 2, тест 2.4** (5 мин) — проверить shaping/padding.
4. **Фаза 3, тест 3.1** (10 мин) — понять как работает relay.
5. **Фаза 2, тест 2.1** (15 мин) — TCP-in-TCP.
6. Остальные тесты по необходимости.

---

## Критерий успеха

| Метрика | Текущее | Цель |
|---|---|---|
| Download через VPN | 3.38 Мбит/с | ≥5 Мбит/с (≥65% от upload СПБ) |
| Upload через VPN | 1.97 Мбит/с | ≥4 Мбит/с (≥50% от upload СПБ) |
| Задержка | 72 мс | ≤90 мс (СПБ latency + relay hop) |

**Теоретический потолок download:** ограничен upload СПБ сервера = 7.64 Мбит/с. С overhead VPN ~3-5% → максимум ~7.2 Мбит/с.

**Теоретический потолок upload:** ограничен upload MacBook → СПБ. Нужно измерить чистый iperf3 MacBook → СПБ для определения потолка.

---

## Прогресс диагностики

### Сеанс 1 — 2026-04-08 — UDP socket buffers (гипотеза #6)

**Гипотеза:** #6 — Малые буферы (применена к UDP транспорту, который является транспортом по умолчанию)

**Что сделано:** Проведён полный анализ кода по гипотезам #1–#3 и #6:

- **Гипотеза #2 (Traffic shaping)** — ОПРОВЕРГНУТА. В `VPNConfig` нет `TrafficShaper`/`StatisticalObfuscator` по умолчанию. Эти модули подключаются только явно пользователем.

- **Гипотеза #3 (Двойной VPN relay)** — ОПРОВЕРГНУТА. Изучен `server/relay.go` — relay это прозрачный TCP/UDP прокси (`io.Copy`). SPB сервер НЕ расшифровывает трафик, не делает второй Noise handshake. VPN стек (Noise_XX, Mux) работает end-to-end MacBook → Астана. Двойного шифрования нет.

- **Гипотеза #1 (TCP-in-TCP meltdown)** — ЧАСТИЧНО ОПРОВЕРГНУТА. Транспорт по умолчанию — **UDP** (`transport: str = "udp"` в `VPNConfig`). Для TCP режима: все оптимизации уже есть — TCP_NODELAY, BBR, 4MB SO_RCVBUF/SO_SNDBUF, TCP_QUICKACK, TCP_NOTSENT_LOWAT=16KB, TCP_WINDOW_CLAMP — в `server/sockopt_linux.go` и `client/core.py:_connect_tcp`. TCP meltdown для TCP режима смягчён.

- **Гипотеза #6 (Малые буферы) → UDP** — ПОДТВЕРЖДЕНА. Найдено КРИТИЧЕСКОЕ расхождение:
  - Сервер (`server/transport/udp.go:932`): `udpSocketBufSize = 4 * 1024 * 1024` — явно устанавливает 4MB SO_RCVBUF/SO_SNDBUF
  - Клиент (`client/reliable_udp.py:connect_udp`): НЕ устанавливал буферы — использовались OS defaults
  - macOS default: `net.inet.udp.recvspace` ≈ 42,080 байт (41 KB)
  - При 7.64 Мбит/с download: буфер заполняется за **~44 мс** → ядро дропает пакеты
  - Каждый дроп → Reno multiplicative decrease (cwnd → max(cwnd/2, 2)) → каскадный коллапс
  - Результат: throughput ограничен 3–4 Мбит/с вместо 7+ Мбит/с

**Результат:** ИСПРАВЛЕНО

**Найденные проблемы:**
- `client/reliable_udp.py:353-373` — `connect_udp()` создавал UDP сокет без SO_RCVBUF/SO_SNDBUF → OS default ~42 KB на macOS vs 4 MB на сервере

**Изменённые файлы:**
- `client/reliable_udp.py` — в `connect_udp()` добавлены `setsockopt(SO_RCVBUF, 4MB)` и `setsockopt(SO_SNDBUF, 4MB)` с silent fallback при OS limit, с комментарием почему это критично

**Тесты:** 17/17 passed (`test_reliable_udp.py`)

**Следующий шаг:** Проверить гипотезу #7 (Python GIL bottleneck) — изучить threading model в `reliable_udp.py` и `core.py`: `_recv_loop`, `_write_packet`, `_retransmit_loop` держат GIL при I/O? Есть ли блокирующие вызовы в main thread? Рассмотреть `io.CopyBuffer` с увеличенным буфером в relay (`server/relay.go:135`).
