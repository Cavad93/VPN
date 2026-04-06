# Historia — лог оптимизации пропускной способности VPN

## Запуск 1 — 2026-04-05

### Выполнено: ObfsConn buffering — устранение двойной буферизации

**Файл:** `server/transport/obfs.go`

**Проблема:**  
В `ObfsConn.Read()` существовало два независимых буфера:
1. `bufio.Reader` (64 KB) — буфер для снижения количества syscall при чтении из сети.
2. `readBuf []byte` — динамически аллоцируемый буфер для хранения "лишних" байт TLS-пейлоада, когда буфер вызывающего (`p`) оказывался меньше длины TLS-записи.

В slow path (когда `len(p) < length`) происходило:
- `payload := make([]byte, length)` — heap-аллокация под весь пейлоад
- Данные из `bufio.Reader` читались в `payload`
- Из `payload` копировалось `len(p)` байт в `p`
- Остаток сохранялся в `c.readBuf = payload[n:]`

Итого: данные буферизовались дважды — в `bufio.Reader` и в `readBuf`.

**Решение:**  
Заменил `readBuf []byte` на `readBufRemaining int`. Теперь `Read()`:
1. Если `readBufRemaining == 0` — декодирует заголовок TLS-записи, устанавливает `readBufRemaining = length`.
2. Читает `min(len(p), readBufRemaining)` байт **напрямую** из `bufio.Reader` в `p`.
3. Уменьшает `readBufRemaining` на число прочитанных байт.

Поток данных: **сеть → bufio.Reader → p** — единственный буфер, нулевых аллокаций.

**Эффект:**
- Устранена heap-аллокация `make([]byte, length)` в slow path (1 аллокация на TLS-запись при малом буфере вызывающего).
- Устранена копия `copy(p, payload)` — данные идут напрямую из bufio в p.
- Нет второго буфера в памяти: `readBuf` больше не живёт до следующего GC.
- Для hot path (вызывающий передаёт 65 KB буфер) поведение идентично — вся запись читается за один вызов `io.ReadFull`.

**Тесты:** все 15 тестов `TestObfs*` прошли, полный `go test ./...` — зелёный.

---

## Запуск 2 — 2026-04-06

### Выполнено: sendMu contention — вынос WriteToUDP за пределы критической секции

**Файл:** `server/transport/udp.go` → функция `doRetransmit()`

**Проблема:**  
`doRetransmit()` держала `sendMu` на протяжении всего цикла ретрансмита, включая каждый вызов `c.conn.WriteToUDP()`. Каждый syscall занимает 1–50 µs. При N ретрансмитах за один тик (`retransmitLoop` каждые 20–200 мс) `sendMu` удерживался на N×50 µs. В это время `writePacket` (основной путь записи данных) полностью блокировался — пропускная способность при потерях пакетов падала.

**Конкретный сценарий:**  
При 1% потери на канале 30 Mbps (~267 пакетов/сек, cwnd=32): ретрансмит-тик обрабатывает несколько тайм-аутов за раз. Если 5 пакетов ждут ретрансмита, `sendMu` держался ~250 µs. За это время `writePacket` простаивал, не подавая новые пакеты в окно.

**Решение:**  
Разделил `doRetransmit` на два этапа:

1. **Под `sendMu`** (только память, без syscall):
   - Итерация по `c.pending` для поиска тайм-аутов
   - Кодирование пакета в pooled-буфер (`sendBufPool.Get()`)
   - Обновление `pp.sentAt`, `pp.retransmits++`
   - Регистрация в `bbr.inflight.OnSend()` (имеет свой lock, быстро)
   - Сбор `rtxItem{bp, buf}` в локальный slice

2. **После `sendMu`** (syscall без блокировки записи):
   - Цикл `c.conn.WriteToUDP(item.buf, c.remote)` — UDP-сокеты thread-safe для concurrent writes
   - Возврат буферов в `sendBufPool`

Введён вспомогательный тип `rtxItem` и stack-allocated буфер `[8]rtxItem` (heap grows only under sustained loss with >8 simultaneous timeouts).

**Эффект:**  
Время удержания `sendMu` в `doRetransmit`: O(N×syscall) → O(N×memcopy). `writePacket` больше не блокируется на время ретрансмита. Под 1% потери при 30 Mbps — ожидаемое снижение задержки записи на 80–95%.

**Тесты:** `go test ./...` — все 8 пакетов зелёные.

---

## Запуск 3 — 2026-04-06

### Выполнено: processACK pool — устранение аллокации backing-array на каждый ACK

**Файл:** `server/transport/udp.go`

**Проблема:**  
В `processACK()` тип `ackedInfo` был объявлен локально внутри функции, а `acked := make([]ackedInfo, 0, 16)` создавал новый backing array при каждом вызове.  
При 30 Mbps / 1460-byte пакетах: ~2500 ACK/сек → ~2500 аллокаций/сек, суммарно ~3.3 MB/сек heap pressure только от этого одного места.

**Решение:**  
1. Вынес `ackedInfo` на уровень пакета (переименован в `ackedPktInfo`).  
2. Добавил `ackedSlicePool = sync.Pool{New: make([]ackedPktInfo, 0, 16)}` для переиспользования backing-array среза.  
3. В `processACK`: `Get()` → `acked := (*ptr)[:0]` → заполнение → использование → zeroing элементов → `Put()`.  
   - Нулевое выделение в горячем пути при отсутствии роста среза (batch ≤ 16 пакетов).  
   - При росте > 16 новый backing array остаётся в пуле для следующего более крупного burst.  
4. Явный `zeroing` перед Put предотвращает удержание `time.Time` (внутренний `*time.Location`) и ссылок на payload-данные дольше их полезного времени жизни.

**Эффект:**  
- Устранена аллокация `make([]ackedPktInfo, 0, 16)` на каждый ACK (16 × 80 байт ≈ 1280 байт × 2500/сек = ~3.3 MB/сек).  
- Снижен GC throughput при высокой нагрузке.

**Тесты:** `go test ./...` — все 8 пакетов зелёные.

---

## Запуск 4 — 2026-04-06

### Выполнено: BBR app-limited — корректное определение idle-отправителя

**Файл:** `server/transport/udp.go`, функция `writePacket`

**Проблема:**

```go
// ДО:
appLimited := len(c.pending) == 0
```

Метка `appLimited=true` выставлялась только для самого первого пакета после
простоя (когда очередь `pending` была пуста). Все последующие пакеты одного
же burst'а получали `appLimited=false`, хотя труба ещё не была заполнена
(`pending << cwndTarget`).

Согласно спецификации BBR и реализации Linux-ядра, пакет считается
«app-limited» если в момент его отправки количество пакетов в полёте (`pending`)
**меньше** целевого окна перегрузки (`cwndTarget`). Только тогда мы можем
утверждать, что ограничение — приложение, а не сеть.

**Последствие бага:**

При возобновлении после простоя:
1. Старые сэмплы BtlBw в `windowedMaxFilter` постепенно вытесняются через
   `recalcBest(currentRound)` — через 10 раундов best→0.
2. Пакеты 2+ burst'а отправляются с `appLimited=false`.
3. Измеренная delivery_rate занижена (pipe не заполнен).
4. Заниженные сэмплы обновляют BtlBw → BBR ошибочно думает, что полоса узкая.
5. cwndTarget снижается, throughput падает спирально.

**Исправление:**

```go
// ПОСЛЕ:
appLimited := len(c.pending) < cwndTarget
```

`cwndTarget` уже вычислен выше в `writePacket` (через `c.bbr.CwndTarget()`),
поэтому дополнительных lock-acquisition не требуется.

**Результат:**
- Все существующие тесты проходят.
- BtlBw не будет занижаться за счёт под-нагрузочных сэмплов после idle.

---

---

## Запуск 5 — 2026-04-06

### Выполнено: batchFlushLoop — atomic fast-path для пустого batch

**Файл:** `server/transport/udp.go`

**Проблема:**  
`batchFlushLoop` просыпается каждые 200 мкс и **всегда** берёт `sendMu` — даже когда batch пуст (нет активных write). Это создавало ~5000 lock/unlock в секунду на idle-соединениях, вызывая CPU spinning и конкуренцию с `writePacket` (который держит `sendMu` во время обработки cwnd + batch.Add).

**Решение:**  
Добавлен `hasBatchData atomic.Bool` в struct `Conn`:
- Устанавливается в `true` (под `sendMu`) в `writePacket` после `batch.Add()`
- Сбрасывается в `false` (под `sendMu`) в `writePacket`, `Write` и `Close` после `batch.Flush()`
- В `batchFlushLoop`: `if !c.hasBatchData.Load() { continue }` — пропускает `sendMu.Lock()` на idle-пути

**Raciness design (намеренная):**  
Флаг читается без `sendMu` — это допустимо:
- Stale `false` → пропустим один 200 мкс тик, пакет доставится на 200 мкс позже — безвредно.
- Stale `true` → приобретём lock, проверим `Len() == 0`, отпустим — один лишний lock/unlock — дешевле текущего.

**Эффект:**  
На idle-соединениях (batch пуст): ~5000 lock/unlock/сек → 0. `writePacket` больше не конкурирует с пустым flush-тиком за `sendMu`. CPU overhead `batchFlushLoop` на idle снижается до стоимости одного atomic load каждые 200 мкс.

**Тесты:** `go test ./...` — все 8 пакетов зелёные.

---

## Запуск 6 — 2026-04-06

### Выполнено: BBR idle restart — устранение отравления BtlBw через stale deliveredTime

**Файлы:** `server/transport/bbr_estimator.go`, `server/transport/bbr_estimator_test.go`

**Проблема (дополнение к Запуску 4):**

Запуск 4 исправил метку `appLimited` (пакеты, пока cwnd не заполнен, помечаются как app-limited). Однако оставалась вторая проблема: все пакеты burst'а после idle получали одинаковый `sendDeliveredTime` из `DeliveredSnapshot()` — время последнего ACK **до** простоя (например, 60 секунд назад).

Когда ACK для этих пакетов возвращался:
```
deliveredInterval = 1400 bytes
ackElapsed = RTT + idle_duration  (например, 90 мс + 60 с = 60.09 с!)
deliveryRate = 1400 / 60.09 ≈ 23 bytes/s  ← мусор
```

Если пакет был помечен `appLimited=false` (например, когда cwnd был заполнен до idle), BBR обновлял BtlBw мусорным значением → throughput коллапсировал.

**Исправление: `DeliveredSnapshot()` капирует устаревший timestamp**

```go
var idleRestartThreshold = time.Second

func (e *bbrEstimator) DeliveredSnapshot() (int64, time.Time) {
    ...
    if time.Since(t) > idleRestartThreshold {
        return d, time.Now()  // cap stale timestamp
    }
    return d, t
}
```

**Эффект:**
- Все пакеты burst'а после idle получают `sendDeliveredTime ≈ now`
- Delivery rate для их ACK = `bytes / RTT` — корректное значение
- BtlBw обновляется корректными сэмплами, а не мусорными
- `idleRestartThreshold = 1s` — переопределяемая переменная для тестов

**Тесты добавлены:**
- `TestDeliveredSnapshotCapsStaleTime` — stale timestamp (5s ago) → returned time ≈ now
- `TestBtlBwNotPoisonedAfterIdle` — e2e: BtlBw > 100 KB/s после 3-секундного idle

**Результат:** все тесты прошли (`go test ./transport/ -count=1`)

---

## Следующие задачи (приоритетный бэклог)

1. **Double CC** — Наш user-space BBR (UDP) + TCP CC ОС (CUBIC/BBR). Два независимых CC на одном пути.
   Архитектурная проблема; требует отдельного исследования. Решение: вынести VPN-транспорт на raw sockets или отключить Nagle/CC для inner TCP потоков.

2. **Диагностика** — pprof-профилирование под нагрузкой для поиска других узких мест:
   - `inflightTracker.mu` — вызывается из `processACK` и `doRetransmit` одновременно
   - `bbr_estimator.mu` — вызывается из `OnACK` для каждого ACK-а
   - `readLoop` в `mux.go` — `make([]byte, length)` на каждый фрейм

3. **ObfsConn write path** — `Write` нет батчинга: каждый `Write(p)` → один TLS record → один syscall.
   При малых write (< MTU) это значительно снижает пропускную способность. Рассмотреть bufio.Writer с Flush по таймеру.
