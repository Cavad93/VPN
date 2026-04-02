package crypto

import (
	"sync"
	"testing"
	"time"
)

// ---------- PacketHeader тесты ----------

func TestNewPacketHeader(t *testing.T) {
	before := time.Now().Unix()
	h, err := NewPacketHeader()
	after := time.Now().Unix()

	if err != nil {
		t.Fatalf("NewPacketHeader: неожиданная ошибка: %v", err)
	}
	if h.Timestamp < before || h.Timestamp > after {
		t.Errorf("Timestamp %d вне диапазона [%d, %d]", h.Timestamp, before, after)
	}
	// Nonce не должен быть нулевым
	var zero [NonceSize]byte
	if h.Nonce == zero {
		t.Error("Nonce не должен быть нулевым")
	}
}

func TestNewPacketHeaderUnique(t *testing.T) {
	h1, err := NewPacketHeader()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := NewPacketHeader()
	if err != nil {
		t.Fatal(err)
	}
	if h1.Nonce == h2.Nonce {
		t.Error("два последовательных заголовка не должны иметь одинаковый nonce")
	}
}

func TestPacketHeaderEncodeDecodeRoundtrip(t *testing.T) {
	original, err := NewPacketHeader()
	if err != nil {
		t.Fatal(err)
	}

	encoded := original.Encode()
	if len(encoded) != PacketHeaderSize {
		t.Errorf("Encode: длина %d, ожидается %d", len(encoded), PacketHeaderSize)
	}

	decoded, err := DecodePacketHeader(encoded)
	if err != nil {
		t.Fatalf("DecodePacketHeader: неожиданная ошибка: %v", err)
	}

	if decoded.Timestamp != original.Timestamp {
		t.Errorf("Timestamp после decode: %d, ожидается %d", decoded.Timestamp, original.Timestamp)
	}
	if decoded.Nonce != original.Nonce {
		t.Errorf("Nonce после decode не совпадает")
	}
}

func TestDecodePacketHeaderTooShort(t *testing.T) {
	short := make([]byte, PacketHeaderSize-1)
	_, err := DecodePacketHeader(short)
	if err == nil {
		t.Error("DecodePacketHeader: ожидалась ошибка для короткого буфера")
	}
}

func TestDecodePacketHeaderExactSize(t *testing.T) {
	data := make([]byte, PacketHeaderSize)
	// timestamp = 1000, nonce = нули
	data[7] = 0xe8 // big-endian 1000 в последнем байте? нет...
	// правильно: 1000 = 0x00000000000003E8
	data[6] = 0x03
	data[7] = 0xe8

	h, err := DecodePacketHeader(data)
	if err != nil {
		t.Fatalf("DecodePacketHeader: неожиданная ошибка: %v", err)
	}
	if h.Timestamp != 1000 {
		t.Errorf("Timestamp: %d, ожидается 1000", h.Timestamp)
	}
}

func TestPacketHeaderEncodeLargerBuffer(t *testing.T) {
	h, err := NewPacketHeader()
	if err != nil {
		t.Fatal(err)
	}
	encoded := h.Encode()
	// DecodePacketHeader должен принять буфер с лишними байтами
	larger := append(encoded, 0xFF, 0xFF)
	decoded, err := DecodePacketHeader(larger)
	if err != nil {
		t.Fatalf("DecodePacketHeader с большим буфером: %v", err)
	}
	if decoded.Timestamp != h.Timestamp || decoded.Nonce != h.Nonce {
		t.Error("данные после decode не совпадают с оригиналом")
	}
}

// ---------- ReplayFilter тесты ----------

func TestNewReplayFilter(t *testing.T) {
	rf := NewReplayFilter()
	if rf == nil {
		t.Fatal("NewReplayFilter вернул nil")
	}
	if rf.Size() != 0 {
		t.Errorf("новый фильтр должен быть пустым, размер: %d", rf.Size())
	}
}

func TestReplayFilterCheckValidPacket(t *testing.T) {
	rf := NewReplayFilter()
	h, err := NewPacketHeader()
	if err != nil {
		t.Fatal(err)
	}
	if err := rf.Check(h); err != nil {
		t.Errorf("Check валидного пакета: %v", err)
	}
}

func TestReplayFilterCheckNilHeader(t *testing.T) {
	rf := NewReplayFilter()
	err := rf.Check(nil)
	if err == nil {
		t.Error("Check(nil): ожидалась ошибка")
	}
}

func TestReplayFilterCheckDuplicateNonce(t *testing.T) {
	rf := NewReplayFilter()
	h, err := NewPacketHeader()
	if err != nil {
		t.Fatal(err)
	}

	// Первый пакет — должен пройти
	if err := rf.Check(h); err != nil {
		t.Fatalf("первый Check: %v", err)
	}

	// Второй пакет с тем же заголовком — должен быть отклонён
	if err := rf.Check(h); err == nil {
		t.Error("повторный Check: ожидалась ошибка replay")
	}
}

func TestReplayFilterCheckOldPacket(t *testing.T) {
	rf := NewReplayFilter()
	h := &PacketHeader{
		Timestamp: time.Now().Add(-(TimestampWindow + time.Second)).Unix(),
	}
	// Nonce: случайные байты, неважно
	h.Nonce[0] = 0x42

	err := rf.Check(h)
	if err == nil {
		t.Error("старый пакет: ожидалась ошибка вне окна")
	}
}

func TestReplayFilterCheckFuturePacket(t *testing.T) {
	rf := NewReplayFilter()
	h := &PacketHeader{
		Timestamp: time.Now().Add(TimestampWindow + time.Second).Unix(),
	}
	h.Nonce[0] = 0x43

	err := rf.Check(h)
	if err == nil {
		t.Error("пакет из будущего: ожидалась ошибка вне окна")
	}
}

func TestReplayFilterCheckBoundaryPackets(t *testing.T) {
	rf := NewReplayFilter()

	// Пакет на границе окна (89 секунд назад) — должен пройти
	h1 := &PacketHeader{
		Timestamp: time.Now().Add(-89 * time.Second).Unix(),
	}
	h1.Nonce[0] = 0x01
	if err := rf.Check(h1); err != nil {
		t.Errorf("пакет на границе окна (89с): %v", err)
	}

	// Пакет на границе окна (89 секунд вперёд) — должен пройти
	h2 := &PacketHeader{
		Timestamp: time.Now().Add(89 * time.Second).Unix(),
	}
	h2.Nonce[0] = 0x02
	if err := rf.Check(h2); err != nil {
		t.Errorf("пакет на будущей границе окна (89с): %v", err)
	}
}

func TestReplayFilterMultipleUniqueNonces(t *testing.T) {
	rf := NewReplayFilter()
	now := time.Now().Unix()

	// Много уникальных пакетов в одну секунду
	for i := 0; i < 100; i++ {
		h := &PacketHeader{Timestamp: now}
		h.Nonce[0] = byte(i)
		h.Nonce[1] = byte(i >> 8)
		if err := rf.Check(h); err != nil {
			t.Errorf("уникальный пакет %d отклонён: %v", i, err)
		}
	}
	if rf.Size() == 0 {
		t.Error("фильтр должен содержать записи после проверок")
	}
}

func TestReplayFilterSameNonceDifferentTimestamps(t *testing.T) {
	rf := NewReplayFilter()

	// Один и тот же nonce, но разные временные метки — оба должны пройти
	var nonce [NonceSize]byte
	nonce[0] = 0xAB

	h1 := &PacketHeader{Timestamp: time.Now().Unix(), Nonce: nonce}
	h2 := &PacketHeader{Timestamp: time.Now().Add(-5 * time.Second).Unix(), Nonce: nonce}

	if err := rf.Check(h1); err != nil {
		t.Errorf("первый пакет: %v", err)
	}
	if err := rf.Check(h2); err != nil {
		t.Errorf("второй пакет (другая секунда, тот же nonce): %v", err)
	}
}

func TestReplayFilterCleanupOldBuckets(t *testing.T) {
	rf := NewReplayFilter()

	// Добавляем старую запись напрямую (имитируем старый пакет)
	rf.mu.Lock()
	oldTs := time.Now().Add(-2 * TimestampWindow).Unix()
	rf.seen[oldTs] = map[[NonceSize]byte]struct{}{
		{0x01}: {},
	}
	rf.mu.Unlock()

	if rf.Size() != 1 {
		t.Fatalf("перед cleanup: размер %d, ожидается 1", rf.Size())
	}

	// Новый валидный пакет должен запустить cleanup
	h, err := NewPacketHeader()
	if err != nil {
		t.Fatal(err)
	}
	if err := rf.Check(h); err != nil {
		t.Fatalf("Check: %v", err)
	}

	// Старый bucket должен быть удалён
	rf.mu.Lock()
	_, stillExists := rf.seen[oldTs]
	rf.mu.Unlock()
	if stillExists {
		t.Error("старый bucket должен быть удалён после cleanup")
	}
}

func TestReplayFilterConcurrentAccess(t *testing.T) {
	rf := NewReplayFilter()
	const goroutines = 50
	now := time.Now().Unix()

	var wg sync.WaitGroup
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			h := &PacketHeader{Timestamp: now}
			h.Nonce[0] = byte(idx)
			h.Nonce[1] = byte(idx >> 8)
			errors[idx] = rf.Check(h)
		}(i)
	}
	wg.Wait()

	// Все горутины с уникальными nonce должны успешно пройти
	for i, err := range errors {
		if err != nil {
			t.Errorf("горутина %d: неожиданная ошибка: %v", i, err)
		}
	}
}

func TestReplayFilterConcurrentDuplicates(t *testing.T) {
	rf := NewReplayFilter()
	const goroutines = 20

	// Все горутины пытаются зарегистрировать один и тот же заголовок
	h, err := NewPacketHeader()
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	accepted := 0
	var mu sync.Mutex

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := rf.Check(h)
			if err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Ровно один пакет должен быть принят
	if accepted != 1 {
		t.Errorf("при конкурентных дублях принято %d пакетов, ожидается 1", accepted)
	}
}

func TestReplayFilterSize(t *testing.T) {
	rf := NewReplayFilter()

	// Добавляем пакеты в разные секунды
	now := time.Now().Unix()
	for i := int64(0); i < 5; i++ {
		h := &PacketHeader{Timestamp: now - i}
		h.Nonce[0] = byte(i + 1)
		if err := rf.Check(h); err != nil {
			t.Fatalf("Check пакет %d: %v", i, err)
		}
	}

	size := rf.Size()
	if size < 1 || size > 5 {
		t.Errorf("Size: %d, ожидается от 1 до 5", size)
	}
}
