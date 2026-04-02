// Package crypto — защита от replay атак.
//
// ReplayFilter отслеживает использованные nonce в скользящем временном окне
// (±90 секунд от текущего времени) и отклоняет:
//   - пакеты с временной меткой вне допустимого окна
//   - пакеты с уже использованным nonce (повторная атака)
//
// Использование:
//
//	filter := crypto.NewReplayFilter()
//
//	// При отправке пакета:
//	header, err := crypto.NewPacketHeader()
//	wire := append(header.Encode(), encryptedPayload...)
//
//	// При получении пакета:
//	header, err := crypto.DecodePacketHeader(wire[:crypto.PacketHeaderSize])
//	if err := filter.Check(header); err != nil {
//	    // отклонить пакет
//	}
package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	// TimestampWindow — максимальная допустимая разница между временной меткой
	// пакета и текущим временем сервера.
	TimestampWindow = 90 * time.Second

	// PacketHeaderSize — размер сериализованного заголовка пакета в байтах.
	// 8 байт (timestamp) + 12 байт (nonce) = 20 байт.
	PacketHeaderSize = 8 + NonceSize
)

// PacketHeader содержит временную метку и nonce пакета.
// Используется для защиты от replay атак.
type PacketHeader struct {
	// Timestamp — Unix-время создания пакета (секунды).
	Timestamp int64
	// Nonce — криптографически случайный уникальный идентификатор пакета.
	Nonce [NonceSize]byte
}

// NewPacketHeader создаёт заголовок с текущим временем и случайным nonce.
func NewPacketHeader() (*PacketHeader, error) {
	h := &PacketHeader{
		Timestamp: time.Now().Unix(),
	}
	if _, err := io.ReadFull(rand.Reader, h.Nonce[:]); err != nil {
		return nil, fmt.Errorf("replay: не удалось сгенерировать nonce заголовка: %w", err)
	}
	return h, nil
}

// Encode сериализует заголовок в PacketHeaderSize байт.
// Формат: 8 байт big-endian timestamp || 12 байт nonce.
func (h *PacketHeader) Encode() []byte {
	buf := make([]byte, PacketHeaderSize)
	binary.BigEndian.PutUint64(buf[:8], uint64(h.Timestamp))
	copy(buf[8:], h.Nonce[:])
	return buf
}

// DecodePacketHeader десериализует заголовок из data.
// data должна содержать не менее PacketHeaderSize байт.
func DecodePacketHeader(data []byte) (*PacketHeader, error) {
	if len(data) < PacketHeaderSize {
		return nil, fmt.Errorf("replay: заголовок слишком короткий (%d байт, нужно %d)", len(data), PacketHeaderSize)
	}
	h := &PacketHeader{
		Timestamp: int64(binary.BigEndian.Uint64(data[:8])),
	}
	copy(h.Nonce[:], data[8:8+NonceSize])
	return h, nil
}

// ReplayFilter защищает от replay атак, используя скользящее временное окно.
//
// Пакет принимается, если:
//  1. Его временная метка находится в пределах ±TimestampWindow от текущего времени.
//  2. Его nonce ещё не встречался в данном временном bucket'е.
//
// Все принятые nonce хранятся в памяти до истечения TimestampWindow.
// Структура потокобезопасна.
type ReplayFilter struct {
	mu     sync.Mutex
	seen   map[int64]map[[NonceSize]byte]struct{}
	window time.Duration
}

// NewReplayFilter создаёт новый ReplayFilter с окном TimestampWindow.
func NewReplayFilter() *ReplayFilter {
	return &ReplayFilter{
		seen:   make(map[int64]map[[NonceSize]byte]struct{}),
		window: TimestampWindow,
	}
}

// Check проверяет заголовок пакета и регистрирует его nonce.
// Метод потокобезопасен.
//
// Возвращает ошибку если:
//   - header равен nil
//   - временная метка пакета вне окна ±90с от текущего времени
//   - nonce уже использовался (replay атака)
func (rf *ReplayFilter) Check(header *PacketHeader) error {
	if header == nil {
		return errors.New("replay: заголовок пакета не может быть nil")
	}

	now := time.Now()
	pktTime := time.Unix(header.Timestamp, 0)

	age := now.Sub(pktTime)
	if age < 0 {
		age = -age
	}
	if age > rf.window {
		return fmt.Errorf("replay: временная метка пакета вне окна (разница %v > %v)",
			age.Round(time.Second), rf.window)
	}

	rf.mu.Lock()
	defer rf.mu.Unlock()

	bucket := header.Timestamp
	if rf.seen[bucket] == nil {
		rf.seen[bucket] = make(map[[NonceSize]byte]struct{})
	}

	if _, exists := rf.seen[bucket][header.Nonce]; exists {
		return errors.New("replay: nonce уже использовался (повторная атака)")
	}

	rf.seen[bucket][header.Nonce] = struct{}{}
	rf.cleanup(now)

	return nil
}

// cleanup удаляет записи старше window. Вызывается с удержанием mu.
func (rf *ReplayFilter) cleanup(now time.Time) {
	cutoff := now.Add(-rf.window).Unix()
	for ts := range rf.seen {
		if ts < cutoff {
			delete(rf.seen, ts)
		}
	}
}

// Size возвращает количество временных bucket'ов в памяти.
// Используется для диагностики и тестирования.
func (rf *ReplayFilter) Size() int {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return len(rf.seen)
}
