// Package transport — bufconn.go implements write-coalescing for TCP connections.
//
// BufConn wraps a net.Conn and batches multiple small Write calls into a
// single TCP segment. This reduces per-packet TCP/IP overhead (~40 bytes per
// segment) and syscall overhead. The write buffer is flushed either when it
// exceeds a size threshold or after a short delay (default 1 ms).
//
// BufConn is inserted between the raw TCP connection and ObfsConn so that
// multiple encrypted Noise messages are coalesced into fewer TCP writes:
//
//	TCP → BufConn → ObfsConn → noiseConn → Mux
//
// This is transparent to all layers above.
package transport

import (
	"net"
	"sync"
	"time"
)

// Default coalescing parameters.
const (
	// coalesceDelay is the maximum time to hold data before flushing.
	// 1 ms adds negligible latency but allows batching burst writes
	// (e.g. multiple mux streams writing concurrently).
	coalesceDelay = time.Millisecond

	// coalesceMaxSize triggers an immediate flush when the buffer reaches
	// this size. Aligned to typical MSS (1460) × 10 to fill ~10 TCP segments.
	coalesceMaxSize = 14600
)

// BufConn wraps a net.Conn with a write-coalescing buffer.
// Reads pass through directly to the underlying connection.
// All methods are safe for concurrent use.
type BufConn struct {
	conn net.Conn

	mu    sync.Mutex
	buf   []byte
	timer *time.Timer
	err   error // last async flush error
}

// NewBufConn creates a BufConn wrapping conn.
func NewBufConn(conn net.Conn) *BufConn {
	return &BufConn{
		conn: conn,
		buf:  make([]byte, 0, coalesceMaxSize),
	}
}

// Write appends p to the coalescing buffer. If the buffer exceeds
// coalesceMaxSize, it is flushed synchronously. Otherwise a 1 ms timer
// is started to flush the buffer.
func (bc *BufConn) Write(p []byte) (int, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Surface any error from a previous async flush.
	if bc.err != nil {
		err := bc.err
		bc.err = nil
		return 0, err
	}

	bc.buf = append(bc.buf, p...)

	// Immediate flush if buffer is large enough.
	if len(bc.buf) >= coalesceMaxSize {
		return len(p), bc.flushLocked()
	}

	// Schedule delayed flush if not already pending.
	if bc.timer == nil {
		bc.timer = time.AfterFunc(coalesceDelay, bc.asyncFlush)
	}
	return len(p), nil
}

// Flush forces all buffered data to be written to the underlying connection.
func (bc *BufConn) Flush() error {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.flushLocked()
}

// flushLocked writes all buffered data. Caller must hold bc.mu.
func (bc *BufConn) flushLocked() error {
	if bc.timer != nil {
		bc.timer.Stop()
		bc.timer = nil
	}
	if len(bc.buf) == 0 {
		return nil
	}
	_, err := bc.conn.Write(bc.buf)
	bc.buf = bc.buf[:0]
	return err
}

// asyncFlush is called by the coalescing timer.
func (bc *BufConn) asyncFlush() {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.timer = nil
	if err := bc.flushLocked(); err != nil {
		bc.err = err
	}
}

// Read passes through to the underlying connection.
func (bc *BufConn) Read(p []byte) (int, error) {
	return bc.conn.Read(p)
}

// Close flushes any pending data and closes the underlying connection.
func (bc *BufConn) Close() error {
	bc.mu.Lock()
	if bc.timer != nil {
		bc.timer.Stop()
		bc.timer = nil
	}
	// Best-effort flush before close.
	if len(bc.buf) > 0 {
		bc.conn.Write(bc.buf) //nolint:errcheck
		bc.buf = bc.buf[:0]
	}
	bc.mu.Unlock()
	return bc.conn.Close()
}

// net.Conn interface — delegate to underlying connection.
func (bc *BufConn) LocalAddr() net.Addr                { return bc.conn.LocalAddr() }
func (bc *BufConn) RemoteAddr() net.Addr               { return bc.conn.RemoteAddr() }
func (bc *BufConn) SetDeadline(t time.Time) error      { return bc.conn.SetDeadline(t) }
func (bc *BufConn) SetReadDeadline(t time.Time) error  { return bc.conn.SetReadDeadline(t) }
func (bc *BufConn) SetWriteDeadline(t time.Time) error { return bc.conn.SetWriteDeadline(t) }
