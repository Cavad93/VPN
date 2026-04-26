package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// UDPNetConn wraps a reliable UDP Conn into a net.Conn interface so that
// ObfsConn, noiseConn, and Mux can work unchanged on top of UDP transport.
//
// Key adaptation: UDP Conn has datagram semantics (Read returns one packet),
// but net.Conn consumers expect stream semantics (partial reads, buffering).
// UDPNetConn maintains an internal read buffer to bridge this gap.
type UDPNetConn struct {
	inner *Conn

	// Read buffering: bridge datagram → stream semantics.
	readMu         sync.Mutex
	readBuf        []byte  // buffered remainder from previous datagram
	readBufBacking *[]byte // pool token for readBuf; returned to decodePayloadPool
	// when readBuf is fully consumed. nil when readBuf is empty or not from pool.

	// Deadlines.
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineMu    sync.Mutex
}

// NewUDPNetConn creates a net.Conn adapter over a reliable UDP connection.
func NewUDPNetConn(c *Conn) *UDPNetConn {
	return &UDPNetConn{inner: c}
}

// nopCancel is a pre-allocated no-op context.CancelFunc used when there is no
// read deadline. It avoids a closure allocation on the hot Read path.
var nopCancel context.CancelFunc = func() {}

// Read implements net.Conn. Returns data from the UDP connection as a stream.
// If the caller's buffer is smaller than the datagram, the remainder is
// buffered and returned on the next Read call.
//
// Pool lifecycle: DecodePacket borrows a buffer from decodePayloadPool for
// each incoming DATA packet. UDPNetConn.Read returns that buffer to the pool
// as soon as all bytes have been copied into the caller's p. On the fast path
// (caller's buffer ≥ datagram, which is always true since mux reads with
// 65536-byte buffers and datagrams are ≤1430 bytes) the backing is returned
// on the same Read call that received it. Zero heap allocations on that path.
func (u *UDPNetConn) Read(p []byte) (int, error) {
	u.readMu.Lock()
	defer u.readMu.Unlock()

	// Drain buffered remainder first.
	if len(u.readBuf) > 0 {
		n := copy(p, u.readBuf)
		u.readBuf = u.readBuf[n:]
		if len(u.readBuf) == 0 && u.readBufBacking != nil {
			// Remainder fully consumed — return backing to pool.
			decodePayloadPool.Put(u.readBufBacking)
			u.readBufBacking = nil
		}
		return n, nil
	}

	// Read a new datagram from the UDP connection.
	// cancel() is called immediately after inner.Read returns to release the
	// associated runtime timer. Without this, every Read with a non-zero deadline
	// leaks one timer entry for up to noiseReadTimeout (120 s). At 30 Mbps the
	// hot path calls Read ~2630/sec, accumulating ~315 K timer objects (≈25 MB).
	ctx, cancel := u.readContext()
	rp, err := u.inner.Read(ctx)
	cancel() // release timer immediately; safe — inner.Read has already returned
	if err != nil {
		return 0, err
	}

	n := copy(p, rp.data)
	if n < len(rp.data) {
		// Partial read: buffer the remainder and keep the pool token until
		// the bytes are drained. This path is effectively unreachable in
		// production (mux reads with 65536-byte buffer > 1430-byte datagram).
		u.readBuf = rp.data[n:]
		u.readBufBacking = rp.backing
	} else if rp.backing != nil {
		// Fast path: all bytes consumed in a single copy — return immediately.
		decodePayloadPool.Put(rp.backing)
	}
	return n, nil
}

// readContext returns a context respecting the current read deadline, plus a
// cancel function that MUST be called after the associated inner.Read returns.
// Calling cancel() immediately frees the runtime timer and associated memory.
//
// Zero-deadline path: returns context.Background() + a pre-allocated nopCancel.
// No heap allocation, no timer entry created.
//
// Non-zero-deadline path: returns context.WithDeadline(Background, dl). The
// cancel returned by WithDeadline MUST be called once inner.Read completes to
// remove the timer from the runtime heap. Callers must not defer cancel inside
// the Read loop — call it directly after inner.Read returns.
func (u *UDPNetConn) readContext() (context.Context, context.CancelFunc) {
	u.deadlineMu.Lock()
	dl := u.readDeadline
	u.deadlineMu.Unlock()

	if dl.IsZero() {
		return context.Background(), nopCancel
	}
	return context.WithDeadline(context.Background(), dl)
}

// Write implements net.Conn. Sends data reliably over the UDP connection.
func (u *UDPNetConn) Write(p []byte) (int, error) {
	// Check write deadline.
	u.deadlineMu.Lock()
	dl := u.writeDeadline
	u.deadlineMu.Unlock()

	if !dl.IsZero() && time.Now().After(dl) {
		return 0, errors.New("transport: write deadline exceeded")
	}

	err := u.inner.Write(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements net.Conn.
func (u *UDPNetConn) Close() error {
	u.inner.Close()
	return nil
}

// LocalAddr implements net.Conn.
func (u *UDPNetConn) LocalAddr() net.Addr {
	return u.inner.LocalAddr()
}

// RemoteAddr implements net.Conn.
func (u *UDPNetConn) RemoteAddr() net.Addr {
	return u.inner.RemoteAddr()
}

// SetDeadline implements net.Conn.
func (u *UDPNetConn) SetDeadline(t time.Time) error {
	u.deadlineMu.Lock()
	u.readDeadline = t
	u.writeDeadline = t
	u.deadlineMu.Unlock()
	return nil
}

// SetReadDeadline implements net.Conn.
func (u *UDPNetConn) SetReadDeadline(t time.Time) error {
	u.deadlineMu.Lock()
	u.readDeadline = t
	u.deadlineMu.Unlock()
	return nil
}

// SetWriteDeadline implements net.Conn.
func (u *UDPNetConn) SetWriteDeadline(t time.Time) error {
	u.deadlineMu.Lock()
	u.writeDeadline = t
	u.deadlineMu.Unlock()
	return nil
}

// SetInitialBandwidth seeds the underlying BBR congestion control with known
// bandwidth and RTT, skipping the slow Startup phase.
func (u *UDPNetConn) SetInitialBandwidth(bytesPerSec int64, rtt time.Duration) {
	u.inner.SetInitialBandwidth(bytesPerSec, rtt)
}

// Congested reports whether the underlying BBR connection's send pipe is near
// capacity (≥75% of cwnd in flight).  Delegates to Conn.Congested.
// Implements the congestionProber interface used by routeFromTun for ECN CE marking.
func (u *UDPNetConn) Congested() bool {
	return u.inner.Congested()
}

// Verify UDPNetConn implements net.Conn at compile time.
var _ net.Conn = (*UDPNetConn)(nil)
