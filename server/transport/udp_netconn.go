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
	readMu  sync.Mutex
	readBuf []byte // buffered remainder from previous datagram

	// Deadlines.
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineMu    sync.Mutex
}

// NewUDPNetConn creates a net.Conn adapter over a reliable UDP connection.
func NewUDPNetConn(c *Conn) *UDPNetConn {
	return &UDPNetConn{inner: c}
}

// Read implements net.Conn. Returns data from the UDP connection as a stream.
// If the caller's buffer is smaller than the datagram, the remainder is
// buffered and returned on the next Read call.
func (u *UDPNetConn) Read(p []byte) (int, error) {
	u.readMu.Lock()
	defer u.readMu.Unlock()

	// Drain buffered remainder first.
	if len(u.readBuf) > 0 {
		n := copy(p, u.readBuf)
		u.readBuf = u.readBuf[n:]
		return n, nil
	}

	// Read a new datagram from the UDP connection.
	ctx := u.readContext()
	data, err := u.inner.Read(ctx)
	if err != nil {
		return 0, err
	}

	n := copy(p, data)
	if n < len(data) {
		// Buffer the remainder for the next Read call.
		u.readBuf = data[n:]
	}
	return n, nil
}

// readContext returns a context with the read deadline, if set.
func (u *UDPNetConn) readContext() context.Context {
	u.deadlineMu.Lock()
	dl := u.readDeadline
	u.deadlineMu.Unlock()

	if dl.IsZero() {
		return context.Background()
	}
	ctx, cancel := context.WithDeadline(context.Background(), dl)
	// The cancel function will be called when Read returns or the deadline fires.
	// We can't defer cancel() here because the context is used in inner.Read.
	// Instead, we rely on the deadline expiring to clean up.
	// In practice, inner.Read returns quickly (data is buffered in readCh).
	_ = cancel
	return ctx
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

// Verify UDPNetConn implements net.Conn at compile time.
var _ net.Conn = (*UDPNetConn)(nil)
