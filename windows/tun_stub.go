//go:build !windows

package main

import "fmt"

// mockTun is a simple pipe-based TUN device for testing on non-Windows platforms.
type mockTun struct {
	r    chan []byte
	w    chan []byte
	done chan struct{}
}

// NewMockTun creates an in-process mock TUN pair for testing.
// Packets written to one side can be read from the other.
func NewMockTun() (TunDevice, TunDevice) {
	a := &mockTun{
		r:    make(chan []byte, 64),
		w:    make(chan []byte, 64),
		done: make(chan struct{}),
	}
	b := &mockTun{
		r:    a.w,
		w:    a.r,
		done: a.done,
	}
	return a, b
}

func (m *mockTun) Read(p []byte) (int, error) {
	select {
	case pkt, ok := <-m.r:
		if !ok {
			return 0, fmt.Errorf("mockTun: closed")
		}
		n := copy(p, pkt)
		return n, nil
	case <-m.done:
		return 0, fmt.Errorf("mockTun: closed")
	}
}

func (m *mockTun) Write(p []byte) (int, error) {
	select {
	case <-m.done:
		return 0, fmt.Errorf("mockTun: closed")
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case m.w <- buf:
		return len(p), nil
	case <-m.done:
		return 0, fmt.Errorf("mockTun: closed")
	}
}

func (m *mockTun) Close() error {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	return nil
}

func openTun(cfg TunConfig) (TunDevice, error) {
	return nil, fmt.Errorf("tun: %w", ErrNotWindows)
}
