//go:build !windows

package main

import "fmt"

// stubTray is a no-op implementation for non-Windows platforms.
type stubTray struct {
	callbacks TrayCallbacks
	quit      chan struct{}
}

func newTrayApp(callbacks TrayCallbacks) TrayApp {
	return &stubTray{
		callbacks: callbacks,
		quit:      make(chan struct{}),
	}
}

func (s *stubTray) Run() error {
	// On non-Windows, just block until Quit is called.
	<-s.quit
	return nil
}

func (s *stubTray) SetStatus(state ConnectionState, assignedIP string) {
	// no-op on non-Windows
	_ = fmt.Sprintf("tray: SetStatus(%s, %s) — not supported on this platform", state, assignedIP)
}

func (s *stubTray) Quit() {
	select {
	case <-s.quit:
	default:
		close(s.quit)
	}
}
