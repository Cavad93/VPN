//go:build !windows

package main

// stubKillSwitch is a no-op implementation for non-Windows platforms.
type stubKillSwitch struct{}

func newKillSwitch() KillSwitch {
	return &stubKillSwitch{}
}

func (s *stubKillSwitch) Start(serverIP string) error { return ErrNotWindows }
func (s *stubKillSwitch) Stop() error                 { return ErrNotWindows }
func (s *stubKillSwitch) IsActive() bool              { return false }
