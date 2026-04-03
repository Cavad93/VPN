//go:build !windows

package main

// stubAutoStart is a no-op implementation for non-Windows platforms.
type stubAutoStart struct{}

func newAutoStart() AutoStart {
	return &stubAutoStart{}
}

func (a *stubAutoStart) Enable(exePath string) error    { return ErrNotWindows }
func (a *stubAutoStart) Disable() error                  { return ErrNotWindows }
func (a *stubAutoStart) IsEnabled() (bool, error)        { return false, ErrNotWindows }
