package main

import "errors"

// ErrNotWindows is returned by Windows-specific features on non-Windows platforms.
var ErrNotWindows = errors.New("feature is only available on Windows")

// KillSwitch controls network traffic blocking to prevent leaks if VPN disconnects.
type KillSwitch interface {
	// Start activates the kill switch, blocking all non-VPN traffic.
	Start(serverIP string) error
	// Stop deactivates the kill switch, restoring normal traffic.
	Stop() error
	// IsActive reports whether the kill switch is currently active.
	IsActive() bool
}

// NewKillSwitch returns the platform-appropriate KillSwitch implementation.
func NewKillSwitch() KillSwitch {
	return newKillSwitch()
}
