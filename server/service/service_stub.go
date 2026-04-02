//go:build !windows

// Package service implements Windows Service Control Manager (SCM) integration
// for the VPN server. On non-Windows platforms all functions return
// ErrNotWindows since Windows SCM is not available.
package service

import (
	"context"
	"errors"
	"log/slog"
)

const (
	// DefaultServiceName is the default Windows service name used with SCM.
	DefaultServiceName = "CavadVPN"
	// DefaultDisplayName is the friendly name shown in the Services console.
	DefaultDisplayName = "Cavad VPN Server"
	// DefaultDescription is the service description shown in the Services console.
	DefaultDescription = "Custom VPN server with Noise_XX encryption and TLS traffic obfuscation"
)

// ErrNotWindows is returned by service management functions when called on a
// non-Windows platform.
var ErrNotWindows = errors.New("service: Windows service management is only supported on Windows")

// RunFunc is the function signature for running the VPN server.
// ctx is cancelled when the Windows SCM sends a Stop or Shutdown command.
type RunFunc func(ctx context.Context) error

// RunAsService is not supported on non-Windows platforms and always returns
// ErrNotWindows. On Windows it starts the server under SCM control.
func RunAsService(_ string, _ RunFunc, _ *slog.Logger) error {
	return ErrNotWindows
}

// IsWindowsService always returns (false, nil) on non-Windows platforms.
// On Windows it returns true when the process is running as a service.
func IsWindowsService() (bool, error) {
	return false, nil
}

// Install is not supported on non-Windows platforms and always returns
// ErrNotWindows. On Windows it registers the executable with the SCM.
func Install(_, _, _, _ string) error {
	return ErrNotWindows
}

// Remove is not supported on non-Windows platforms and always returns
// ErrNotWindows. On Windows it removes the service registration from the SCM.
func Remove(_ string) error {
	return ErrNotWindows
}
