//go:build !linux && !windows

package main

import "errors"

// OpenTun returns an error on unsupported platforms (not Linux, not Windows).
func OpenTun(name string) (TunDevice, error) {
	return nil, errors.New("TUN device is not supported on this platform")
}
