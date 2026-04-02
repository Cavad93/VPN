//go:build !linux

package main

import "errors"

// OpenTun returns an error on non-Linux platforms.
func OpenTun(name string) (TunDevice, error) {
	return nil, errors.New("TUN device is not supported on this platform")
}
