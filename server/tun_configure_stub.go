//go:build !linux && !windows

package main

import "fmt"

// ConfigureTun is a no-op stub for unsupported platforms.
// TUN configuration must be performed manually on this OS.
func ConfigureTun(name, cidr string) error {
	return fmt.Errorf("ConfigureTun: platform not supported — configure %s with %s manually", name, cidr)
}
