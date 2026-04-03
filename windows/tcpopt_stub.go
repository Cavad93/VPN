//go:build !windows

package main

import "net"

// setTCPKeepalive is a no-op on non-Windows platforms.
// On Linux/macOS the caller can use SetKeepAlive + SetKeepAlivePeriod instead.
func setTCPKeepalive(conn *net.TCPConn) error {
	return nil
}
