//go:build !linux && !windows

package main

import "net"

// applySysctls is a no-op on non-Linux/non-Windows platforms.
func applySysctls() {}

// setListenerTFO is a no-op on non-Linux platforms.
func setListenerTFO(_ *net.TCPListener) {}

// setListenerDeferAccept is a no-op on non-Linux platforms.
func setListenerDeferAccept(_ *net.TCPListener, _ int) {}

// verifyBBR is a no-op on non-Linux platforms.
func verifyBBR(_ interface{ Warn(string, ...any); Info(string, ...any) }) {}

// setForcedSocketBuffers sets socket buffer sizes on non-Linux/non-Windows platforms.
func setForcedSocketBuffers(conn *net.TCPConn, size int) {
	conn.SetReadBuffer(size)  //nolint:errcheck
	conn.SetWriteBuffer(size) //nolint:errcheck
}

// setConnTTL64 is a no-op on non-Linux/non-Windows platforms (macOS default is already 64).
func setConnTTL64(_ net.Conn) {}

// makeQuickACKRearm is a no-op on non-Linux/non-Windows platforms.
// TCP_QUICKACK is a Linux-specific socket option; other platforms use
// different mechanisms or have delayed-ACK disabled by default.
func makeQuickACKRearm(_ net.Conn) func() { return nil }
