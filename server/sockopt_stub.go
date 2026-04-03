//go:build !linux

package main

import "net"

// applySysctls is a no-op on non-Linux platforms.
func applySysctls() {}

// setListenerTFO is a no-op on non-Linux platforms.
func setListenerTFO(_ *net.TCPListener) {}

// setListenerDeferAccept is a no-op on non-Linux platforms.
func setListenerDeferAccept(_ *net.TCPListener, _ int) {}

// setForcedSocketBuffers is a no-op on non-Linux platforms.
// On Windows, socket buffer sizing is handled by the TCP stack automatically.
func setForcedSocketBuffers(conn *net.TCPConn, size int) {
	conn.SetReadBuffer(size)  //nolint:errcheck
	conn.SetWriteBuffer(size) //nolint:errcheck
}
