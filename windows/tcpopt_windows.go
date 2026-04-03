//go:build windows

package main

import (
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// setTCPKeepalive enables TCP keep-alive on conn with tuned parameters to
// prevent NAT timeouts on high-latency links (e.g. Russia ↔ Kazakhstan).
// idle=30s, interval=10s, count=3.
func setTCPKeepalive(conn *net.TCPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		handle := windows.Handle(fd)

		// SIO_KEEPALIVE_VALS lets us set idle and interval in one call.
		ka := windows.TCPKeepalive{
			OnOff:    1,
			Time:     uint32((30 * time.Second).Milliseconds()),
			Interval: uint32((10 * time.Second).Milliseconds()),
		}
		ret := uint32(0)
		setErr = windows.WSAIoctl(
			handle,
			windows.SIO_KEEPALIVE_VALS,
			(*byte)(unsafe.Pointer(&ka)),
			uint32(unsafe.Sizeof(ka)),
			nil, 0,
			&ret,
			nil,
			0,
		)
	})
	if err != nil {
		return err
	}
	return setErr
}
