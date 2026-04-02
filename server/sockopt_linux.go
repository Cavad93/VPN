//go:build linux

package main

import (
	"net"
	"syscall"
)

// SO_RCVBUFFORCE and SO_SNDBUFFORCE bypass the net.core.rmem_max /
// net.core.wmem_max kernel limits when the process has CAP_NET_ADMIN.
// Without this, SetReadBuffer(4MB) silently gets capped to rmem_max
// (default 212 KB on many distros), limiting throughput to ~2 Mbps.
const (
	soRcvBufForce = 33 // SO_RCVBUFFORCE — Linux ≥ 2.6.14
	soSndBufForce = 32 // SO_SNDBUFFORCE — Linux ≥ 2.6.14
)

// dscpCS1 is DSCP class CS1 (DSCP=8, TOS=0x20): "lower effort" forwarding.
// Setting this on VPN tunnel packets signals to ISP QoS systems that the
// traffic should not be rate-limited as a high-priority flow, which can
// help avoid DPI-triggered throttling on some Russian ISPs.
const dscpCS1 = 0x20

// setForcedSocketBuffers attempts to set SO_RCVBUFFORCE / SO_SNDBUFFORCE on
// conn.  Falls back to SO_RCVBUF / SO_SNDBUF if the process lacks
// CAP_NET_ADMIN (e.g. unprivileged container) or if the call is unavailable.
// Also sets IP_TOS to DSCP CS1 to avoid ISP QoS rate-limiting.
func setForcedSocketBuffers(conn *net.TCPConn, size int) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) { //nolint:errcheck
		// Try FORCE variant first (bypasses rmem_max — needs CAP_NET_ADMIN).
		if syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soRcvBufForce, size) != nil {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size) //nolint:errcheck
		}
		if syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soSndBufForce, size) != nil {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, size) //nolint:errcheck
		}
		// Mark outgoing packets with DSCP CS1 (best-effort, lower than default).
		// This is a hint to ISP QoS systems; ignored by most.
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscpCS1) //nolint:errcheck
	})
}
