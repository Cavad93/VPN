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

// dscpDefault is DSCP 0 (TOS=0x00): default/best-effort forwarding.
// Previous CS1 (0x20) explicitly asked ISPs to deprioritize the traffic,
// which reduced throughput. Using default class ensures equal treatment.
const dscpDefault = 0x00

// TCP_QUICKACK disables delayed ACKs. On Linux the default TCP delayed-ACK
// timer is 40 ms, which adds a full RTT of latency to every request-response
// exchange over the VPN tunnel. Disabling it sends ACKs immediately,
// allowing the sender's congestion window to open faster.
const tcpQuickAck = 12 // TCP_QUICKACK — Linux ≥ 2.4.4

// TCP_CONGESTION sets the per-socket congestion control algorithm.
// BBR (Bottleneck Bandwidth and RTT) probes actual link bandwidth
// rather than relying on packet loss, which dramatically improves
// throughput on high-latency links (Russia↔Kazakhstan ≈ 80-120 ms).
const tcpCongestion = 13 // TCP_CONGESTION — Linux ≥ 2.6.13

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
		// Mark outgoing packets with default DSCP (best-effort).
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscpDefault) //nolint:errcheck
		// Disable delayed ACKs — send ACKs immediately to speed up congestion
		// window growth and reduce per-packet latency by up to 40 ms.
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpQuickAck, 1) //nolint:errcheck
		// Try to use BBR congestion control (requires kernel module tcp_bbr).
		// Falls back silently to the system default (usually CUBIC) if BBR
		// is not available.
		syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, tcpCongestion, "bbr") //nolint:errcheck
	})
}
