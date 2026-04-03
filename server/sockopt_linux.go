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

// TCP keepalive constants.
// These are applied to every accepted VPN client connection to prevent NAT
// gateways (e.g. Russian ISP NAT, Kazakhstan transit NAT) from silently
// dropping idle VPN sessions. Without keepalives, NAT tables typically expire
// TCP entries after 60–120 s of inactivity, causing mysterious disconnects.
const (
	tcpKeepIdle  = 4  // TCP_KEEPIDLE  — start probes after N seconds of idle
	tcpKeepIntvl = 5  // TCP_KEEPINTVL — send a probe every N seconds
	tcpKeepCnt   = 6  // TCP_KEEPCNT   — give up after N failed probes
)

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

		// TCP keepalive tuning — prevents NAT timeout drops on idle VPN
		// sessions (Russia↔Kazakhstan latency path).
		// SO_KEEPALIVE enables the OS keepalive probes.
		// TCP_KEEPIDLE=30s: wait 30 s of idle before first probe.
		// TCP_KEEPINTVL=10s: repeat probes every 10 s.
		// TCP_KEEPCNT=3: declare connection dead after 3 missed probes (30 s total).
		// Total disconnect detection: 30 + 3×10 = 60 s — well inside NAT timeouts.
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1) //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIdle, 30)        //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIntvl, 10)       //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepCnt, 3)          //nolint:errcheck
	})
}
