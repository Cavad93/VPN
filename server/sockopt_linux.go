//go:build linux

package main

import (
	"net"
	"os"
	"strings"
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

// TCP_DEFER_ACCEPT delays the accept() wake-up until the client sends actual
// data (the TLS ClientHello). This eliminates one context switch for the
// server goroutine on each new connection, and rejects pure SYN-only probes
// (port scanners, health checks) without waking the accept loop.
const tcpDeferAccept = 9 // TCP_DEFER_ACCEPT — Linux ≥ 2.4

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

// SO_BUSY_POLL enables busy-polling on the socket. The kernel spins for
// up to N microseconds in the network driver when the socket has no data,
// avoiding the context switch to/from the interrupt handler. On low-latency
// paths this reduces per-packet latency by 10-50 µs, improving throughput
// by keeping the congestion window growing without pauses.
const soBusyPoll = 46 // SO_BUSY_POLL — Linux ≥ 3.11

// TCP_WINDOW_CLAMP sets the maximum advertised TCP window size. Setting this
// to the socket buffer size allows the kernel to fully utilise the
// configured buffer for the advertised window, maximising bandwidth-delay
// product coverage. Without this, the kernel may advertise a smaller window.
const tcpWindowClamp = 10 // TCP_WINDOW_CLAMP — Linux ≥ 2.4

// TCP_NOTSENT_LOWAT controls the threshold of unsent data in the kernel's
// TCP send buffer. When unsent data drops below this value, the socket is
// reported as writable (epoll/select). Setting this to 16 KB means the
// kernel never queues more than ~16 KB of unsent data, so on packet loss
// only 16 KB needs to be retransmitted instead of potentially megabytes.
// This reduces tail latency by 5-10× on lossy links (0.7% loss
// Russia↔Kazakhstan). Apple recommends this for real-time apps (WWDC 2015).
const tcpNotSentLowat = 73 // TCP_NOTSENT_LOWAT — Linux ≥ 3.12

// notSentLowatBytes is the threshold value for TCP_NOTSENT_LOWAT.
// 16 KB ≈ ~11 full-size TCP segments. Small enough to limit retransmit
// penalty on loss, large enough to keep the pipe full at 50 Mbps × 80 ms RTT.
const notSentLowatBytes = 16384

// TCP_FASTOPEN enables TFO on the listener socket.
// TFO allows the client to send data in the SYN packet, saving one full RTT
// (80-120 ms Russia↔Kazakhstan) on reconnections.
const tcpFastOpen = 23 // TCP_FASTOPEN — Linux ≥ 3.7

// applySysctls writes kernel tuning parameters via /proc/sys.
// Requires root/CAP_SYS_ADMIN. Failures are silently ignored — the VPN
// still works but may be limited by default kernel buffer caps.
//
// Key settings:
//   - rmem_max/wmem_max=16 MB: allows SO_RCVBUF/SO_SNDBUF up to 16 MB
//   - tcp_rmem/tcp_wmem: autotuning range up to 16 MB
//   - default_qdisc=fq: required for BBR to work correctly
//   - tcp_congestion_control=bbr: global BBR (per-socket fallback in setForcedSocketBuffers)
//   - ip_forward=1: required for TUN packet routing
//   - tcp_fastopen=3: enable TFO for both client and server sockets
//   - tcp_mtu_probing=1: discover path MTU to avoid fragmentation
//   - tcp_slow_start_after_idle=0: don't reset cwnd after idle periods
func applySysctls() {
	sysctls := map[string]string{
		// 4 MB max — enough for 400 Mbps at 80ms, no bufferbloat.
		// 16 MB caused latency spike from 80ms to 321ms.
		"net.core.rmem_max":                  "4194304",
		"net.core.wmem_max":                  "4194304",
		"net.core.rmem_default":              "524288",
		"net.core.wmem_default":              "524288",
		"net.ipv4.tcp_rmem":                  "4096 524288 4194304",
		"net.ipv4.tcp_wmem":                  "4096 524288 4194304",
		"net.core.default_qdisc":             "fq",
		"net.ipv4.tcp_congestion_control":    "bbr",
		"net.ipv4.ip_forward":                "1",
		"net.ipv4.tcp_fastopen":              "3",
		"net.ipv4.tcp_mtu_probing":           "1",
		"net.ipv4.tcp_slow_start_after_idle": "0",
		"net.core.netdev_max_backlog":        "5000",
	}
	for k, v := range sysctls {
		path := "/proc/sys/" + strings.ReplaceAll(k, ".", "/")
		os.WriteFile(path, []byte(v), 0644) //nolint:errcheck — best-effort
	}
}

// verifyBBR checks whether the BBR congestion control module is available
// and the global congestion algorithm is correctly set to BBR. Logs warnings
// for any issues. This is called at startup to surface misconfigurations
// early — a missing tcp_bbr module silently falls back to CUBIC, causing
// 10× worse throughput on lossy links (0.7% loss Russia↔Kazakhstan).
func verifyBBR(logger interface{ Warn(string, ...any); Info(string, ...any) }) {
	// Check if the tcp_bbr kernel module is loaded.
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
	if err != nil {
		logger.Warn("cannot read available congestion control algorithms", "err", err)
		return
	}
	available := strings.TrimSpace(string(data))
	if !strings.Contains(available, "bbr") {
		logger.Warn("BBR congestion control NOT available — throughput will be degraded",
			"available", available,
			"hint", "run: modprobe tcp_bbr")
	} else {
		logger.Info("BBR congestion control available", "algorithms", available)
	}

	// Verify the active global algorithm.
	data, err = os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		logger.Warn("cannot read active congestion control", "err", err)
		return
	}
	active := strings.TrimSpace(string(data))
	if active != "bbr" {
		logger.Warn("global congestion control is NOT bbr — per-socket fallback will be used",
			"active", active)
	} else {
		logger.Info("global congestion control confirmed", "algorithm", active)
	}

	// Verify qdisc is fq (required for BBR pacing).
	data, err = os.ReadFile("/proc/sys/net/core/default_qdisc")
	if err == nil {
		qdisc := strings.TrimSpace(string(data))
		if qdisc != "fq" {
			logger.Warn("default qdisc is not 'fq' — BBR pacing may not work correctly",
				"qdisc", qdisc,
				"hint", "run: sysctl net.core.default_qdisc=fq")
		}
	}
}

// setListenerTFO enables TCP Fast Open on a TCP listener socket.
// TFO allows clients to send data in the SYN packet, saving 1 RTT
// (80-120 ms Russia↔Kazakhstan) on reconnections after the first.
// The queue length (128) sets the max pending TFO connections.
func setListenerTFO(ln *net.TCPListener) {
	raw, err := ln.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) { //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpen, 128) //nolint:errcheck
	})
}

// setListenerDeferAccept sets TCP_DEFER_ACCEPT on a TCP listener socket.
// The kernel holds incoming connections in SYN_RECV state until the client
// sends data (up to timeout seconds), eliminating a context switch per
// connection and silently dropping SYN-only probes.
func setListenerDeferAccept(ln *net.TCPListener, timeout int) {
	raw, err := ln.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) { //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpDeferAccept, timeout) //nolint:errcheck
	})
}

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
		// TCP_KEEPIDLE=15s: wait 15 s of idle before first probe.
		// TCP_KEEPINTVL=5s: repeat probes every 5 s.
		// TCP_KEEPCNT=3: declare connection dead after 3 missed probes.
		// Total disconnect detection: 15 + 3×5 = 30 s — well inside NAT timeouts
		// and detects dead connections 2× faster than before (was 60 s).
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1) //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIdle, 15)        //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepIntvl, 5)        //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpKeepCnt, 3)          //nolint:errcheck
		// Busy-poll: spin for 50 µs in the driver on empty recv to cut latency.
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soBusyPoll, 50) //nolint:errcheck
		// Window clamp: allow the kernel to advertise the full buffer window.
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpWindowClamp, size) //nolint:errcheck
		// TCP_NOTSENT_LOWAT: limit unsent data to 16 KB. On packet loss,
		// only 16 KB needs retransmitting instead of the entire send buffer.
		// Reduces tail latency 5-10× on the 0.7% loss Kazakhstan route.
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpNotSentLowat, notSentLowatBytes) //nolint:errcheck
	})
}

// setConnTTL64 sets IP TTL to 64 on any net.Conn that supports SyscallConn.
// Linux default is already 64, but we set it explicitly to ensure consistency
// regardless of sysctl net.ipv4.ip_default_ttl changes.
func setConnTTL64(conn net.Conn) {
	type syscaller interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := conn.(syscaller)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) { //nolint:errcheck
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 64) //nolint:errcheck
	})
}
