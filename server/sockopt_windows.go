//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// SIO_TCP_SET_ACK_FREQUENCY is a Windows Winsock ioctl that controls how
// often the TCP stack sends ACKs. By default, Windows delays ACKs for up
// to 200 ms (the "delayed ACK" timer). Setting this to 1 makes the stack
// ACK every incoming segment immediately — the Windows equivalent of
// Linux TCP_QUICKACK.
//
// Without this, the 200 ms delayed ACK combined with 93 ms RTT means the
// sender's congestion window can only grow once per ~293 ms round-trip.
// This alone caps throughput to ~17 KB/window × (1000/293) ≈ 450 KB/s.
// With immediate ACKs, the window grows every ~93 ms, tripling throughput.
//
// Constant: IOC_IN(0x80000000) | IOC_VENDOR(0x18000000) | 23 = 0x98000017
const sioTCPSetACKFrequency = 0x98000017

// TCP_NOTSENT_LOWAT limits unsent data in the kernel send buffer.
// When unsent bytes drop below this threshold, the socket becomes writable.
// Setting to 16 KB means at most 16 KB needs retransmitting on packet loss,
// reducing tail latency 5-10× on lossy links. Available on Windows 10 1903+
// and Windows Server 2019+. Fails silently on older versions.
const tcpNotSentLowat = 25 // TCP_NOTSENT_LOWAT — Windows 10 1903+

// notSentLowatBytes is the threshold value for TCP_NOTSENT_LOWAT.
const notSentLowatBytes = 16384

// applySysctls runs Windows-specific global TCP tuning via netsh.
// Requires admin rights (the VPN server always runs as admin).
//
// Key settings:
//   - autotuninglevel=experimental: allows kernel to use the largest TCP
//     receive window (up to 16 MB). Default "normal" caps at ~1 MB.
//   - congestionprovider=ctcp: Compound TCP — better than default CUBIC
//     on high-latency (93 ms) links because it uses both loss and delay signals.
//   - ecncapability=enabled: Explicit Congestion Notification reduces loss-based
//     retransmissions on congested paths.
func applySysctls() {
	// Each command is logged so the admin can verify which settings applied.
	cmds := [][]string{
		// Largest TCP receive window (up to 16 MB). Default "normal" caps ~256 KB.
		{"netsh", "int", "tcp", "set", "global", "autotuninglevel=experimental"},
		// CTCP: uses both loss and delay signals for congestion control.
		{"netsh", "int", "tcp", "set", "global", "congestionprovider=ctcp"},
		// ECN: reduce loss-based retransmissions.
		{"netsh", "int", "tcp", "set", "global", "ecncapability=enabled"},
		// Receive Side Scaling: use multiple CPU cores for TCP.
		{"netsh", "int", "tcp", "set", "global", "rss=enabled"},
		// TCP timestamps: more accurate RTT measurement for congestion control.
		{"netsh", "int", "tcp", "set", "global", "timestamps=enabled"},
		// Initial congestion window = 100 MSS ≈ 146 KB.
		// With 80 ms RTT and 0.7% packet loss on the Kazakhstan→Russia route,
		// the per-connection cwnd stabilizes at ~17 KB. A large IW gets the
		// first burst through faster before losses kick in. Combined with
		// multi-connection bonding (8 connections), this yields ~14 Mbps.
		{"netsh", "int", "tcp", "set", "global", "initialcongestionwindow=100"},
		// Enable IP forwarding on all interfaces — required for TUN routing.
		{"netsh", "int", "ipv4", "set", "global", "forwarding=enabled"},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[sysctl] FAIL %v: %s\n", args, string(out))
		} else {
			fmt.Fprintf(os.Stderr, "[sysctl] OK   %v\n", args)
		}
	}
}

// verifyBBR is a no-op on Windows (Windows uses CTCP, not BBR).
func verifyBBR(_ interface{ Warn(string, ...any); Info(string, ...any) }) {}

// setListenerTFO is a no-op on Windows.
// Windows 10+ has TFO support but it's enabled globally via netsh,
// not per-socket like on Linux.
func setListenerTFO(_ *net.TCPListener) {}

// setListenerDeferAccept is a no-op on Windows.
func setListenerDeferAccept(_ *net.TCPListener, _ int) {}

// setForcedSocketBuffers sets large TCP socket buffers and disables the
// 200 ms delayed ACK timer on each VPN client connection.
//
// The delayed ACK fix is the single highest-impact optimization for Windows:
// it reduces the effective per-ACK RTT from ~293 ms (200 ms delay + 93 ms
// network) to ~93 ms, allowing the TCP congestion window to grow ~3× faster.
func setForcedSocketBuffers(conn *net.TCPConn, size int) {
	conn.SetReadBuffer(size)  //nolint:errcheck
	conn.SetWriteBuffer(size) //nolint:errcheck

	// Disable Nagle's algorithm — VPN packets must not be delayed.
	conn.SetNoDelay(true) //nolint:errcheck

	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) { //nolint:errcheck
		// Disable delayed ACKs: ACK every segment immediately.
		// This is the Windows equivalent of Linux TCP_QUICKACK.
		freq := uint32(1)
		var bytesReturned uint32
		syscall.WSAIoctl( //nolint:errcheck
			syscall.Handle(fd),
			sioTCPSetACKFrequency,
			(*byte)(unsafe.Pointer(&freq)),
			uint32(unsafe.Sizeof(freq)),
			nil, 0,
			&bytesReturned,
			nil, 0,
		)
		// TCP_NOTSENT_LOWAT: limit unsent data to 16 KB.
		// Reduces retransmit penalty on packet loss from megabytes to 16 KB.
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, tcpNotSentLowat, notSentLowatBytes) //nolint:errcheck
	})
}
