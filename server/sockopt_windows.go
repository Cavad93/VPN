//go:build windows

package main

import (
	"net"
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
	// Best-effort — errors are ignored. If any command fails, the VPN
	// still works, just with default (slower) TCP settings.
	cmds := [][]string{
		{"netsh", "int", "tcp", "set", "global", "autotuninglevel=experimental"},
		{"netsh", "int", "tcp", "set", "global", "congestionprovider=ctcp"},
		{"netsh", "int", "tcp", "set", "global", "ecncapability=enabled"},
		{"netsh", "int", "tcp", "set", "global", "rss=enabled"},
		// Enable IP forwarding on all interfaces — required for TUN routing.
		{"netsh", "int", "ipv4", "set", "global", "forwarding=enabled"},
	}
	for _, args := range cmds {
		exec.Command(args[0], args[1:]...).Run() //nolint:errcheck
	}
}

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
	})
}
