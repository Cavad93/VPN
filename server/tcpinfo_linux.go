//go:build linux

package main

import (
	"net"
	"unsafe"

	"github.com/cavad93/vpn/server/perf"
	"golang.org/x/sys/unix"
)

// pollTCPInfo reads OS-level TCP metrics from the connection and updates
// the perf collector atomically. Called periodically from the data path.
func pollTCPInfo(conn net.Conn, pc *perf.Collector) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	var info unix.TCPInfo
	raw.Control(func(fd uintptr) { //nolint:errcheck
		size := uint32(unsafe.Sizeof(info))
		// getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &size)
		unix.Syscall6( //nolint:errcheck
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.IPPROTO_TCP),
			uintptr(unix.TCP_INFO),
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
	})
	pc.TCP.RTTUs.Store(uint64(info.Rtt))
	pc.TCP.RTTVarUs.Store(uint64(info.Rttvar))
	pc.TCP.RetransmitSegs.Store(uint64(info.Total_retrans))
	pc.TCP.LostSegs.Store(uint64(info.Lost))
	pc.TCP.CwndSegs.Store(uint64(info.Snd_cwnd))
	pc.TCP.SndMSS.Store(uint64(info.Snd_mss))
	pc.TCP.SSThresh.Store(uint64(info.Snd_ssthresh))

	// Sync top-level perf fields with OS TCP info so the diagnostics AI
	// sees consistent retransmit_count, congestion_window, and ssthresh.
	pc.RetransmitCount.Store(uint64(info.Total_retrans))
	pc.CongestionWindow.Store(int64(info.Snd_cwnd))
	pc.SSThresh.Store(int64(info.Snd_ssthresh))
}
