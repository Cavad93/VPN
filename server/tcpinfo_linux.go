//go:build linux

package main

import (
	"net"

	"github.com/cavad93/vpn/server/perf"
	"golang.org/x/sys/unix"
)

// pollTCPInfo reads OS-level TCP metrics from the connection and updates
// the perf collector atomically. Called periodically from the data path.
//
// Uses unix.GetsockoptTCPInfo() instead of raw Syscall6 to guarantee correct
// struct alignment across kernel versions. The raw Syscall6 approach could
// return zero for Rttvar and Snd_ssthresh if the kernel's tcp_info struct
// had padding differences from the Go definition.
func pollTCPInfo(conn net.Conn, pc *perf.Collector) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	var info *unix.TCPInfo
	var controlErr error
	raw.Control(func(fd uintptr) { //nolint:errcheck
		info, controlErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if controlErr != nil || info == nil {
		return
	}
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
