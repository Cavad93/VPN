//go:build windows

package main

import (
	"net"
	"syscall"
	"unsafe"

	"github.com/cavad93/vpn/server/perf"
)

// MIB_TCPROW_OWNER_PID and related structures are not needed; we use
// getsockopt TCP_INFO_v0 which Windows 10 1709+ / Server 2019 supports.
//
// struct TCP_INFO_v0 from <mstcpip.h>:
type tcpInfoV0 struct {
	State             uint32
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled uint8  // BOOLEAN
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        uint8
}

// SIO_TCP_INFO is the Windows ioctl to query TCP_INFO_v0.
// Constant: IOC_INOUT(0xC0000000) | IOC_VENDOR(0x18000000) | 39 = 0xD8000027
const sioTCPInfo = 0xD8000027

// pollTCPInfo reads OS-level TCP metrics from the connection via the
// SIO_TCP_INFO ioctl (Windows Server 2019+) and updates the perf collector.
func pollTCPInfo(conn net.Conn, pc *perf.Collector) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	var info tcpInfoV0
	raw.Control(func(fd uintptr) { //nolint:errcheck
		// SIO_TCP_INFO requires the version as the input parameter.
		version := uint32(0) // v0
		var bytesReturned uint32
		syscall.WSAIoctl( //nolint:errcheck
			syscall.Handle(fd),
			sioTCPInfo,
			(*byte)(unsafe.Pointer(&version)),
			uint32(unsafe.Sizeof(version)),
			(*byte)(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
			&bytesReturned,
			nil, 0,
		)
	})
	pc.TCP.RTTUs.Store(uint64(info.RttUs))
	pc.TCP.RTTVarUs.Store(0) // Not available in TCP_INFO_v0
	mss := uint64(info.Mss)
	if mss == 0 {
		mss = 1
	}
	retransSegs := uint64(info.BytesRetrans) / mss
	cwndSegs := uint64(info.Cwnd) / mss
	pc.TCP.RetransmitSegs.Store(retransSegs)
	pc.TCP.LostSegs.Store(uint64(info.TimeoutEpisodes))
	pc.TCP.CwndSegs.Store(cwndSegs)
	pc.TCP.SndMSS.Store(uint64(info.Mss))
	pc.TCP.SSThresh.Store(0) // Not available in TCP_INFO_v0

	// Sync top-level perf fields with OS TCP info so the diagnostics AI
	// sees consistent retransmit_count, congestion_window, and ssthresh.
	pc.RetransmitCount.Store(retransSegs)
	pc.CongestionWindow.Store(int64(cwndSegs))
	// SSThresh not available from Windows TCP_INFO_v0; leave unchanged.
}
