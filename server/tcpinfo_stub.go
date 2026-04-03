//go:build !linux && !windows

package main

import (
	"net"

	"github.com/cavad93/vpn/server/perf"
)

// pollTCPInfo is a no-op on platforms without TCP_INFO support.
func pollTCPInfo(_ net.Conn, _ *perf.Collector) {}
