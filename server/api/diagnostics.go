// Package api — server-side system metrics and speed test for telemetry diagnostics.

package api

import (
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cavad93/vpn/server/perf"
)

// ---------------------------------------------------------------------------
// Server system metrics
// ---------------------------------------------------------------------------

// ServerMetrics holds server-side system resource usage.
type ServerMetrics struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`      // process CPU usage
	MemoryMB      float64   `json:"memory_mb"`         // process RSS
	NumGoroutines int       `json:"num_goroutines"`    // goroutine count
	HeapAllocMB   float64   `json:"heap_alloc_mb"`     // Go heap in use
	HeapSysMB     float64   `json:"heap_sys_mb"`       // Go heap reserved
	GCPauseUs     float64   `json:"gc_pause_us"`       // last GC pause
	NumGC         uint32    `json:"num_gc"`             // total GC cycles
	UptimeSec     float64   `json:"uptime_sec"`        // server uptime
}

var serverStartTime = time.Now()

// collectServerMetrics gathers current server resource usage.
func CollectServerMetrics() ServerMetrics {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	cpuPct := estimateCPU()

	return ServerMetrics{
		Timestamp:     time.Now(),
		CPUPercent:    cpuPct,
		MemoryMB:      float64(getRSSBytes()) / (1024 * 1024),
		NumGoroutines: runtime.NumGoroutine(),
		HeapAllocMB:   float64(mem.HeapAlloc) / (1024 * 1024),
		HeapSysMB:     float64(mem.HeapSys) / (1024 * 1024),
		GCPauseUs:     float64(mem.PauseNs[(mem.NumGC+255)%256]) / 1000,
		NumGC:         mem.NumGC,
		UptimeSec:     time.Since(serverStartTime).Seconds(),
	}
}

// estimateCPU reads /proc/self/stat to estimate process CPU usage.
func estimateCPU() float64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0 // non-Linux
	}

	// /proc/self/stat fields: pid (comm) state ppid ... utime stime ...
	// utime is field 14, stime is field 15 (1-indexed).
	// We need to skip past the (comm) field which may contain spaces.
	str := string(data)
	closeIdx := strings.LastIndex(str, ")")
	if closeIdx < 0 {
		return 0
	}
	fields := strings.Fields(str[closeIdx+2:])
	if len(fields) < 13 {
		return 0
	}

	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	totalTicks := utime + stime
	cpuSeconds := totalTicks / 100 // USER_HZ = 100 on Linux
	uptime := time.Since(serverStartTime).Seconds()
	if uptime <= 0 {
		return 0
	}
	return (cpuSeconds / uptime) * 100
}

// getRSSBytes reads /proc/self/status for VmRSS.
func getRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		return mem.Sys // fallback to Go runtime Sys
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseUint(fields[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Speed test endpoint
// ---------------------------------------------------------------------------

// speedTestChunkSize is the size of random data sent in the speed test.
const speedTestChunkSize = 1024 * 1024 // 1 MB

// speedTestBuf is a pre-generated random buffer to avoid per-request allocations.
var speedTestBuf []byte
var speedTestOnce sync.Once

func getSpeedTestBuf() []byte {
	speedTestOnce.Do(func() {
		speedTestBuf = make([]byte, speedTestChunkSize)
		rand.Read(speedTestBuf)
	})
	return speedTestBuf
}

// ---------------------------------------------------------------------------
// Enhanced telemetry: server perf snapshot in analysis
// ---------------------------------------------------------------------------

// ServerPerfSummary is a condensed version of perf.Snapshot for telemetry.
type ServerPerfSummary struct {
	ObfsWriteP95Us    float64 `json:"obfs_write_p95_us"`
	ObfsReadP95Us     float64 `json:"obfs_read_p95_us"`
	NoiseEncryptP95Us float64 `json:"noise_encrypt_p95_us"`
	NoiseDecryptP95Us float64 `json:"noise_decrypt_p95_us"`
	MuxWriteP95Us     float64 `json:"mux_write_p95_us"`
	MuxReadP95Us      float64 `json:"mux_read_p95_us"`
	TunWriteP95Us     float64 `json:"tun_write_p95_us"`
	TunReadP95Us      float64 `json:"tun_read_p95_us"`
	FullIngressP95Us  float64 `json:"full_ingress_p95_us"`
	FullEgressP95Us   float64 `json:"full_egress_p95_us"`
	HandshakeMeanUs   float64 `json:"handshake_mean_us"`
	RetransmitCount   uint64  `json:"retransmit_count"`
	TCPRTTUs          uint64  `json:"tcp_rtt_us"`
	TCPLostSegs       uint64  `json:"tcp_lost_segs"`
	TCPCwndSegs       uint64  `json:"tcp_cwnd_segs"`
}

// summarizePerf extracts key metrics from a perf.Snapshot.
func SummarizePerf(snap perf.Snapshot) ServerPerfSummary {
	p95 := func(stage string) float64 {
		if s, ok := snap.Stages[stage]; ok {
			return s.Latency.P95Us
		}
		return 0
	}
	mean := func(stage string) float64 {
		if s, ok := snap.Stages[stage]; ok {
			return s.Latency.MeanUs
		}
		return 0
	}
	return ServerPerfSummary{
		ObfsWriteP95Us:    p95("obfs_write"),
		ObfsReadP95Us:     p95("obfs_read"),
		NoiseEncryptP95Us: p95("noise_encrypt"),
		NoiseDecryptP95Us: p95("noise_decrypt"),
		MuxWriteP95Us:     p95("mux_write"),
		MuxReadP95Us:      p95("mux_read"),
		TunWriteP95Us:     p95("tun_write"),
		TunReadP95Us:      p95("tun_read"),
		FullIngressP95Us:  p95("full_ingress"),
		FullEgressP95Us:   p95("full_egress"),
		HandshakeMeanUs:   mean("handshake"),
		RetransmitCount:   snap.RetransmitCount,
		TCPRTTUs:          snap.TCPInfo.RTTUs,
		TCPLostSegs:       snap.TCPInfo.LostSegs,
		TCPCwndSegs:       snap.TCPInfo.CwndSegs,
	}
}

// ---------------------------------------------------------------------------
// API route registration
// ---------------------------------------------------------------------------

// registerDiagnosticsRoutes adds server metrics and speed test endpoints.
func (a *APIServer) registerDiagnosticsRoutes() {
	// Server system metrics — auth required.
	a.mux.HandleFunc("GET /api/v1/server/metrics", a.auth(a.handleServerMetrics))
	// Speed test — download direction (no auth, needs to work from clients).
	a.mux.HandleFunc("GET /api/v1/speedtest/download", a.handleSpeedTestDownload)
	// Speed test — upload direction.
	a.mux.HandleFunc("POST /api/v1/speedtest/upload", a.handleSpeedTestUpload)
	// Combined diagnostics: server metrics + perf + latest telemetry analysis.
	a.mux.HandleFunc("GET /api/v1/diagnostics", a.auth(a.handleDiagnostics))
}

// handleServerMetrics returns current server resource usage.
func (a *APIServer) handleServerMetrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, CollectServerMetrics())
}

// handleSpeedTestDownload streams random data for download speed measurement.
// Client measures how fast it can receive `size` bytes.
// Query: ?size=1048576 (default 1MB, max 10MB)
func (a *APIServer) handleSpeedTestDownload(w http.ResponseWriter, r *http.Request) {
	size := speedTestChunkSize
	if s := r.URL.Query().Get("size"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			size = n
		}
	}
	if size > 10*1024*1024 {
		size = 10 * 1024 * 1024
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(size))
	w.Header().Set("X-Speedtest-Size", strconv.Itoa(size))
	w.WriteHeader(http.StatusOK)

	buf := getSpeedTestBuf()
	written := 0
	for written < size {
		chunk := size - written
		if chunk > len(buf) {
			chunk = len(buf)
		}
		n, err := w.Write(buf[:chunk])
		written += n
		if err != nil {
			return
		}
	}
}

// handleSpeedTestUpload measures upload speed: client sends data, server
// discards and returns stats.
func (a *APIServer) handleSpeedTestUpload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	n, _ := io.Copy(io.Discard, r.Body)
	elapsed := time.Since(start).Seconds()

	speedKbps := 0.0
	if elapsed > 0 {
		speedKbps = float64(n*8) / (elapsed * 1000)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"bytes":      n,
		"elapsed_ms": elapsed * 1000,
		"speed_kbps": speedKbps,
	})
}

// DiagnosticsResponse combines all diagnostics data.
type DiagnosticsResponse struct {
	Server   ServerMetrics      `json:"server"`
	Perf     *ServerPerfSummary `json:"perf,omitempty"`
	Analysis *AnalysisResult    `json:"analysis,omitempty"`
}

// handleDiagnostics returns the combined diagnostics view.
func (a *APIServer) handleDiagnostics(w http.ResponseWriter, _ *http.Request) {
	resp := DiagnosticsResponse{
		Server: CollectServerMetrics(),
	}

	if a.perfCollector != nil {
		snap := a.perfCollector.Snapshot()
		summary := SummarizePerf(snap)
		resp.Perf = &summary
	}

	if a.telemetryStore != nil {
		resp.Analysis = a.telemetryStore.LastAnalysis()
	}

	writeJSON(w, http.StatusOK, resp)
}
