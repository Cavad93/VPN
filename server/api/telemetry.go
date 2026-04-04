// Package api — telemetry collection and AI-powered diagnostics.
//
// Endpoints:
//
//	POST   /api/v1/telemetry          — submit telemetry report from client
//	GET    /api/v1/telemetry          — list recent telemetry reports
//	GET    /api/v1/telemetry/analysis — latest AI analysis result
//	POST   /api/v1/telemetry/analyze  — trigger immediate analysis

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// jsonReader wraps JSON bytes into an io.Reader.
func jsonReader(b []byte) io.Reader { return bytes.NewReader(b) }

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

// TelemetryReport is a single diagnostic snapshot sent by a client device.
type TelemetryReport struct {
	// Device identification
	DeviceID   string `json:"device_id"`             // unique device identifier (hex)
	Platform   string `json:"platform"`              // "android", "ios", "macos"
	AppVersion string `json:"app_version,omitempty"` // e.g. "1.0.0"

	// Timing
	Timestamp time.Time `json:"timestamp"`            // when the report was created on the client
	ReceivedAt time.Time `json:"received_at"`          // when the server received it

	// Connection metrics
	ServerAddr     string  `json:"server_addr"`               // server:port the client connects to
	ConnectionState string `json:"connection_state"`          // "connected", "reconnecting", "disconnected"
	UptimeSec      float64 `json:"uptime_sec"`                // seconds since last connect
	ReconnectCount int     `json:"reconnect_count"`           // reconnects since app start

	// Latency
	HandshakeMs float64 `json:"handshake_ms"`          // Noise_XX handshake duration
	PingMs      float64 `json:"ping_ms"`               // round-trip time to server
	JitterMs    float64 `json:"jitter_ms,omitempty"`   // ping variance

	// Throughput
	BytesIn       uint64  `json:"bytes_in"`              // total bytes received
	BytesOut      uint64  `json:"bytes_out"`             // total bytes sent
	ThroughputIn  float64 `json:"throughput_in_kbps"`    // current download speed kbit/s
	ThroughputOut float64 `json:"throughput_out_kbps"`   // current upload speed kbit/s

	// Packet stats
	PacketLossPercent float64 `json:"packet_loss_percent"` // estimated packet loss
	RetransmitCount   int     `json:"retransmit_count"`    // UDP retransmissions
	OutOfOrderCount   int     `json:"out_of_order_count"`  // out-of-order packets

	// Network environment
	NetworkType    string `json:"network_type"`            // "wifi", "cellular", "ethernet"
	SignalStrength int    `json:"signal_strength,omitempty"` // dBm for cellular, RSSI for wifi
	Carrier        string `json:"carrier,omitempty"`        // mobile carrier name
	LocalIP        string `json:"local_ip,omitempty"`       // device local IP (privacy: last octet masked)
	PublicIP       string `json:"public_ip,omitempty"`      // client's public IP as seen by server

	// TLS obfuscation
	ObfsLatencyMs float64 `json:"obfs_latency_ms,omitempty"` // obfuscation overhead
	DPIDetected   bool    `json:"dpi_detected,omitempty"`    // client suspects DPI interference
	TLSErrors     int     `json:"tls_errors,omitempty"`      // TLS handshake failures

	// DNS
	DNSResolveMs float64 `json:"dns_resolve_ms,omitempty"` // DNS resolution time

	// Speed test
	DownloadSpeedKbps float64 `json:"download_speed_kbps,omitempty"` // measured download speed
	UploadSpeedKbps   float64 `json:"upload_speed_kbps,omitempty"`   // measured upload speed

	// System
	CPUPercent    float64 `json:"cpu_percent,omitempty"`     // app CPU usage
	MemoryMB      float64 `json:"memory_mb,omitempty"`       // app memory usage
	BatteryPercent int    `json:"battery_percent,omitempty"` // device battery level
}

// AnalysisResult is the output of AI-powered telemetry analysis.
type AnalysisResult struct {
	Timestamp    time.Time          `json:"timestamp"`
	ReportCount  int                `json:"report_count"`   // how many reports were analyzed
	DeviceCount  int                `json:"device_count"`   // unique devices
	Summary      string             `json:"summary"`        // human-readable summary
	Issues       []DiagnosticIssue  `json:"issues"`         // detected problems
	Recommendations []string        `json:"recommendations"` // suggested actions
	RawPrompt    string             `json:"raw_prompt,omitempty"` // the prompt sent to AI (debug)
	RawResponse  string             `json:"raw_response,omitempty"` // raw AI response (debug)
	Error        string             `json:"error,omitempty"` // if analysis failed
}

// DiagnosticIssue is a single problem found during analysis.
type DiagnosticIssue struct {
	Severity    string   `json:"severity"`     // "critical", "warning", "info"
	Category    string   `json:"category"`     // "latency", "packet_loss", "throughput", "dpi", "connection"
	Description string   `json:"description"`  // human-readable description
	AffectedDevices []string `json:"affected_devices,omitempty"` // device IDs
}

// ---------------------------------------------------------------------------
// Telemetry store (in-memory ring buffer)
// ---------------------------------------------------------------------------

// TelemetryStore holds recent telemetry reports in a ring buffer.
type TelemetryStore struct {
	mu       sync.RWMutex
	reports  []TelemetryReport
	capacity int
	pos      int // write position in ring buffer
	full     bool

	analysisMu sync.RWMutex
	lastAnalysis *AnalysisResult
}

// NewTelemetryStore creates a store with the given capacity.
func NewTelemetryStore(capacity int) *TelemetryStore {
	if capacity <= 0 {
		capacity = 10000
	}
	return &TelemetryStore{
		reports:  make([]TelemetryReport, capacity),
		capacity: capacity,
	}
}

// Add stores a new telemetry report.
func (ts *TelemetryStore) Add(r TelemetryReport) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	r.ReceivedAt = time.Now()
	ts.reports[ts.pos] = r
	ts.pos++
	if ts.pos >= ts.capacity {
		ts.pos = 0
		ts.full = true
	}
}

// Recent returns the last n reports in chronological order.
func (ts *TelemetryStore) Recent(n int) []TelemetryReport {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	total := ts.count()
	if n <= 0 || n > total {
		n = total
	}
	if n == 0 {
		return nil
	}

	result := make([]TelemetryReport, n)
	// Read the last n entries in chronological order.
	start := ts.pos - n
	if start < 0 {
		if ts.full {
			start += ts.capacity
		} else {
			start = 0
			n = ts.pos
			result = result[:n]
		}
	}
	for i := 0; i < n; i++ {
		idx := (start + i) % ts.capacity
		result[i] = ts.reports[idx]
	}
	return result
}

// Since returns all reports after the given time.
func (ts *TelemetryStore) Since(after time.Time) []TelemetryReport {
	all := ts.Recent(0) // get all
	var out []TelemetryReport
	for _, r := range all {
		if r.ReceivedAt.After(after) {
			out = append(out, r)
		}
	}
	return out
}

// Count returns the number of stored reports.
func (ts *TelemetryStore) Count() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.count()
}

func (ts *TelemetryStore) count() int {
	if ts.full {
		return ts.capacity
	}
	return ts.pos
}

// SetAnalysis stores the latest analysis result.
func (ts *TelemetryStore) SetAnalysis(a *AnalysisResult) {
	ts.analysisMu.Lock()
	defer ts.analysisMu.Unlock()
	ts.lastAnalysis = a
}

// LastAnalysis returns the most recent analysis result, or nil.
func (ts *TelemetryStore) LastAnalysis() *AnalysisResult {
	ts.analysisMu.RLock()
	defer ts.analysisMu.RUnlock()
	return ts.lastAnalysis
}

// ---------------------------------------------------------------------------
// AI Analyzer
// ---------------------------------------------------------------------------

// AnalyzerFunc is a function that analyzes telemetry reports and returns a result.
// It receives a context, the reports to analyze, the Anthropic API key, and optional server perf data.
type AnalyzerFunc func(ctx context.Context, reports []TelemetryReport, apiKey string, serverPerf *ServerPerfSummary, serverMetrics *ServerMetrics) (*AnalysisResult, error)

// TelemetryAnalyzer runs periodic AI analysis of telemetry data.
type TelemetryAnalyzer struct {
	store    *TelemetryStore
	analyze  AnalyzerFunc
	apiKey   string
	interval time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
	// Optional: callbacks to get server-side data for enriching analysis.
	GetServerPerf    func() *ServerPerfSummary
	GetServerMetrics func() *ServerMetrics
}

// NewTelemetryAnalyzer creates an analyzer that runs every interval.
func NewTelemetryAnalyzer(store *TelemetryStore, fn AnalyzerFunc, apiKey string, interval time.Duration) *TelemetryAnalyzer {
	return &TelemetryAnalyzer{
		store:    store,
		analyze:  fn,
		apiKey:   apiKey,
		interval: interval,
	}
}

// Start begins the periodic analysis loop.
func (ta *TelemetryAnalyzer) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	ta.cancel = cancel
	ta.done = make(chan struct{})
	go ta.loop(ctx)
}

// Stop stops the analyzer.
func (ta *TelemetryAnalyzer) Stop() {
	if ta.cancel != nil {
		ta.cancel()
		<-ta.done
	}
}

func (ta *TelemetryAnalyzer) loop(ctx context.Context) {
	defer close(ta.done)
	ticker := time.NewTicker(ta.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ta.runOnce(ctx)
		}
	}
}

// RunOnce triggers a single analysis cycle.
func (ta *TelemetryAnalyzer) RunOnce(ctx context.Context) *AnalysisResult {
	return ta.runOnce(ctx)
}

func (ta *TelemetryAnalyzer) runOnce(ctx context.Context) *AnalysisResult {
	// Analyze reports from the last interval (+ 10% overlap).
	since := time.Now().Add(-ta.interval - ta.interval/10)
	reports := ta.store.Since(since)
	if len(reports) == 0 {
		result := &AnalysisResult{
			Timestamp:   time.Now(),
			ReportCount: 0,
			Summary:     "No telemetry reports received in the last analysis window.",
		}
		ta.store.SetAnalysis(result)
		return result
	}

	// Gather server-side data.
	var perfSummary *ServerPerfSummary
	var srvMetrics *ServerMetrics
	if ta.GetServerPerf != nil {
		perfSummary = ta.GetServerPerf()
	}
	if ta.GetServerMetrics != nil {
		srvMetrics = ta.GetServerMetrics()
	}

	result, err := ta.analyze(ctx, reports, ta.apiKey, perfSummary, srvMetrics)
	if err != nil {
		result = &AnalysisResult{
			Timestamp:   time.Now(),
			ReportCount: len(reports),
			Error:       err.Error(),
			Summary:     "Analysis failed: " + err.Error(),
		}
	}
	ta.store.SetAnalysis(result)
	return result
}

// ---------------------------------------------------------------------------
// Default Sonnet analyzer (calls Anthropic API)
// ---------------------------------------------------------------------------

// SonnetAnalyze calls Claude Sonnet API to analyze telemetry reports.
func SonnetAnalyze(ctx context.Context, reports []TelemetryReport, apiKey string, serverPerf *ServerPerfSummary, serverMetrics *ServerMetrics) (*AnalysisResult, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("anthropic API key not configured")
	}

	// Build analysis prompt.
	prompt := buildAnalysisPrompt(reports, serverPerf, serverMetrics)

	// Call Anthropic Messages API.
	body := map[string]interface{}{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 2048,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", jsonReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("anthropic API %d: %v", resp.StatusCode, errBody)
	}

	var apiResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(apiResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from Anthropic API")
	}

	rawText := apiResp.Content[0].Text

	// Parse structured response.
	result := parseAnalysisResponse(rawText, len(reports))
	result.RawPrompt = prompt
	result.RawResponse = rawText
	return result, nil
}

// buildAnalysisPrompt creates the prompt for Sonnet from telemetry data.
func buildAnalysisPrompt(reports []TelemetryReport, serverPerf *ServerPerfSummary, serverMetrics *ServerMetrics) string {
	// Aggregate per-device stats.
	type deviceStats struct {
		Platform       string
		ReportCount    int
		AvgPingMs      float64
		MaxPingMs      float64
		AvgLossPercent float64
		MaxLossPercent float64
		AvgThroughIn   float64
		AvgThroughOut  float64
		Reconnects     int
		DPIDetected    int
		TLSErrors      int
		AvgDNSMs       float64
		AvgDownloadKbps float64
		AvgUploadKbps  float64
		NetworkTypes   map[string]int
		States         map[string]int
	}

	devices := make(map[string]*deviceStats)
	for _, r := range reports {
		ds, ok := devices[r.DeviceID]
		if !ok {
			ds = &deviceStats{
				Platform:     r.Platform,
				NetworkTypes: make(map[string]int),
				States:       make(map[string]int),
			}
			devices[r.DeviceID] = ds
		}
		ds.ReportCount++
		ds.AvgPingMs += r.PingMs
		if r.PingMs > ds.MaxPingMs {
			ds.MaxPingMs = r.PingMs
		}
		ds.AvgLossPercent += r.PacketLossPercent
		if r.PacketLossPercent > ds.MaxLossPercent {
			ds.MaxLossPercent = r.PacketLossPercent
		}
		ds.AvgThroughIn += r.ThroughputIn
		ds.AvgThroughOut += r.ThroughputOut
		ds.Reconnects += r.ReconnectCount
		if r.DPIDetected {
			ds.DPIDetected++
		}
		ds.TLSErrors += r.TLSErrors
		ds.AvgDNSMs += r.DNSResolveMs
		ds.AvgDownloadKbps += r.DownloadSpeedKbps
		ds.AvgUploadKbps += r.UploadSpeedKbps
		ds.NetworkTypes[r.NetworkType]++
		ds.States[r.ConnectionState]++
	}

	// Compute averages.
	for _, ds := range devices {
		if ds.ReportCount > 0 {
			ds.AvgPingMs /= float64(ds.ReportCount)
			ds.AvgLossPercent /= float64(ds.ReportCount)
			ds.AvgThroughIn /= float64(ds.ReportCount)
			ds.AvgThroughOut /= float64(ds.ReportCount)
			ds.AvgDNSMs /= float64(ds.ReportCount)
			// Speed tests run less frequently; average only non-zero values.
			downloadCount := 0.0
			uploadCount := 0.0
			for _, r := range reports {
				if r.DeviceID == "" {
					continue
				}
				if r.DownloadSpeedKbps > 0 {
					downloadCount++
				}
				if r.UploadSpeedKbps > 0 {
					uploadCount++
				}
			}
			if downloadCount > 0 {
				ds.AvgDownloadKbps /= downloadCount
			}
			if uploadCount > 0 {
				ds.AvgUploadKbps /= uploadCount
			}
		}
	}

	prompt := "You are a VPN network diagnostics expert. Analyze the following telemetry data from CavadVPN clients and identify causes of slow connections or connectivity issues.\n\n"
	prompt += "## VPN Architecture\n"
	prompt += "Protocol: Noise_XX handshake + ChaCha20-Poly1305 encryption over TLS-obfuscated TCP.\n"
	prompt += "Transport: TCP with TLS 1.3 obfuscation wrapper (anti-DPI). Mux multiplexing over single connection.\n"
	prompt += "Server location: Russia (may be subject to DPI/throttling by ISP or РКН).\n\n"

	prompt += fmt.Sprintf("## Telemetry Summary (%d reports from %d devices, last hour)\n\n", len(reports), len(devices))

	for id, ds := range devices {
		shortID := id
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		prompt += fmt.Sprintf("### Device %s (%s) — %d reports\n", shortID, ds.Platform, ds.ReportCount)
		prompt += fmt.Sprintf("- Avg ping: %.1f ms, Max ping: %.1f ms\n", ds.AvgPingMs, ds.MaxPingMs)
		prompt += fmt.Sprintf("- Avg packet loss: %.2f%%, Max: %.2f%%\n", ds.AvgLossPercent, ds.MaxLossPercent)
		prompt += fmt.Sprintf("- Avg throughput: ↓%.1f kbps, ↑%.1f kbps\n", ds.AvgThroughIn, ds.AvgThroughOut)
		prompt += fmt.Sprintf("- Reconnects: %d, DPI detections: %d, TLS errors: %d\n", ds.Reconnects, ds.DPIDetected, ds.TLSErrors)
		prompt += fmt.Sprintf("- Avg DNS resolve: %.1f ms\n", ds.AvgDNSMs)
		if ds.AvgDownloadKbps > 0 || ds.AvgUploadKbps > 0 {
			prompt += fmt.Sprintf("- Speed test: ↓%.0f kbps, ↑%.0f kbps\n", ds.AvgDownloadKbps, ds.AvgUploadKbps)
		}
		prompt += fmt.Sprintf("- Network types: %v\n", ds.NetworkTypes)
		prompt += fmt.Sprintf("- Connection states: %v\n\n", ds.States)
	}

	// Server-side performance data.
	if serverPerf != nil {
		prompt += "## Server Per-Layer Latency (P95, microseconds)\n\n"
		prompt += fmt.Sprintf("- TLS obfuscation write: %.0f µs, read: %.0f µs\n", serverPerf.ObfsWriteP95Us, serverPerf.ObfsReadP95Us)
		prompt += fmt.Sprintf("- Noise encrypt: %.0f µs, decrypt: %.0f µs\n", serverPerf.NoiseEncryptP95Us, serverPerf.NoiseDecryptP95Us)
		prompt += fmt.Sprintf("- Mux write: %.0f µs, read: %.0f µs\n", serverPerf.MuxWriteP95Us, serverPerf.MuxReadP95Us)
		prompt += fmt.Sprintf("- TUN write: %.0f µs, read: %.0f µs\n", serverPerf.TunWriteP95Us, serverPerf.TunReadP95Us)
		prompt += fmt.Sprintf("- Full ingress (socket→TUN): %.0f µs, egress (TUN→socket): %.0f µs\n", serverPerf.FullIngressP95Us, serverPerf.FullEgressP95Us)
		prompt += fmt.Sprintf("- Handshake mean: %.0f µs\n", serverPerf.HandshakeMeanUs)
		prompt += fmt.Sprintf("- TCP retransmits: %d, lost segments: %d, cwnd: %d segs\n", serverPerf.RetransmitCount, serverPerf.TCPLostSegs, serverPerf.TCPCwndSegs)
		if serverPerf.TCPRTTUs > 0 {
			prompt += fmt.Sprintf("- TCP RTT: %d µs (%.1f ms)\n", serverPerf.TCPRTTUs, float64(serverPerf.TCPRTTUs)/1000)
		}
		prompt += "\n"
	}

	// Server resource usage.
	if serverMetrics != nil {
		prompt += "## Server Resources\n\n"
		prompt += fmt.Sprintf("- CPU: %.1f%%\n", serverMetrics.CPUPercent)
		prompt += fmt.Sprintf("- Memory (RSS): %.1f MB, Heap: %.1f MB\n", serverMetrics.MemoryMB, serverMetrics.HeapAllocMB)
		prompt += fmt.Sprintf("- Goroutines: %d\n", serverMetrics.NumGoroutines)
		prompt += fmt.Sprintf("- GC pauses: %.0f µs, total cycles: %d\n", serverMetrics.GCPauseUs, serverMetrics.NumGC)
		prompt += fmt.Sprintf("- Uptime: %.0f sec\n\n", serverMetrics.UptimeSec)
	}

	prompt += `## Instructions
Analyze the data above and identify the bottleneck causing slow VPN speed.
Consider: DPI throttling, server CPU/memory, encryption overhead, obfuscation latency, TCP retransmits, packet loss, network jitter, congestion window.
Respond with EXACTLY this JSON structure (no markdown, no extra text):
{
  "summary": "One paragraph overview of the network health and bottleneck location",
  "issues": [
    {
      "severity": "critical|warning|info",
      "category": "latency|packet_loss|throughput|dpi|connection|obfuscation|server_resources|tcp",
      "description": "Description of the issue with specific numbers",
      "affected_devices": ["device_id_prefix"]
    }
  ],
  "recommendations": ["Specific action item 1", "Specific action item 2"]
}
`
	return prompt
}

// parseAnalysisResponse tries to parse the AI response as structured JSON.
func parseAnalysisResponse(text string, reportCount int) *AnalysisResult {
	result := &AnalysisResult{
		Timestamp:   time.Now(),
		ReportCount: reportCount,
	}

	// Try direct JSON parse.
	var parsed struct {
		Summary         string            `json:"summary"`
		Issues          []DiagnosticIssue `json:"issues"`
		Recommendations []string          `json:"recommendations"`
	}

	if err := json.Unmarshal([]byte(text), &parsed); err == nil {
		result.Summary = parsed.Summary
		result.Issues = parsed.Issues
		result.Recommendations = parsed.Recommendations
		// Count unique devices.
		deviceSet := make(map[string]struct{})
		for _, issue := range parsed.Issues {
			for _, d := range issue.AffectedDevices {
				deviceSet[d] = struct{}{}
			}
		}
		result.DeviceCount = len(deviceSet)
		return result
	}

	// If JSON parse fails, use raw text as summary.
	result.Summary = text
	return result
}

// ---------------------------------------------------------------------------
// API route registration
// ---------------------------------------------------------------------------

// SetTelemetryStore enables telemetry endpoints on the API server.
func (a *APIServer) SetTelemetryStore(ts *TelemetryStore, analyzer *TelemetryAnalyzer) {
	a.telemetryStore = ts
	a.telemetryAnalyzer = analyzer

	// Submit telemetry — no auth required (clients use device_id).
	a.mux.HandleFunc("POST /api/v1/telemetry", a.handleSubmitTelemetry)
	// List reports — auth required.
	a.mux.HandleFunc("GET /api/v1/telemetry", a.auth(a.handleListTelemetry))
	// Get latest analysis — auth required.
	a.mux.HandleFunc("GET /api/v1/telemetry/analysis", a.auth(a.handleGetAnalysis))
	// Trigger immediate analysis — auth required.
	a.mux.HandleFunc("POST /api/v1/telemetry/analyze", a.auth(a.handleTriggerAnalysis))
}

// handleSubmitTelemetry receives a telemetry report from a client.
func (a *APIServer) handleSubmitTelemetry(w http.ResponseWriter, r *http.Request) {
	if a.telemetryStore == nil {
		writeError(w, http.StatusServiceUnavailable, "telemetry not enabled")
		return
	}

	var report TelemetryReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if report.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "device_id required")
		return
	}
	if report.Platform == "" {
		writeError(w, http.StatusBadRequest, "platform required")
		return
	}

	// Set public IP from request.
	report.PublicIP = remoteIP(r)

	a.telemetryStore.Add(report)
	a.logger.Debug("telemetry received", "device", report.DeviceID, "platform", report.Platform)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleListTelemetry returns recent telemetry reports.
func (a *APIServer) handleListTelemetry(w http.ResponseWriter, r *http.Request) {
	if a.telemetryStore == nil {
		writeJSON(w, http.StatusOK, []TelemetryReport{})
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := fmt.Sscanf(l, "%d", &limit); n == 1 && err == nil {
			if limit < 1 {
				limit = 1
			}
			if limit > 1000 {
				limit = 1000
			}
		}
	}

	reports := a.telemetryStore.Recent(limit)
	if reports == nil {
		reports = []TelemetryReport{}
	}
	writeJSON(w, http.StatusOK, reports)
}

// handleGetAnalysis returns the latest AI analysis.
func (a *APIServer) handleGetAnalysis(w http.ResponseWriter, _ *http.Request) {
	if a.telemetryStore == nil {
		writeError(w, http.StatusServiceUnavailable, "telemetry not enabled")
		return
	}
	analysis := a.telemetryStore.LastAnalysis()
	if analysis == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no analysis yet"})
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

// handleTriggerAnalysis triggers an immediate analysis.
func (a *APIServer) handleTriggerAnalysis(w http.ResponseWriter, r *http.Request) {
	if a.telemetryAnalyzer == nil {
		writeError(w, http.StatusServiceUnavailable, "analyzer not configured")
		return
	}
	result := a.telemetryAnalyzer.RunOnce(r.Context())
	writeJSON(w, http.StatusOK, result)
}

// remoteIP extracts the client IP from the request.
func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
