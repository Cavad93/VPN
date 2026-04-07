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
	"os"
	"sync"
	"sync/atomic"
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

	// Transport & bypass info (new fields for AI bypass/speed analysis)
	SNIHost           string `json:"sni_host,omitempty"`           // SNI cover domain used in this session
	TransportMode     string `json:"transport_mode,omitempty"`     // "udp" or "tcp"
	BondCount         int    `json:"bond_count,omitempty"`         // TCP parallel bonds (0 = N/A)
	PaddingMode       string `json:"padding_mode,omitempty"`       // "none", "light", "balanced", "paranoid"
	HandshakeAttempts int    `json:"handshake_attempts,omitempty"` // attempts before successful connect (>1 = DPI reset)
	ISPName           string `json:"isp_name,omitempty"`           // detected ISP / carrier for DPI correlation
}

// AnalysisResult is the output of AI-powered telemetry analysis.
type AnalysisResult struct {
	Timestamp    time.Time          `json:"timestamp"`
	ReportCount  int                `json:"report_count"`   // how many reports were analyzed
	DeviceCount  int                `json:"device_count"`   // unique devices
	Summary      string             `json:"summary"`        // human-readable summary
	Issues       []DiagnosticIssue  `json:"issues"`         // detected problems
	Recommendations []string        `json:"recommendations"` // backward-compat general actions

	// Focused AI analysis results
	BypassRecommendations []BypassRecommendation `json:"bypass_recommendations,omitempty"`
	SpeedRecommendations  []SpeedRecommendation  `json:"speed_recommendations,omitempty"`
	ActionableConfig      *ActionableConfig      `json:"actionable_config,omitempty"` // auto-applicable settings

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

// BypassRecommendation is a single actionable DPI-bypass recommendation.
type BypassRecommendation struct {
	Priority    int                    `json:"priority"`              // 1=urgent, 2=recommended, 3=optional
	Action      string                 `json:"action"`                // "rotate_sni", "enable_padding", "switch_transport", "add_relay", "increase_jitter"
	Description string                 `json:"description"`           // human-readable explanation
	Config      map[string]interface{} `json:"config,omitempty"`      // action-specific parameters
}

// SpeedRecommendation is a single actionable speed optimization.
type SpeedRecommendation struct {
	Priority     int                    `json:"priority"`
	ExpectedGain string                 `json:"expected_gain"`         // e.g. "20-40% throughput increase"
	Action       string                 `json:"action"`                // "switch_to_udp", "increase_bonds", "reduce_mtu", "switch_to_tcp"
	Description  string                 `json:"description"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

// ActionableConfig is a machine-readable config the client can auto-apply without manual intervention.
type ActionableConfig struct {
	TransportMode  string   `json:"transport_mode,omitempty"` // "udp" or "tcp"
	BondCount      int      `json:"bond_count,omitempty"`     // TCP parallel bonds (0 = default)
	MTU            int      `json:"mtu,omitempty"`            // packet MTU (0 = default)
	SNIHosts       []string `json:"sni_hosts,omitempty"`      // SNI cover domains to rotate through
	PaddingEnabled bool     `json:"padding_enabled"`          // enable traffic padding
	PaddingMode    string   `json:"padding_mode,omitempty"`   // "light", "balanced", "paranoid"
	JitterMs       int      `json:"jitter_ms,omitempty"`      // inter-packet timing jitter in ms (0 = off)
	RelayAddr      string   `json:"relay_addr,omitempty"`     // suggest relay hop if direct path is blocked
}

// ---------------------------------------------------------------------------
// AI decision log — history of config changes made by the analyzer
// ---------------------------------------------------------------------------

// ConfigChange describes one parameter that AI changed.
type ConfigChange struct {
	Field    string `json:"field"`
	OldValue any    `json:"old_value"`
	NewValue any    `json:"new_value"`
	Reason   string `json:"reason,omitempty"`
}

// ConfigDecision is one entry in the AI decision history.
type ConfigDecision struct {
	Timestamp   time.Time      `json:"timestamp"`
	Changes     []ConfigChange `json:"changes"`      // what changed; empty if NoChange
	Summary     string         `json:"summary"`      // AI one-liner
	ReportCount int            `json:"report_count"` // how many reports were analyzed
	NoChange    bool           `json:"no_change"`    // true when AI kept current config
}

// AppliedConfig is the currently-active configuration that AI chose.
type AppliedConfig struct {
	Config    ActionableConfig `json:"config"`
	AppliedAt time.Time        `json:"applied_at"`
	Reason    string           `json:"reason"` // short summary of why this config was chosen
}

// OverrideConfig holds user-pinned values that AI must not change.
// Any field listed in PinnedFields takes its value from Values map
// and overrides whatever the AI recommends.
type OverrideConfig struct {
	PinnedFields []string               `json:"pinned_fields"` // e.g. ["bond_count","transport_mode"]
	Values       map[string]interface{} `json:"values"`        // pinned values keyed by field name
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
	enabled  atomic.Bool // toggleable at runtime; true by default

	// Optional: callbacks to get server-side data for enriching analysis.
	GetServerPerf    func() *ServerPerfSummary
	GetServerMetrics func() *ServerMetrics

	// AI decision log — last 50 decisions in a ring buffer.
	decMu      sync.RWMutex
	decisions  [50]ConfigDecision
	decPos     int
	decFull    bool

	// Currently applied config chosen by AI.
	cfgMu      sync.RWMutex
	appliedCfg AppliedConfig

	// User-pinned overrides — AI cannot change pinned fields.
	overrideMu sync.RWMutex
	override   OverrideConfig
}

// NewTelemetryAnalyzer creates an analyzer that runs every interval.
func NewTelemetryAnalyzer(store *TelemetryStore, fn AnalyzerFunc, apiKey string, interval time.Duration) *TelemetryAnalyzer {
	a := &TelemetryAnalyzer{
		store:    store,
		analyze:  fn,
		apiKey:   apiKey,
		interval: interval,
	}
	a.enabled.Store(true)
	return a
}

// SetEnabled enables or disables the periodic AI analysis.
func (ta *TelemetryAnalyzer) SetEnabled(v bool) { ta.enabled.Store(v) }

// IsEnabled reports whether AI analysis is currently enabled.
func (ta *TelemetryAnalyzer) IsEnabled() bool { return ta.enabled.Load() }

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
	if !ta.enabled.Load() {
		return nil // AI выключен пользователем
	}
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
		ta.recordDecision(ConfigDecision{
			Timestamp:   result.Timestamp,
			NoChange:    true,
			Summary:     result.Summary,
			ReportCount: 0,
		})
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

	// Auto-apply the config recommended by AI.
	ta.applyConfig(result)

	return result
}

// SetOverride replaces the current override config.
func (ta *TelemetryAnalyzer) SetOverride(ov OverrideConfig) {
	ta.overrideMu.Lock()
	defer ta.overrideMu.Unlock()
	ta.override = ov
}

// GetOverride returns the current override config.
func (ta *TelemetryAnalyzer) GetOverride() OverrideConfig {
	ta.overrideMu.RLock()
	defer ta.overrideMu.RUnlock()
	return ta.override
}

// applyOverride merges pinned values into cfg, marking overridden fields.
// Returns the merged config and a list of fields that were overridden.
func (ta *TelemetryAnalyzer) applyOverride(cfg ActionableConfig) (ActionableConfig, []string) {
	ta.overrideMu.RLock()
	ov := ta.override
	ta.overrideMu.RUnlock()

	pinned := make(map[string]bool, len(ov.PinnedFields))
	for _, f := range ov.PinnedFields {
		pinned[f] = true
	}
	overridden := []string{}

	if pinned["transport_mode"] {
		if v, ok := ov.Values["transport_mode"].(string); ok && v != "" {
			cfg.TransportMode = v
			overridden = append(overridden, "transport_mode")
		}
	}
	if pinned["bond_count"] {
		if v, ok := ov.Values["bond_count"].(float64); ok {
			cfg.BondCount = int(v)
			overridden = append(overridden, "bond_count")
		}
	}
	if pinned["mtu"] {
		if v, ok := ov.Values["mtu"].(float64); ok {
			cfg.MTU = int(v)
			overridden = append(overridden, "mtu")
		}
	}
	if pinned["padding_mode"] {
		if v, ok := ov.Values["padding_mode"].(string); ok && v != "" {
			cfg.PaddingMode = v
			overridden = append(overridden, "padding_mode")
		}
	}
	if pinned["padding_enabled"] {
		if v, ok := ov.Values["padding_enabled"].(bool); ok {
			cfg.PaddingEnabled = v
			overridden = append(overridden, "padding_enabled")
		}
	}
	if pinned["jitter_ms"] {
		if v, ok := ov.Values["jitter_ms"].(float64); ok {
			cfg.JitterMs = int(v)
			overridden = append(overridden, "jitter_ms")
		}
	}
	return cfg, overridden
}

// applyConfig compares the new ActionableConfig with the current one,
// records what changed in the decision log, and stores the new config.
func (ta *TelemetryAnalyzer) applyConfig(result *AnalysisResult) {
	if result == nil || result.ActionableConfig == nil {
		return
	}
	// Apply user overrides before diff — pinned fields always win.
	newCfg, overridden := ta.applyOverride(*result.ActionableConfig)

	ta.cfgMu.Lock()
	old := ta.appliedCfg.Config
	changes := diffConfig(old, newCfg)
	ta.appliedCfg = AppliedConfig{
		Config:    newCfg,
		AppliedAt: result.Timestamp,
		Reason:    result.Summary,
	}
	ta.cfgMu.Unlock()

	// Mark overridden fields in the change log so UI can show lock icon.
	for i := range changes {
		for _, f := range overridden {
			if changes[i].Field == f {
				changes[i].Reason = "pinned by user"
			}
		}
	}

	dec := ConfigDecision{
		Timestamp:   result.Timestamp,
		Changes:     changes,
		Summary:     result.Summary,
		ReportCount: result.ReportCount,
		NoChange:    len(changes) == 0,
	}
	ta.recordDecision(dec)
}

// diffConfig computes field-level differences between two ActionableConfig values.
func diffConfig(old, new ActionableConfig) []ConfigChange {
	var out []ConfigChange
	if old.TransportMode != new.TransportMode && new.TransportMode != "" {
		out = append(out, ConfigChange{Field: "transport_mode", OldValue: old.TransportMode, NewValue: new.TransportMode})
	}
	if old.BondCount != new.BondCount && new.BondCount != 0 {
		out = append(out, ConfigChange{Field: "bond_count", OldValue: old.BondCount, NewValue: new.BondCount})
	}
	if old.MTU != new.MTU && new.MTU != 0 {
		out = append(out, ConfigChange{Field: "mtu", OldValue: old.MTU, NewValue: new.MTU})
	}
	if old.PaddingMode != new.PaddingMode && new.PaddingMode != "" {
		out = append(out, ConfigChange{Field: "padding_mode", OldValue: old.PaddingMode, NewValue: new.PaddingMode})
	}
	if old.PaddingEnabled != new.PaddingEnabled {
		out = append(out, ConfigChange{Field: "padding_enabled", OldValue: old.PaddingEnabled, NewValue: new.PaddingEnabled})
	}
	if old.JitterMs != new.JitterMs {
		out = append(out, ConfigChange{Field: "jitter_ms", OldValue: old.JitterMs, NewValue: new.JitterMs})
	}
	if old.RelayAddr != new.RelayAddr && new.RelayAddr != "" {
		out = append(out, ConfigChange{Field: "relay_addr", OldValue: old.RelayAddr, NewValue: new.RelayAddr})
	}
	return out
}

// recordDecision appends a decision to the ring buffer.
func (ta *TelemetryAnalyzer) recordDecision(d ConfigDecision) {
	ta.decMu.Lock()
	defer ta.decMu.Unlock()
	ta.decisions[ta.decPos] = d
	ta.decPos++
	if ta.decPos >= 50 {
		ta.decPos = 0
		ta.decFull = true
	}
}

// Decisions returns the last n decisions in chronological order.
func (ta *TelemetryAnalyzer) Decisions(n int) []ConfigDecision {
	ta.decMu.RLock()
	defer ta.decMu.RUnlock()
	total := ta.decPos
	if ta.decFull {
		total = 50
	}
	if n <= 0 || n > total {
		n = total
	}
	if n == 0 {
		return nil
	}
	out := make([]ConfigDecision, n)
	start := ta.decPos - n
	if start < 0 {
		start += 50
	}
	for i := 0; i < n; i++ {
		out[i] = ta.decisions[(start+i)%50]
	}
	return out
}

// CurrentApplied returns the config that AI most recently applied.
func (ta *TelemetryAnalyzer) CurrentApplied() AppliedConfig {
	ta.cfgMu.RLock()
	defer ta.cfgMu.RUnlock()
	return ta.appliedCfg
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
// It produces a two-task analysis: (a) DPI bypass, (b) speed optimization.
func buildAnalysisPrompt(reports []TelemetryReport, serverPerf *ServerPerfSummary, serverMetrics *ServerMetrics) string {
	// Aggregate per-device stats.
	type deviceStats struct {
		Platform          string
		ReportCount       int
		AvgPingMs         float64
		MaxPingMs         float64
		AvgLossPercent    float64
		MaxLossPercent    float64
		AvgThroughIn      float64
		AvgThroughOut     float64
		Reconnects        int
		DPIDetected       int
		TLSErrors         int
		AvgDNSMs          float64
		AvgDownloadKbps   float64
		AvgUploadKbps     float64
		NetworkTypes      map[string]int
		States            map[string]int
		TransportModes    map[string]int
		SNIHosts          map[string]int
		PaddingModes      map[string]int
		MaxHandshakeAttempts int
		ISPs              map[string]int
	}

	devices := make(map[string]*deviceStats)
	for _, r := range reports {
		ds, ok := devices[r.DeviceID]
		if !ok {
			ds = &deviceStats{
				Platform:       r.Platform,
				NetworkTypes:   make(map[string]int),
				States:         make(map[string]int),
				TransportModes: make(map[string]int),
				SNIHosts:       make(map[string]int),
				PaddingModes:   make(map[string]int),
				ISPs:           make(map[string]int),
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
		if r.TransportMode != "" {
			ds.TransportModes[r.TransportMode]++
		}
		if r.SNIHost != "" {
			ds.SNIHosts[r.SNIHost]++
		}
		mode := r.PaddingMode
		if mode == "" {
			mode = "none"
		}
		ds.PaddingModes[mode]++
		if r.HandshakeAttempts > ds.MaxHandshakeAttempts {
			ds.MaxHandshakeAttempts = r.HandshakeAttempts
		}
		if r.ISPName != "" {
			ds.ISPs[r.ISPName]++
		}
	}

	// Compute averages.
	for _, ds := range devices {
		if ds.ReportCount > 0 {
			ds.AvgPingMs /= float64(ds.ReportCount)
			ds.AvgLossPercent /= float64(ds.ReportCount)
			ds.AvgThroughIn /= float64(ds.ReportCount)
			ds.AvgThroughOut /= float64(ds.ReportCount)
			ds.AvgDNSMs /= float64(ds.ReportCount)
			downloadCount := 0.0
			uploadCount := 0.0
			for _, r := range reports {
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

	// --- Compute bypass signals across all devices ---
	totalDPI := 0
	totalTLSErrors := 0
	totalReconnects := 0
	totalHandshakeAttempts := 0
	for _, ds := range devices {
		totalDPI += ds.DPIDetected
		totalTLSErrors += ds.TLSErrors
		totalReconnects += ds.Reconnects
		totalHandshakeAttempts += ds.MaxHandshakeAttempts
	}

	prompt := "You are an expert VPN security engineer specializing in DPI bypass and performance optimization.\n"
	prompt += "The VPN is operated in Russia and must evade Roskomnadzor (РКН) deep packet inspection.\n\n"

	prompt += "## System Architecture\n"
	prompt += "- Protocol: Noise_XX handshake + ChaCha20-Poly1305 end-to-end encryption\n"
	prompt += "- Obfuscation: TLS 1.3-like record framing (anti-DPI), SNI spoofing with cover domains\n"
	prompt += "- Transport: UDP+BBR (default) or TCP with N parallel bonds\n"
	prompt += "- Topology: Client → [optional SPb relay] → Astana VPN server\n"
	prompt += "- Active-probe protection: non-TLS probes get nginx 400 decoy response\n\n"

	prompt += fmt.Sprintf("## Telemetry Window: %d reports from %d devices\n\n", len(reports), len(devices))

	for id, ds := range devices {
		shortID := id
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		prompt += fmt.Sprintf("### Device %s (%s)\n", shortID, ds.Platform)
		prompt += fmt.Sprintf("- Avg/max ping: %.1f / %.1f ms\n", ds.AvgPingMs, ds.MaxPingMs)
		prompt += fmt.Sprintf("- Avg/max packet loss: %.2f%% / %.2f%%\n", ds.AvgLossPercent, ds.MaxLossPercent)
		prompt += fmt.Sprintf("- Avg throughput: ↓%.1f kbps ↑%.1f kbps\n", ds.AvgThroughIn, ds.AvgThroughOut)
		prompt += fmt.Sprintf("- Reconnects: %d, DPI flags: %d/%d, TLS errors: %d\n",
			ds.Reconnects, ds.DPIDetected, ds.ReportCount, ds.TLSErrors)
		if ds.MaxHandshakeAttempts > 1 {
			prompt += fmt.Sprintf("- Max handshake attempts before success: %d (>1 indicates DPI reset)\n", ds.MaxHandshakeAttempts)
		}
		prompt += fmt.Sprintf("- DNS: %.1f ms\n", ds.AvgDNSMs)
		if ds.AvgDownloadKbps > 0 {
			prompt += fmt.Sprintf("- Speed test: ↓%.0f kbps ↑%.0f kbps\n", ds.AvgDownloadKbps, ds.AvgUploadKbps)
		}
		prompt += fmt.Sprintf("- Network types: %v\n", ds.NetworkTypes)
		prompt += fmt.Sprintf("- States: %v\n", ds.States)
		if len(ds.TransportModes) > 0 {
			prompt += fmt.Sprintf("- Transports: %v\n", ds.TransportModes)
		}
		if len(ds.SNIHosts) > 0 {
			prompt += fmt.Sprintf("- SNI hosts used: %v\n", ds.SNIHosts)
		}
		if len(ds.PaddingModes) > 0 {
			prompt += fmt.Sprintf("- Padding modes: %v\n", ds.PaddingModes)
		}
		if len(ds.ISPs) > 0 {
			prompt += fmt.Sprintf("- ISPs: %v\n", ds.ISPs)
		}
		prompt += "\n"
	}

	// DPI bypass signal summary
	prompt += "## DPI / Block Signals (Aggregated)\n"
	prompt += fmt.Sprintf("- Total DPI detection flags: %d\n", totalDPI)
	prompt += fmt.Sprintf("- Total TLS errors: %d\n", totalTLSErrors)
	prompt += fmt.Sprintf("- Total reconnects: %d\n", totalReconnects)
	if totalHandshakeAttempts > len(devices) {
		prompt += fmt.Sprintf("- Elevated handshake attempts (sum): %d — indicates active connection resets\n", totalHandshakeAttempts)
	}
	prompt += "\n"

	// Server-side performance data.
	if serverPerf != nil {
		prompt += "## Server Per-Layer Latency (P95, microseconds)\n"
		prompt += fmt.Sprintf("- Obfs write/read: %.0f / %.0f µs\n", serverPerf.ObfsWriteP95Us, serverPerf.ObfsReadP95Us)
		prompt += fmt.Sprintf("- Noise encrypt/decrypt: %.0f / %.0f µs\n", serverPerf.NoiseEncryptP95Us, serverPerf.NoiseDecryptP95Us)
		prompt += fmt.Sprintf("- Mux write/read: %.0f / %.0f µs\n", serverPerf.MuxWriteP95Us, serverPerf.MuxReadP95Us)
		prompt += fmt.Sprintf("- TUN write/read: %.0f / %.0f µs\n", serverPerf.TunWriteP95Us, serverPerf.TunReadP95Us)
		prompt += fmt.Sprintf("- Full ingress/egress: %.0f / %.0f µs\n", serverPerf.FullIngressP95Us, serverPerf.FullEgressP95Us)
		prompt += fmt.Sprintf("- Handshake mean: %.0f µs\n", serverPerf.HandshakeMeanUs)
		prompt += fmt.Sprintf("- TCP retransmits: %d, cwnd: %d segs\n", serverPerf.RetransmitCount, serverPerf.TCPCwndSegs)
		if serverPerf.TCPRTTUs > 0 {
			prompt += fmt.Sprintf("- TCP RTT: %.1f ms\n", float64(serverPerf.TCPRTTUs)/1000)
		}
		prompt += "\n"
	}

	if serverMetrics != nil {
		prompt += "## Server Resources\n"
		prompt += fmt.Sprintf("- CPU: %.1f%%, Memory RSS: %.1f MB, Heap: %.1f MB\n",
			serverMetrics.CPUPercent, serverMetrics.MemoryMB, serverMetrics.HeapAllocMB)
		prompt += fmt.Sprintf("- Goroutines: %d, GC pauses: %.0f µs\n\n",
			serverMetrics.NumGoroutines, serverMetrics.GCPauseUs)
	}

	prompt += `## Your Task

Perform TWO analyses and produce ONE unified JSON response:

### Task 1 — DPI Bypass Analysis
Identify signs of ISP/РКН interference and recommend specific bypass actions.
Key signals: high reconnects (>3/hour = DPI resets), dpi_detected flags, TLS errors, handshake_attempts > 1.
Bypass action options (use exact action names):
- "rotate_sni"      → config: {"sni_hosts": ["youtube.com", "google.com", "apple.com"]}  (3–5 cover domains)
- "enable_padding"  → config: {"padding_mode": "balanced", "jitter_ms": 15}
- "switch_transport"→ config: {"transport_mode": "udp"} or {"transport_mode": "tcp", "bond_count": 64}
- "increase_jitter" → config: {"jitter_ms": 20}
- "add_relay"       → config: {"relay_addr": "suggest adding SPb relay hop"}

### Task 2 — Speed Optimization
Identify the primary throughput bottleneck and recommend the single highest-impact change.
Bottleneck hierarchy: packet_loss > server_latency > transport_mode > bond_count > MTU.
Speed action options (use exact action names):
- "switch_to_udp"    → config: {"transport_mode": "udp", "mtu": 1400}           (best for low-loss links)
- "switch_to_tcp"    → config: {"transport_mode": "tcp", "bond_count": 64}      (best for high-loss/CIS links)
- "increase_bonds"   → config: {"bond_count": 128}                               (more TCP bonds)
- "reduce_mtu"       → config: {"mtu": 1300}                                     (for fragmented links)
- "reduce_padding"   → config: {"padding_mode": "light"}                         (reduce overhead)

### actionable_config
Synthesize the TOP bypass + speed recommendations into ONE actionable_config object the client will auto-apply.
Only include fields that differ from current baseline. Do NOT include relay_addr unless direct path is clearly blocked.

Respond with EXACTLY this JSON (no markdown, no extra text):
{
  "summary": "One paragraph: overall network health, DPI risk level, and primary speed bottleneck.",
  "issues": [
    {
      "severity": "critical|warning|info",
      "category": "dpi|connection|throughput|latency|packet_loss|obfuscation|server_resources",
      "description": "Issue description with specific numbers from the data above.",
      "affected_devices": ["device_id_prefix"]
    }
  ],
  "recommendations": ["General action 1", "General action 2"],
  "bypass_recommendations": [
    {
      "priority": 1,
      "action": "rotate_sni",
      "description": "Why this helps bypass DPI in this specific case.",
      "config": {"sni_hosts": ["youtube.com", "google.com"]}
    }
  ],
  "speed_recommendations": [
    {
      "priority": 1,
      "expected_gain": "30-50% throughput increase",
      "action": "switch_to_udp",
      "description": "Why this improves speed based on the observed metrics.",
      "config": {"transport_mode": "udp", "mtu": 1400}
    }
  ],
  "actionable_config": {
    "transport_mode": "udp",
    "bond_count": 0,
    "mtu": 1400,
    "sni_hosts": ["youtube.com", "google.com"],
    "padding_enabled": true,
    "padding_mode": "balanced",
    "jitter_ms": 10
  }
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
		Summary               string                `json:"summary"`
		Issues                []DiagnosticIssue     `json:"issues"`
		Recommendations       []string              `json:"recommendations"`
		BypassRecommendations []BypassRecommendation `json:"bypass_recommendations"`
		SpeedRecommendations  []SpeedRecommendation  `json:"speed_recommendations"`
		ActionableConfig      *ActionableConfig      `json:"actionable_config"`
	}

	if err := json.Unmarshal([]byte(text), &parsed); err == nil {
		result.Summary = parsed.Summary
		result.Issues = parsed.Issues
		result.Recommendations = parsed.Recommendations
		result.BypassRecommendations = parsed.BypassRecommendations
		result.SpeedRecommendations = parsed.SpeedRecommendations
		result.ActionableConfig = parsed.ActionableConfig
		// Count unique devices from issues.
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

// SetDiagnosticsFile enables appending every received report to a JSONL file.
// Each line is a JSON-encoded TelemetryReport. File is created if it doesn't exist.
func (a *APIServer) SetDiagnosticsFile(path string) {
	a.diagnosticsFile = path
}

// appendDiagnostics appends one report as a JSON line to the diagnostics file.
func (a *APIServer) appendDiagnostics(r TelemetryReport) {
	line, err := json.Marshal(r)
	if err != nil {
		return
	}
	line = append(line, '\n')
	f, err := os.OpenFile(a.diagnosticsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		a.logger.Warn("diagnostics write failed", "err", err)
		return
	}
	defer f.Close()
	f.Write(line) //nolint:errcheck
}

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
	// Get actionable config from latest analysis — no auth (clients poll this every 5 min).
	a.mux.HandleFunc("GET /api/v1/telemetry/config", a.handleGetTelemetryConfig)
	// Get currently applied config (what AI chose) — no auth.
	a.mux.HandleFunc("GET /api/v1/telemetry/config/applied", a.handleGetAppliedConfig)
	// AI decision history — auth required.
	a.mux.HandleFunc("GET /api/v1/telemetry/decisions", a.auth(a.handleGetDecisions))
	// User overrides — get/set pinned fields — auth required.
	a.mux.HandleFunc("GET /api/v1/telemetry/config/override", a.auth(a.handleGetOverride))
	a.mux.HandleFunc("POST /api/v1/telemetry/config/override", a.auth(a.handleSetOverride))
	// AI enable/disable toggle — auth required.
	a.mux.HandleFunc("GET /api/v1/telemetry/ai", a.auth(a.handleGetAIStatus))
	a.mux.HandleFunc("POST /api/v1/telemetry/ai", a.auth(a.handleSetAIStatus))
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

	// Persist to diagnostics file if configured.
	if a.diagnosticsFile != "" {
		go a.appendDiagnostics(report)
	}

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

// handleGetAIStatus returns whether AI analysis is currently enabled.
func (a *APIServer) handleGetAIStatus(w http.ResponseWriter, _ *http.Request) {
	if a.telemetryAnalyzer == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false, "reason": "no anthropic key configured"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": a.telemetryAnalyzer.IsEnabled()})
}

// handleSetAIStatus enables or disables AI analysis at runtime.
func (a *APIServer) handleSetAIStatus(w http.ResponseWriter, r *http.Request) {
	if a.telemetryAnalyzer == nil {
		writeError(w, http.StatusServiceUnavailable, "no anthropic key configured")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	a.telemetryAnalyzer.SetEnabled(body.Enabled)
	a.logger.Info("AI analysis toggled", "enabled", body.Enabled)
	writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": body.Enabled})
}

// handleGetTelemetryConfig returns only the ActionableConfig from the latest analysis.
// Clients poll this endpoint every 5 minutes to auto-apply bypass/speed improvements.
// No authentication required — the config contains no secrets.
func (a *APIServer) handleGetTelemetryConfig(w http.ResponseWriter, _ *http.Request) {
	if a.telemetryStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{})
		return
	}
	analysis := a.telemetryStore.LastAnalysis()
	if analysis == nil || analysis.ActionableConfig == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{})
		return
	}
	writeJSON(w, http.StatusOK, analysis.ActionableConfig)
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

// handleGetOverride returns the current user-pinned override config.
func (a *APIServer) handleGetOverride(w http.ResponseWriter, _ *http.Request) {
	if a.telemetryAnalyzer == nil {
		writeJSON(w, http.StatusOK, OverrideConfig{PinnedFields: []string{}, Values: map[string]interface{}{}})
		return
	}
	writeJSON(w, http.StatusOK, a.telemetryAnalyzer.GetOverride())
}

// handleSetOverride replaces the user-pinned override config.
// Body: {"pinned_fields":["bond_count"],"values":{"bond_count":64}}
func (a *APIServer) handleSetOverride(w http.ResponseWriter, r *http.Request) {
	if a.telemetryAnalyzer == nil {
		writeError(w, http.StatusServiceUnavailable, "analyzer not configured")
		return
	}
	var ov OverrideConfig
	if err := json.NewDecoder(r.Body).Decode(&ov); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if ov.Values == nil {
		ov.Values = map[string]interface{}{}
	}
	a.telemetryAnalyzer.SetOverride(ov)
	writeJSON(w, http.StatusOK, ov)
}

// handleGetAppliedConfig returns the config that AI most recently applied.
// Clients poll this to know what settings are currently active.
func (a *APIServer) handleGetAppliedConfig(w http.ResponseWriter, _ *http.Request) {
	if a.telemetryAnalyzer == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{})
		return
	}
	writeJSON(w, http.StatusOK, a.telemetryAnalyzer.CurrentApplied())
}

// handleGetDecisions returns the AI decision history (last N decisions).
func (a *APIServer) handleGetDecisions(w http.ResponseWriter, r *http.Request) {
	if a.telemetryAnalyzer == nil {
		writeJSON(w, http.StatusOK, []ConfigDecision{})
		return
	}
	n := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &n)
		if n < 1 {
			n = 1
		} else if n > 50 {
			n = 50
		}
	}
	decisions := a.telemetryAnalyzer.Decisions(n)
	if decisions == nil {
		decisions = []ConfigDecision{}
	}
	writeJSON(w, http.StatusOK, decisions)
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
