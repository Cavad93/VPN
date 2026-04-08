// relay_metrics.go — per-segment throughput instrumentation for relay mode.
//
// When the server runs as a transparent relay (-relay-to), this module tracks
// byte and packet counts in each direction so that the AI diagnostics tool can
// pinpoint WHICH network segment is the bottleneck:
//
//	MacBook ──(segment A)──► SPb relay ──(segment B)──► Astana VPN server
//
// Counters:
//
//	clientRxBytes   = bytes received on segment A (MacBook → SPb)
//	upstreamTxBytes = bytes forwarded on segment A→B (SPb → Astana)
//	upstreamRxBytes = bytes received on segment B (Astana → SPb)
//	clientTxBytes   = bytes delivered on B→A (SPb → MacBook)
//
// In a lossless relay: clientRxBytes ≈ upstreamTxBytes (what comes in goes out).
// If clientRxBytes >> upstreamTxBytes then the relay is dropping/queueing.
// If upstreamRxBps > clientTxBps then SPb upload is the bottleneck.
//
// The HTTP endpoint /relay-metrics on the metrics address (default :9092)
// returns a JSON snapshot that vpn_diagnostics.py fetches for AI analysis.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// relayMetrics holds per-direction byte/drop counters for one relay process.
// All total fields use atomic operations (hot path, called from UDP I/O goroutines).
// Rate fields are updated once per second by samplerLoop (mutex-protected).
type relayMetrics struct {
	// Segment A: MacBook ↔ SPb relay.
	clientRxBytes atomic.Int64 // bytes received FROM VPN clients
	clientTxBytes atomic.Int64 // bytes sent TO VPN clients

	// Segment B: SPb relay ↔ Astana VPN server.
	upstreamTxBytes atomic.Int64 // bytes forwarded TO upstream server
	upstreamRxBytes atomic.Int64 // bytes received FROM upstream server

	// Drop counters (send queue full → packet silently dropped).
	clientDrops   atomic.Int64 // dropped on client→upstream path
	upstreamDrops atomic.Int64 // dropped on upstream→client path

	// Active session count (gauge).
	activeSessions atomic.Int64

	// Per-second rate estimates — updated by samplerLoop every 1s.
	ratesMu        sync.Mutex
	clientRxBps    float64
	clientTxBps    float64
	upstreamTxBps  float64
	upstreamRxBps  float64

	startTime time.Time
}

// globalRelayMetrics is the process-wide singleton used by runUDPRelay / runRelay.
var globalRelayMetrics = &relayMetrics{
	startTime: time.Now(),
}

// samplerLoop runs in a background goroutine and computes per-second byte rates.
// It samples deltas every 1 second so the rates are instantaneous (1-s window).
func (m *relayMetrics) samplerLoop() {
	var (
		prevClientRx  int64
		prevClientTx  int64
		prevUpstreamTx int64
		prevUpstreamRx int64
	)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		curClientRx  := m.clientRxBytes.Load()
		curClientTx  := m.clientTxBytes.Load()
		curUpstreamTx := m.upstreamTxBytes.Load()
		curUpstreamRx := m.upstreamRxBytes.Load()

		m.ratesMu.Lock()
		m.clientRxBps   = float64(curClientRx  - prevClientRx)
		m.clientTxBps   = float64(curClientTx  - prevClientTx)
		m.upstreamTxBps  = float64(curUpstreamTx - prevUpstreamTx)
		m.upstreamRxBps  = float64(curUpstreamRx - prevUpstreamRx)
		m.ratesMu.Unlock()

		prevClientRx   = curClientRx
		prevClientTx   = curClientTx
		prevUpstreamTx = curUpstreamTx
		prevUpstreamRx = curUpstreamRx
	}
}

// RelayMetricsSnapshot is a JSON-serialisable point-in-time snapshot of relay metrics.
// vpn_diagnostics.py fetches this from /relay-metrics and feeds it to Claude.
type RelayMetricsSnapshot struct {
	// ── Cumulative totals since process start ───────────────────────────────────
	ClientRxBytes   int64 `json:"client_rx_bytes"`   // MacBook → SPb (segment A)
	ClientTxBytes   int64 `json:"client_tx_bytes"`   // SPb → MacBook (segment A, reverse)
	UpstreamTxBytes int64 `json:"upstream_tx_bytes"` // SPb → Astana  (segment B)
	UpstreamRxBytes int64 `json:"upstream_rx_bytes"` // Astana → SPb  (segment B, reverse)

	// ── Drop counters ───────────────────────────────────────────────────────────
	ClientDrops   int64 `json:"client_drops"`   // client→upstream queue-full drops
	UpstreamDrops int64 `json:"upstream_drops"` // upstream→client queue-full drops

	// ── Active sessions ─────────────────────────────────────────────────────────
	ActiveSessions int64 `json:"active_sessions"`

	// ── Per-second rates (1-second sliding window) ──────────────────────────────
	ClientRxBps    float64 `json:"client_rx_bps"`    // bytes/s: MacBook → SPb
	ClientTxBps    float64 `json:"client_tx_bps"`    // bytes/s: SPb → MacBook
	UpstreamTxBps  float64 `json:"upstream_tx_bps"`  // bytes/s: SPb → Astana
	UpstreamRxBps  float64 `json:"upstream_rx_bps"`  // bytes/s: Astana → SPb

	// ── Mbit/s convenience fields (computed from bps) ────────────────────────────
	ClientRxMbps   float64 `json:"client_rx_mbps"`
	ClientTxMbps   float64 `json:"client_tx_mbps"`
	UpstreamTxMbps float64 `json:"upstream_tx_mbps"`
	UpstreamRxMbps float64 `json:"upstream_rx_mbps"`

	// ── Derived ratios for bottleneck identification ─────────────────────────────
	// ForwardEfficiency: fraction of bytes received from client that reach upstream.
	// < 0.95 means the relay is dropping/queuing on segment A→B.
	// Computed only when ClientRxBytes > 0.
	ForwardEfficiency float64 `json:"forward_efficiency,omitempty"` // upstreamTx/clientRx

	// DownlinkEfficiency: fraction of bytes from upstream that reach the client.
	// < 0.95 means SPb upload bandwidth is the bottleneck on segment B→A.
	DownlinkEfficiency float64 `json:"downlink_efficiency,omitempty"` // clientTx/upstreamRx

	// ── Meta ─────────────────────────────────────────────────────────────────────
	UptimeSec float64 `json:"uptime_sec"`
	SampledAt string  `json:"sampled_at"`
}

// snapshot returns a current RelayMetricsSnapshot.
func (m *relayMetrics) snapshot() RelayMetricsSnapshot {
	m.ratesMu.Lock()
	rxBps   := m.clientRxBps
	txBps   := m.clientTxBps
	upTxBps := m.upstreamTxBps
	upRxBps := m.upstreamRxBps
	m.ratesMu.Unlock()

	clientRx   := m.clientRxBytes.Load()
	clientTx   := m.clientTxBytes.Load()
	upstreamTx := m.upstreamTxBytes.Load()
	upstreamRx := m.upstreamRxBytes.Load()

	snap := RelayMetricsSnapshot{
		ClientRxBytes:   clientRx,
		ClientTxBytes:   clientTx,
		UpstreamTxBytes: upstreamTx,
		UpstreamRxBytes: upstreamRx,
		ClientDrops:     m.clientDrops.Load(),
		UpstreamDrops:   m.upstreamDrops.Load(),
		ActiveSessions:  m.activeSessions.Load(),
		ClientRxBps:     rxBps,
		ClientTxBps:     txBps,
		UpstreamTxBps:   upTxBps,
		UpstreamRxBps:   upRxBps,
		ClientRxMbps:    rxBps * 8 / 1_000_000,
		ClientTxMbps:    txBps * 8 / 1_000_000,
		UpstreamTxMbps:  upTxBps * 8 / 1_000_000,
		UpstreamRxMbps:  upRxBps * 8 / 1_000_000,
		UptimeSec:       time.Since(m.startTime).Seconds(),
		SampledAt:       time.Now().UTC().Format(time.RFC3339),
	}
	// Compute efficiency ratios on cumulative totals (more stable than instantaneous rates).
	if clientRx > 0 {
		snap.ForwardEfficiency = float64(upstreamTx) / float64(clientRx)
	}
	if upstreamRx > 0 {
		snap.DownlinkEfficiency = float64(clientTx) / float64(upstreamRx)
	}
	return snap
}

// relayMetricsHandler serves GET /relay-metrics as a JSON snapshot.
func relayMetricsHandler(w http.ResponseWriter, _ *http.Request) {
	snap := globalRelayMetrics.snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap) //nolint:errcheck
}

// startRelayMetricsServer starts a lightweight HTTP server that exposes:
//
//	GET /relay-metrics  — JSON snapshot of per-segment throughput
//	GET /health         — simple liveness check
//
// It also starts the background samplerLoop goroutine.
// addr should be e.g. ":9092".  This function blocks; run it in a goroutine.
func startRelayMetricsServer(addr string, logger *slog.Logger) {
	go globalRelayMetrics.samplerLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/relay-metrics", relayMetricsHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","role":"relay"}`)) //nolint:errcheck
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	logger.Info("relay metrics server listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Warn("relay metrics server stopped", "err", err)
	}
}
