package api

import (
	"net/http"

	"github.com/cavad93/vpn/server/perf"
)

// SetPerfCollector attaches the performance metrics collector to the API
// server and registers the /api/v1/perf endpoints.
func (a *APIServer) SetPerfCollector(pc *perf.Collector) {
	if pc == nil {
		return
	}
	a.perfCollector = pc
	a.mux.HandleFunc("GET /api/v1/perf", a.auth(a.handlePerf))
	a.mux.HandleFunc("POST /api/v1/perf/reset", a.auth(a.handlePerfReset))
}

// handlePerf returns a full performance metrics snapshot.
func (a *APIServer) handlePerf(w http.ResponseWriter, _ *http.Request) {
	if a.perfCollector == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no collector"})
		return
	}
	writeJSON(w, http.StatusOK, a.perfCollector.Snapshot())
}

// handlePerfReset zeroes all performance counters and histograms.
func (a *APIServer) handlePerfReset(w http.ResponseWriter, _ *http.Request) {
	if a.perfCollector == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no collector"})
		return
	}
	a.perfCollector.Reset()
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}
