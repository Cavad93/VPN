package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavad93/vpn/server/perf"
)

func TestCollectServerMetrics(t *testing.T) {
	m := CollectServerMetrics()
	if m.NumGoroutines <= 0 {
		t.Error("expected positive goroutine count")
	}
	if m.UptimeSec <= 0 {
		t.Error("expected positive uptime")
	}
	if m.HeapAllocMB <= 0 {
		t.Error("expected positive heap alloc")
	}
}

func TestSummarizePerf(t *testing.T) {
	c := perf.NewCollector()
	c.TrackLatency(perf.StageNoiseEnc, 100_000) // 100µs
	c.TrackLatency(perf.StageObfsWrite, 50_000)
	snap := c.Snapshot()
	summary := SummarizePerf(snap)
	if summary.NoiseEncryptP95Us <= 0 {
		t.Error("expected non-zero noise encrypt P95")
	}
}

func TestHandleServerMetrics(t *testing.T) {
	a := NewAPIServer(Config{APIToken: "tok"}, &mockServer{}, testLogger())
	// registerDiagnosticsRoutes is called by registerRoutes in NewAPIServer.

	req := httptest.NewRequest("GET", "/api/v1/server/metrics", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "num_goroutines") {
		t.Error("expected num_goroutines in response")
	}
}

func TestHandleSpeedTestDownload(t *testing.T) {
	a := NewAPIServer(Config{}, &mockServer{}, testLogger())

	req := httptest.NewRequest("GET", "/api/v1/speedtest/download?size=1024", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.Len() != 1024 {
		t.Errorf("expected 1024 bytes, got %d", w.Body.Len())
	}
	if w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Error("expected octet-stream content type")
	}
}

func TestHandleSpeedTestDownloadMaxSize(t *testing.T) {
	a := NewAPIServer(Config{}, &mockServer{}, testLogger())

	// Request more than 10MB — should be capped.
	req := httptest.NewRequest("GET", "/api/v1/speedtest/download?size=999999999", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.Len() != 10*1024*1024 {
		t.Errorf("expected 10MB cap, got %d", w.Body.Len())
	}
}

func TestHandleSpeedTestUpload(t *testing.T) {
	a := NewAPIServer(Config{}, &mockServer{}, testLogger())

	data := strings.Repeat("x", 4096)
	req := httptest.NewRequest("POST", "/api/v1/speedtest/upload", strings.NewReader(data))
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "speed_kbps") {
		t.Error("expected speed_kbps in response")
	}
	if !strings.Contains(body, `"bytes":4096`) {
		t.Errorf("expected bytes:4096 in response: %s", body)
	}
}

func TestHandleDiagnostics(t *testing.T) {
	cfg := Config{APIToken: "tok"}
	a := NewAPIServer(cfg, &mockServer{}, testLogger())
	c := perf.NewCollector()
	a.SetPerfCollector(c)

	req := httptest.NewRequest("GET", "/api/v1/diagnostics", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "server") {
		t.Error("expected server section")
	}
	if !strings.Contains(body, "perf") {
		t.Error("expected perf section")
	}
}

func TestHandleDiagnosticsRequiresAuth(t *testing.T) {
	a := NewAPIServer(Config{APIToken: "tok"}, &mockServer{}, testLogger())

	req := httptest.NewRequest("GET", "/api/v1/diagnostics", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// Ensure SetPerfCollector is accessible from internal tests.
func TestSetPerfCollectorInternal(t *testing.T) {
	a := NewAPIServer(Config{}, &mockServer{}, testLogger())
	c := perf.NewCollector()
	a.SetPerfCollector(c)
	if a.perfCollector == nil {
		t.Error("perfCollector should be set")
	}
}

// Ensure download buffer is idempotent.
func TestSpeedTestBufIdempotent(t *testing.T) {
	b1 := getSpeedTestBuf()
	b2 := getSpeedTestBuf()
	if &b1[0] != &b2[0] {
		t.Error("expected same buffer")
	}
}

// Verify getRSSBytes doesn't panic.
func TestGetRSSBytes(t *testing.T) {
	_ = getRSSBytes() // should not panic
}

// Verify estimateCPU doesn't panic.
func TestEstimateCPU(t *testing.T) {
	_ = estimateCPU() // should not panic
}

// Suppress unused import warning.
var _ = io.Discard
