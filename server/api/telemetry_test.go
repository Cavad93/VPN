package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testLogger returns a discarding logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mockServer implements ServerIface for internal tests.
type mockServer struct {
	sessions []SessionInfo
	keys     [][32]byte
}

func (m *mockServer) Sessions() []SessionInfo          { return m.sessions }
func (m *mockServer) DisconnectSession(_ uint64) bool   { return false }
func (m *mockServer) AddAllowedKey(key [32]byte)        { m.keys = append(m.keys, key) }
func (m *mockServer) RemoveAllowedKey(_ [32]byte)       {}
func (m *mockServer) AllowedKeys() [][32]byte           { return m.keys }

// ---------------------------------------------------------------------------
// TelemetryStore tests
// ---------------------------------------------------------------------------

func TestTelemetryStoreAdd(t *testing.T) {
	store := NewTelemetryStore(5)
	if store.Count() != 0 {
		t.Fatalf("expected 0, got %d", store.Count())
	}

	store.Add(TelemetryReport{DeviceID: "d1", Platform: "android"})
	store.Add(TelemetryReport{DeviceID: "d2", Platform: "ios"})
	if store.Count() != 2 {
		t.Fatalf("expected 2, got %d", store.Count())
	}
}

func TestTelemetryStoreRingBuffer(t *testing.T) {
	store := NewTelemetryStore(3)

	for i := 0; i < 5; i++ {
		store.Add(TelemetryReport{
			DeviceID: fmt.Sprintf("d%d", i),
			Platform: "android",
		})
	}

	if store.Count() != 3 {
		t.Fatalf("expected 3 (capacity), got %d", store.Count())
	}

	reports := store.Recent(0)
	if len(reports) != 3 {
		t.Fatalf("expected 3, got %d", len(reports))
	}
	// Should have d2, d3, d4 (oldest d0, d1 overwritten).
	if reports[0].DeviceID != "d2" {
		t.Errorf("expected d2, got %s", reports[0].DeviceID)
	}
	if reports[2].DeviceID != "d4" {
		t.Errorf("expected d4, got %s", reports[2].DeviceID)
	}
}

func TestTelemetryStoreRecent(t *testing.T) {
	store := NewTelemetryStore(100)
	for i := 0; i < 10; i++ {
		store.Add(TelemetryReport{DeviceID: fmt.Sprintf("d%d", i)})
	}

	reports := store.Recent(3)
	if len(reports) != 3 {
		t.Fatalf("expected 3, got %d", len(reports))
	}
	if reports[0].DeviceID != "d7" {
		t.Errorf("expected d7, got %s", reports[0].DeviceID)
	}
	if reports[2].DeviceID != "d9" {
		t.Errorf("expected d9, got %s", reports[2].DeviceID)
	}
}

func TestTelemetryStoreSince(t *testing.T) {
	store := NewTelemetryStore(100)

	store.Add(TelemetryReport{DeviceID: "old"})
	cutoff := time.Now()
	time.Sleep(2 * time.Millisecond)
	store.Add(TelemetryReport{DeviceID: "new"})

	reports := store.Since(cutoff)
	if len(reports) != 1 {
		t.Fatalf("expected 1, got %d", len(reports))
	}
	if reports[0].DeviceID != "new" {
		t.Errorf("expected 'new', got %s", reports[0].DeviceID)
	}
}

func TestTelemetryStoreAnalysis(t *testing.T) {
	store := NewTelemetryStore(10)
	if store.LastAnalysis() != nil {
		t.Fatal("expected nil analysis initially")
	}

	a := &AnalysisResult{Summary: "test"}
	store.SetAnalysis(a)
	got := store.LastAnalysis()
	if got == nil || got.Summary != "test" {
		t.Fatal("expected analysis to be stored")
	}
}

// ---------------------------------------------------------------------------
// API handler tests
// ---------------------------------------------------------------------------

func setupTelemetryAPI(t *testing.T) (*APIServer, *TelemetryStore) {
	t.Helper()
	cfg := Config{ListenAddr: ":0", APIToken: "test-token"}
	srv := &mockServer{}
	a := NewAPIServer(cfg, srv, testLogger())
	store := NewTelemetryStore(1000)
	a.SetTelemetryStore(store, nil)
	return a, store
}

func TestHandleSubmitTelemetry(t *testing.T) {
	a, store := setupTelemetryAPI(t)

	report := TelemetryReport{
		DeviceID:    "abc123",
		Platform:    "android",
		PingMs:      42.5,
		NetworkType: "wifi",
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if store.Count() != 1 {
		t.Fatalf("expected 1 report, got %d", store.Count())
	}
	reports := store.Recent(1)
	if reports[0].DeviceID != "abc123" {
		t.Errorf("expected abc123, got %s", reports[0].DeviceID)
	}
	if reports[0].PingMs != 42.5 {
		t.Errorf("expected ping 42.5, got %f", reports[0].PingMs)
	}
}

func TestHandleSubmitTelemetryMissingFields(t *testing.T) {
	a, _ := setupTelemetryAPI(t)

	// Missing device_id.
	body, _ := json.Marshal(TelemetryReport{Platform: "ios"})
	req := httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_id, got %d", w.Code)
	}

	// Missing platform.
	body, _ = json.Marshal(TelemetryReport{DeviceID: "x"})
	req = httptest.NewRequest("POST", "/api/v1/telemetry", bytes.NewReader(body))
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing platform, got %d", w.Code)
	}
}

func TestHandleListTelemetry(t *testing.T) {
	a, store := setupTelemetryAPI(t)

	for i := 0; i < 5; i++ {
		store.Add(TelemetryReport{DeviceID: fmt.Sprintf("d%d", i), Platform: "ios"})
	}

	req := httptest.NewRequest("GET", "/api/v1/telemetry?limit=3", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var reports []TelemetryReport
	json.NewDecoder(w.Body).Decode(&reports)
	if len(reports) != 3 {
		t.Fatalf("expected 3, got %d", len(reports))
	}
}

func TestHandleListTelemetryRequiresAuth(t *testing.T) {
	a, _ := setupTelemetryAPI(t)

	req := httptest.NewRequest("GET", "/api/v1/telemetry", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetAnalysis(t *testing.T) {
	a, store := setupTelemetryAPI(t)

	// No analysis yet.
	req := httptest.NewRequest("GET", "/api/v1/telemetry/analysis", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Set analysis.
	store.SetAnalysis(&AnalysisResult{
		Summary: "All good",
		Issues:  []DiagnosticIssue{{Severity: "info", Description: "test"}},
	})

	req = httptest.NewRequest("GET", "/api/v1/telemetry/analysis", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	var result AnalysisResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.Summary != "All good" {
		t.Errorf("expected 'All good', got %q", result.Summary)
	}
	if len(result.Issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(result.Issues))
	}
}

// ---------------------------------------------------------------------------
// Analyzer tests
// ---------------------------------------------------------------------------

func TestAnalyzerRunOnce(t *testing.T) {
	store := NewTelemetryStore(100)
	store.Add(TelemetryReport{
		DeviceID:    "d1",
		Platform:    "android",
		PingMs:      150,
		NetworkType: "cellular",
	})

	// Mock analyzer function.
	mockFn := func(ctx context.Context, reports []TelemetryReport, apiKey string, _ *ServerPerfSummary, _ *ServerMetrics) (*AnalysisResult, error) {
		return &AnalysisResult{
			Timestamp:   time.Now(),
			ReportCount: len(reports),
			DeviceCount: 1,
			Summary:     "High latency detected",
			Issues: []DiagnosticIssue{
				{Severity: "warning", Category: "latency", Description: "150ms ping"},
			},
		}, nil
	}

	analyzer := NewTelemetryAnalyzer(store, mockFn, "test-key", time.Hour)
	result := analyzer.RunOnce(context.Background())

	if result.Summary != "High latency detected" {
		t.Errorf("expected 'High latency detected', got %q", result.Summary)
	}
	if result.ReportCount != 1 {
		t.Errorf("expected 1 report, got %d", result.ReportCount)
	}

	// Check it's stored.
	stored := store.LastAnalysis()
	if stored == nil || stored.Summary != "High latency detected" {
		t.Error("analysis not stored")
	}
}

func TestAnalyzerNoReports(t *testing.T) {
	store := NewTelemetryStore(100)
	mockFn := func(ctx context.Context, reports []TelemetryReport, apiKey string, _ *ServerPerfSummary, _ *ServerMetrics) (*AnalysisResult, error) {
		t.Fatal("should not be called with no reports")
		return nil, nil
	}
	analyzer := NewTelemetryAnalyzer(store, mockFn, "key", time.Hour)
	result := analyzer.RunOnce(context.Background())
	if result.ReportCount != 0 {
		t.Errorf("expected 0, got %d", result.ReportCount)
	}
}

func TestAnalyzerError(t *testing.T) {
	store := NewTelemetryStore(100)
	store.Add(TelemetryReport{DeviceID: "d1", Platform: "ios"})

	mockFn := func(ctx context.Context, reports []TelemetryReport, apiKey string, _ *ServerPerfSummary, _ *ServerMetrics) (*AnalysisResult, error) {
		return nil, fmt.Errorf("API timeout")
	}
	analyzer := NewTelemetryAnalyzer(store, mockFn, "key", time.Hour)
	result := analyzer.RunOnce(context.Background())
	if result.Error == "" {
		t.Error("expected error in result")
	}
}

func TestHandleTriggerAnalysis(t *testing.T) {
	cfg := Config{ListenAddr: ":0", APIToken: "test-token"}
	srv := &mockServer{}
	a := NewAPIServer(cfg, srv, testLogger())
	store := NewTelemetryStore(1000)

	mockFn := func(ctx context.Context, reports []TelemetryReport, apiKey string, _ *ServerPerfSummary, _ *ServerMetrics) (*AnalysisResult, error) {
		return &AnalysisResult{Summary: "triggered"}, nil
	}
	analyzer := NewTelemetryAnalyzer(store, mockFn, "key", time.Hour)
	a.SetTelemetryStore(store, analyzer)

	store.Add(TelemetryReport{DeviceID: "d1", Platform: "android"})

	req := httptest.NewRequest("POST", "/api/v1/telemetry/analyze", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result AnalysisResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.Summary != "triggered" {
		t.Errorf("expected 'triggered', got %q", result.Summary)
	}
}

// ---------------------------------------------------------------------------
// Prompt & parse tests
// ---------------------------------------------------------------------------

func TestBuildAnalysisPrompt(t *testing.T) {
	reports := []TelemetryReport{
		{DeviceID: "aabbccdd", Platform: "android", PingMs: 100, PacketLossPercent: 2.5, NetworkType: "wifi", ConnectionState: "connected"},
		{DeviceID: "aabbccdd", Platform: "android", PingMs: 200, PacketLossPercent: 5.0, NetworkType: "wifi", ConnectionState: "connected"},
		{DeviceID: "eeff0011", Platform: "ios", PingMs: 50, NetworkType: "cellular", ConnectionState: "connected"},
	}

	prompt := buildAnalysisPrompt(reports, nil, nil)
	if len(prompt) < 100 {
		t.Error("prompt too short")
	}
	// Should mention device count.
	if !containsStr(prompt, "3 reports") {
		t.Error("should mention report count")
	}
	if !containsStr(prompt, "2 devices") {
		t.Error("should mention device count")
	}
}

func TestParseAnalysisResponse(t *testing.T) {
	jsonResp := `{
		"summary": "Network is healthy",
		"issues": [{"severity":"info","category":"latency","description":"Low latency"}],
		"recommendations": ["No action needed"]
	}`

	result := parseAnalysisResponse(jsonResp, 10)
	if result.Summary != "Network is healthy" {
		t.Errorf("unexpected summary: %q", result.Summary)
	}
	if len(result.Issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(result.Issues))
	}
	if len(result.Recommendations) != 1 {
		t.Errorf("expected 1 recommendation, got %d", len(result.Recommendations))
	}
}

func TestParseAnalysisResponseFallback(t *testing.T) {
	// Non-JSON response should still work.
	result := parseAnalysisResponse("The network looks fine overall.", 5)
	if result.Summary != "The network looks fine overall." {
		t.Errorf("fallback should use raw text: %q", result.Summary)
	}
}

func containsStr(s, sub string) bool {
	return len(s) > 0 && len(sub) > 0 && bytes.Contains([]byte(s), []byte(sub))
}
