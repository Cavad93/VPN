package api_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavad93/vpn/server/api"
)

// ---------------------------------------------------------------------------
// LogBuffer tests
// ---------------------------------------------------------------------------

func TestLogBuffer_Empty(t *testing.T) {
	b := api.NewLogBuffer(10)
	entries := b.Entries(0)
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestLogBuffer_AddAndRetrieve(t *testing.T) {
	b := api.NewLogBuffer(10)
	for i := 0; i < 5; i++ {
		b.Add(api.LogEntry{Message: string(rune('A' + i)), Level: "info"})
	}
	entries := b.Entries(0)
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	if entries[0].Message != "A" {
		t.Errorf("expected first message A, got %q", entries[0].Message)
	}
	if entries[4].Message != "E" {
		t.Errorf("expected last message E, got %q", entries[4].Message)
	}
}

func TestLogBuffer_RingOverwrite(t *testing.T) {
	b := api.NewLogBuffer(3)
	for i := 0; i < 5; i++ {
		b.Add(api.LogEntry{Message: string(rune('A' + i)), Level: "info"})
	}
	// Buffer holds newest 3: C, D, E
	entries := b.Entries(0)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Message != "C" {
		t.Errorf("expected C, got %q", entries[0].Message)
	}
	if entries[2].Message != "E" {
		t.Errorf("expected E, got %q", entries[2].Message)
	}
}

func TestLogBuffer_LimitParameter(t *testing.T) {
	b := api.NewLogBuffer(20)
	for i := 0; i < 10; i++ {
		b.Add(api.LogEntry{Message: string(rune('A' + i)), Level: "info"})
	}
	entries := b.Entries(3)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Latest 3: H, I, J
	if entries[0].Message != "H" {
		t.Errorf("expected H, got %q", entries[0].Message)
	}
	if entries[2].Message != "J" {
		t.Errorf("expected J, got %q", entries[2].Message)
	}
}

func TestLogBuffer_LimitExceedsCount(t *testing.T) {
	b := api.NewLogBuffer(10)
	b.Add(api.LogEntry{Message: "only", Level: "info"})
	entries := b.Entries(100)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestLogBuffer_DefaultCapacity(t *testing.T) {
	b := api.NewLogBuffer(0)
	// Verify it doesn't panic and can store entries
	b.Add(api.LogEntry{Message: "test", Level: "info"})
	entries := b.Entries(0)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after add to default-capacity buffer")
	}
}

func TestLogBuffer_ExactCapacity(t *testing.T) {
	b := api.NewLogBuffer(5)
	for i := 0; i < 5; i++ {
		b.Add(api.LogEntry{Message: string(rune('A' + i)), Level: "info"})
	}
	entries := b.Entries(0)
	if len(entries) != 5 {
		t.Fatalf("expected 5, got %d", len(entries))
	}
	if entries[0].Message != "A" || entries[4].Message != "E" {
		t.Errorf("unexpected messages: %v", entries)
	}
}

func TestLogBuffer_OneEntry(t *testing.T) {
	b := api.NewLogBuffer(5)
	b.Add(api.LogEntry{Message: "hello", Level: "warn"})
	entries := b.Entries(0)
	if len(entries) != 1 || entries[0].Message != "hello" {
		t.Errorf("unexpected: %v", entries)
	}
}

func TestLogBuffer_ChronologicalOrder(t *testing.T) {
	b := api.NewLogBuffer(10)
	for i := 0; i < 6; i++ {
		b.Add(api.LogEntry{Message: string(rune('A' + i)), Level: "info"})
	}
	entries := b.Entries(0)
	for i := 1; i < len(entries); i++ {
		if entries[i].Message <= entries[i-1].Message {
			t.Errorf("entries not in order at index %d: %q <= %q", i, entries[i].Message, entries[i-1].Message)
		}
	}
}

// ---------------------------------------------------------------------------
// slog handler tests (via exported LogBuffer.Handler)
// ---------------------------------------------------------------------------

func TestLogBufHandler_BasicLevels(t *testing.T) {
	b := api.NewLogBuffer(50)
	h := b.Handler()
	logger := slog.New(h)

	logger.Info("info message", "key", "value")
	logger.Warn("warn message")
	logger.Error("error message")
	logger.Debug("debug message")

	entries := b.Entries(0)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	expected := []string{"info", "warn", "error", "debug"}
	for i, e := range entries {
		if e.Level != expected[i] {
			t.Errorf("entry %d: expected level %q got %q", i, expected[i], e.Level)
		}
	}
}

func TestLogBufHandler_Attrs(t *testing.T) {
	b := api.NewLogBuffer(10)
	h := b.Handler()
	logger := slog.New(h)

	logger.Info("test", "user", "alice", "count", 42)
	entries := b.Entries(0)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Attrs["user"] != "alice" {
		t.Errorf("expected user=alice, got %v", e.Attrs["user"])
	}
}

func TestLogBufHandler_WithAttrs(t *testing.T) {
	b := api.NewLogBuffer(10)
	h := b.Handler()
	logger := slog.New(h).With("component", "server")

	logger.Info("hello")
	entries := b.Entries(0)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Attrs["component"] != "server" {
		t.Errorf("expected component=server, got %v", entries[0].Attrs["component"])
	}
}

func TestLogBufHandler_WithGroup(t *testing.T) {
	b := api.NewLogBuffer(10)
	h := b.Handler()
	h2 := h.WithGroup("grp")
	if h2 == nil {
		t.Fatal("WithGroup returned nil")
	}
}

func TestLogBufHandler_Enabled(t *testing.T) {
	b := api.NewLogBuffer(10)
	h := b.Handler()
	for _, lvl := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		if !h.Enabled(context.Background(), lvl) {
			t.Errorf("expected Enabled=true for level %v", lvl)
		}
	}
}

func TestLogBufHandler_Timestamp(t *testing.T) {
	b := api.NewLogBuffer(10)
	h := b.Handler()
	logger := slog.New(h)
	before := time.Now()
	logger.Info("ts test")
	after := time.Now()

	entries := b.Entries(0)
	if len(entries) == 0 {
		t.Fatal("no entries")
	}
	ts := entries[0].Time
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v out of range [%v, %v]", ts, before, after)
	}
}

func TestLogBufHandler_BoolAttr(t *testing.T) {
	b := api.NewLogBuffer(10)
	h := b.Handler()
	logger := slog.New(h)
	logger.Info("bool test", "flag", true)
	entries := b.Entries(0)
	if entries[0].Attrs["flag"] != true {
		t.Errorf("expected flag=true, got %v", entries[0].Attrs["flag"])
	}
}

func TestLogBufHandler_MessagePreserved(t *testing.T) {
	b := api.NewLogBuffer(10)
	logger := slog.New(b.Handler())
	logger.Info("hello world")
	entries := b.Entries(0)
	if entries[0].Message != "hello world" {
		t.Errorf("expected 'hello world', got %q", entries[0].Message)
	}
}

// ---------------------------------------------------------------------------
// Dashboard HTTP routes tests
// ---------------------------------------------------------------------------

// dashMockServer satisfies api.ServerIface with empty implementations.
type dashMockServer struct{}

func (m *dashMockServer) Sessions() []api.SessionInfo          { return nil }
func (m *dashMockServer) DisconnectSession(_ uint64) bool      { return false }
func (m *dashMockServer) AddAllowedKey(_ [32]byte)             {}
func (m *dashMockServer) RemoveAllowedKey(_ [32]byte)          {}
func (m *dashMockServer) AllowedKeys() [][32]byte              { return nil }

func newDashAPIServer(t *testing.T, token string) (*api.APIServer, *api.LogBuffer) {
	t.Helper()
	buf := api.NewLogBuffer(100)
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
	a := api.NewAPIServer(api.Config{APIToken: token}, &dashMockServer{}, logger)
	a.SetLogBuffer(buf)
	return a, buf
}

func TestDashboard_ServeIndex(t *testing.T) {
	a, _ := newDashAPIServer(t, "")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content-type, got %q", ct)
	}
}

func TestDashboard_IndexContainsCavadVPN(t *testing.T) {
	a, _ := newDashAPIServer(t, "")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "CavadVPN") {
		t.Error("dashboard index.html should contain 'CavadVPN'")
	}
}

func TestDashboard_IndexContainsAutoRefresh(t *testing.T) {
	a, _ := newDashAPIServer(t, "")
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "refreshAll") {
		t.Error("dashboard should contain refreshAll JS function")
	}
}

func TestDashboard_LogsEmpty(t *testing.T) {
	a, _ := newDashAPIServer(t, "")

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []api.LogEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestDashboard_LogsWithEntries(t *testing.T) {
	a, buf := newDashAPIServer(t, "")

	logger := slog.New(buf.Handler())
	logger.Info("server started", "addr", "0.0.0.0:443")
	logger.Warn("low memory")
	logger.Error("connection failed")

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	var entries []api.LogEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Level != "info" {
		t.Errorf("expected info, got %q", entries[0].Level)
	}
	if entries[2].Level != "error" {
		t.Errorf("expected error, got %q", entries[2].Level)
	}
}

func TestDashboard_LogsLimitQueryParam(t *testing.T) {
	a, buf := newDashAPIServer(t, "")

	for i := 0; i < 20; i++ {
		buf.Add(api.LogEntry{Message: "msg", Level: "info"})
	}

	req := httptest.NewRequest("GET", "/api/v1/logs?limit=5", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	var entries []api.LogEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5, got %d", len(entries))
	}
}

func TestDashboard_LogsLimitCapped(t *testing.T) {
	a, buf := newDashAPIServer(t, "")

	for i := 0; i < 100; i++ {
		buf.Add(api.LogEntry{Message: "msg", Level: "debug"})
	}

	req := httptest.NewRequest("GET", "/api/v1/logs?limit=99999", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	var entries []api.LogEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 100 < 1000 cap, so all should be returned
	if len(entries) != 100 {
		t.Errorf("expected 100, got %d", len(entries))
	}
}

func TestDashboard_LogsNoBufferSet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
	a := api.NewAPIServer(api.Config{}, &dashMockServer{}, logger)
	// No SetLogBuffer

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var entries []api.LogEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestDashboard_LogsRequireAuth(t *testing.T) {
	a, _ := newDashAPIServer(t, "secret")

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", w.Code)
	}
}

func TestDashboard_LogsWithValidAuth(t *testing.T) {
	a, _ := newDashAPIServer(t, "secret")

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDashboard_LogsWithXAPIKey(t *testing.T) {
	a, _ := newDashAPIServer(t, "secret")

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	req.Header.Set("X-API-Key", "secret")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDashboard_LogsContentType(t *testing.T) {
	a, _ := newDashAPIServer(t, "")

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected application/json, got %q", ct)
	}
}

func TestDashboard_SetLogBuffer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
	a := api.NewAPIServer(api.Config{}, &dashMockServer{}, logger)

	lb := api.NewLogBuffer(50)
	a.SetLogBuffer(lb)

	// Verify it works by adding an entry and fetching via API
	lb.Add(api.LogEntry{Message: "test", Level: "info"})

	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)

	var entries []api.LogEntry
	json.NewDecoder(w.Body).Decode(&entries) //nolint:errcheck
	if len(entries) != 1 || entries[0].Message != "test" {
		t.Errorf("expected 1 entry 'test', got %v", entries)
	}
}

func TestLogEntry_JSONFields(t *testing.T) {
	e := api.LogEntry{
		Time:    time.Now(),
		Level:   "warn",
		Message: "test message",
		Attrs:   map[string]any{"code": 42},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"level":"warn"`, `"message":"test message"`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON missing %q in %s", want, s)
		}
	}
}

func TestLogEntry_AttrsOmittedWhenNil(t *testing.T) {
	e := api.LogEntry{Level: "info", Message: "no attrs"}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), `"attrs"`) {
		t.Errorf("attrs should be omitted when nil: %s", b)
	}
}
