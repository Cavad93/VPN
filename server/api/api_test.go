package api_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavad93/vpn/server/api"
)

// ---------------------------------------------------------------------------
// mockServer — implements api.ServerIface for testing
// ---------------------------------------------------------------------------

type mockServer struct {
	sessions    []api.SessionInfo
	keys        [][32]byte
	disconnects []uint64
}

func (m *mockServer) Sessions() []api.SessionInfo { return m.sessions }

func (m *mockServer) DisconnectSession(id uint64) bool {
	for _, s := range m.sessions {
		if s.ID == id {
			m.disconnects = append(m.disconnects, id)
			return true
		}
	}
	return false
}

func (m *mockServer) AddAllowedKey(key [32]byte) {
	m.keys = append(m.keys, key)
}

func (m *mockServer) RemoveAllowedKey(key [32]byte) {
	out := m.keys[:0]
	for _, k := range m.keys {
		if k != key {
			out = append(out, k)
		}
	}
	m.keys = out
}

func (m *mockServer) AllowedKeys() [][32]byte { return m.keys }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newServer(t *testing.T, cfg api.Config, mock *mockServer) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.NewAPIServer(cfg, mock, logger).Handler()
}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(w.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v (body: %s)", err, w.Body.String())
	}
}

func randomHexKey() string {
	var k [32]byte
	k[0] = 0xAB
	k[1] = 0xCD
	return hex.EncodeToString(k[:])
}

// ---------------------------------------------------------------------------
// TestHealth
// ---------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "GET", "/api/v1/health", "", "")

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string]string
	decodeJSON(t, w, &resp)
	if resp["status"] != "ok" {
		t.Errorf("want status=ok, got %q", resp["status"])
	}
}

// TestHealthNoAuth verifies health is accessible without a token even when auth
// is enabled.
func TestHealthNoAuth(t *testing.T) {
	t.Parallel()
	cfg := api.Config{ListenAddr: "127.0.0.1:0", APIToken: "secret"}
	h := newServer(t, cfg, &mockServer{})
	w := do(t, h, "GET", "/api/v1/health", "", "") // no token
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// TestAuth middleware
// ---------------------------------------------------------------------------

func TestAuthRequired(t *testing.T) {
	t.Parallel()
	cfg := api.Config{ListenAddr: "127.0.0.1:0", APIToken: "s3cr3t"}
	h := newServer(t, cfg, &mockServer{})

	t.Run("no token", func(t *testing.T) {
		w := do(t, h, "GET", "/api/v1/sessions", "", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", w.Code)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		w := do(t, h, "GET", "/api/v1/sessions", "wrongtoken", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", w.Code)
		}
	})

	t.Run("correct token", func(t *testing.T) {
		w := do(t, h, "GET", "/api/v1/sessions", "s3cr3t", "")
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", w.Code)
		}
	})
}

func TestAuthXAPIKey(t *testing.T) {
	t.Parallel()
	cfg := api.Config{ListenAddr: "127.0.0.1:0", APIToken: "mytoken"}
	h := newServer(t, cfg, &mockServer{})
	req := httptest.NewRequest("GET", "/api/v1/sessions", nil)
	req.Header.Set("X-API-Key", "mytoken")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("X-API-Key: want 200, got %d", w.Code)
	}
}

func TestAuthDisabled(t *testing.T) {
	t.Parallel()
	// APIToken is empty — all requests pass through.
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "GET", "/api/v1/sessions", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// TestListSessions
// ---------------------------------------------------------------------------

func TestListSessions_Empty(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "GET", "/api/v1/sessions", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var sessions []api.SessionInfo
	decodeJSON(t, w, &sessions)
	if len(sessions) != 0 {
		t.Errorf("want empty list, got %d sessions", len(sessions))
	}
}

func TestListSessions_WithData(t *testing.T) {
	t.Parallel()
	mock := &mockServer{
		sessions: []api.SessionInfo{
			{ID: 1, RemoteKey: "aabbcc", AssignedIP: "10.8.0.2", BytesIn: 100, BytesOut: 200, ConnectedAt: time.Now(), Duration: "5s"},
			{ID: 2, RemoteKey: "ddeeff", AssignedIP: "10.8.0.3", BytesIn: 300, BytesOut: 400, ConnectedAt: time.Now(), Duration: "10s"},
		},
	}
	h := newServer(t, api.DefaultConfig(), mock)
	w := do(t, h, "GET", "/api/v1/sessions", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var sessions []api.SessionInfo
	decodeJSON(t, w, &sessions)
	if len(sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(sessions))
	}
	if sessions[0].ID != 1 || sessions[1].ID != 2 {
		t.Errorf("unexpected IDs: %d, %d", sessions[0].ID, sessions[1].ID)
	}
}

// ---------------------------------------------------------------------------
// TestGetSession
// ---------------------------------------------------------------------------

func TestGetSession_Found(t *testing.T) {
	t.Parallel()
	mock := &mockServer{
		sessions: []api.SessionInfo{
			{ID: 42, RemoteKey: "aabbcc", AssignedIP: "10.8.0.5"},
		},
	}
	h := newServer(t, api.DefaultConfig(), mock)
	w := do(t, h, "GET", "/api/v1/sessions/42", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var s api.SessionInfo
	decodeJSON(t, w, &s)
	if s.ID != 42 {
		t.Errorf("want ID=42, got %d", s.ID)
	}
}

func TestGetSession_NotFound(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "GET", "/api/v1/sessions/99", "", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestGetSession_BadID(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "GET", "/api/v1/sessions/notanumber", "", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// TestDeleteSession
// ---------------------------------------------------------------------------

func TestDeleteSession_Found(t *testing.T) {
	t.Parallel()
	mock := &mockServer{
		sessions: []api.SessionInfo{{ID: 7}},
	}
	h := newServer(t, api.DefaultConfig(), mock)
	w := do(t, h, "DELETE", "/api/v1/sessions/7", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if len(mock.disconnects) != 1 || mock.disconnects[0] != 7 {
		t.Errorf("expected session 7 to be disconnected")
	}
}

func TestDeleteSession_NotFound(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "DELETE", "/api/v1/sessions/999", "", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestDeleteSession_BadID(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "DELETE", "/api/v1/sessions/abc", "", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// TestListKeys
// ---------------------------------------------------------------------------

func TestListKeys_Empty(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "GET", "/api/v1/keys", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string][]string
	decodeJSON(t, w, &resp)
	if len(resp["keys"]) != 0 {
		t.Errorf("want empty keys, got %v", resp["keys"])
	}
}

func TestListKeys_WithData(t *testing.T) {
	t.Parallel()
	var k1, k2 [32]byte
	k1[0] = 1
	k2[0] = 2
	mock := &mockServer{keys: [][32]byte{k1, k2}}
	h := newServer(t, api.DefaultConfig(), mock)
	w := do(t, h, "GET", "/api/v1/keys", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string][]string
	decodeJSON(t, w, &resp)
	if len(resp["keys"]) != 2 {
		t.Fatalf("want 2 keys, got %d", len(resp["keys"]))
	}
}

// ---------------------------------------------------------------------------
// TestAddKey
// ---------------------------------------------------------------------------

func TestAddKey_Valid(t *testing.T) {
	t.Parallel()
	mock := &mockServer{}
	h := newServer(t, api.DefaultConfig(), mock)
	hexKey := randomHexKey()
	body, _ := json.Marshal(map[string]string{"key": hexKey})
	w := do(t, h, "POST", "/api/v1/keys", "", string(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (body: %s)", w.Code, w.Body.String())
	}
	if len(mock.keys) != 1 {
		t.Errorf("expected 1 key added, got %d", len(mock.keys))
	}
}

func TestAddKey_InvalidHex(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	body := `{"key":"notvalidhex!"}`
	w := do(t, h, "POST", "/api/v1/keys", "", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestAddKey_WrongLength(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	body := `{"key":"aabb"}` // only 2 bytes
	w := do(t, h, "POST", "/api/v1/keys", "", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestAddKey_BadJSON(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "POST", "/api/v1/keys", "", "{notjson")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestAddKey_EmptyBody(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	req := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewReader(nil))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// TestRemoveKey
// ---------------------------------------------------------------------------

func TestRemoveKey_Valid(t *testing.T) {
	t.Parallel()
	var k [32]byte
	k[5] = 0xFF
	mock := &mockServer{keys: [][32]byte{k}}
	h := newServer(t, api.DefaultConfig(), mock)
	hexKey := hex.EncodeToString(k[:])
	w := do(t, h, "DELETE", "/api/v1/keys/"+hexKey, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if len(mock.keys) != 0 {
		t.Errorf("expected key to be removed, still have %d keys", len(mock.keys))
	}
}

func TestRemoveKey_InvalidHex(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "DELETE", "/api/v1/keys/ZZZZ", "", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestRemoveKey_WrongLength(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "DELETE", "/api/v1/keys/deadbeef", "", "") // only 4 bytes
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// TestStats
// ---------------------------------------------------------------------------

func TestStats_NoSessions(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "GET", "/api/v1/stats", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp api.StatsResponse
	decodeJSON(t, w, &resp)
	if resp.ActiveSessions != 0 {
		t.Errorf("want 0 sessions, got %d", resp.ActiveSessions)
	}
}

func TestStats_WithSessions(t *testing.T) {
	t.Parallel()
	mock := &mockServer{
		sessions: []api.SessionInfo{
			{ID: 1, BytesIn: 1000, BytesOut: 2000},
			{ID: 2, BytesIn: 500, BytesOut: 800},
		},
	}
	h := newServer(t, api.DefaultConfig(), mock)
	w := do(t, h, "GET", "/api/v1/stats", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp api.StatsResponse
	decodeJSON(t, w, &resp)
	if resp.ActiveSessions != 2 {
		t.Errorf("want 2 sessions, got %d", resp.ActiveSessions)
	}
	if resp.TotalBytesIn != 1500 {
		t.Errorf("want TotalBytesIn=1500, got %d", resp.TotalBytesIn)
	}
	if resp.TotalBytesOut != 2800 {
		t.Errorf("want TotalBytesOut=2800, got %d", resp.TotalBytesOut)
	}
}

// ---------------------------------------------------------------------------
// TestContentType
// ---------------------------------------------------------------------------

func TestContentTypeJSON(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	w := do(t, h, "GET", "/api/v1/health", "", "")
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("want application/json content-type, got %q", ct)
	}
}
