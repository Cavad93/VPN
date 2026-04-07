package api_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavad93/vpn/server/api"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// pprofMockServer satisfies api.ServerIface with no-op implementations.
type pprofMockServer struct{}

func (m *pprofMockServer) Sessions() []api.SessionInfo          { return nil }
func (m *pprofMockServer) DisconnectSession(_ uint64) bool      { return false }
func (m *pprofMockServer) AddAllowedKey(_ [32]byte)             {}
func (m *pprofMockServer) RemoveAllowedKey(_ [32]byte)          {}
func (m *pprofMockServer) AllowedKeys() [][32]byte              { return nil }

// newPprofServer creates an APIServer with a fixed Bearer token so auth is enforced.
func newPprofServer(t *testing.T) (http.Handler, string) {
	t.Helper()
	const tok = "pprof-test-token-xyz"
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := api.NewAPIServer(api.Config{APIToken: tok}, &pprofMockServer{}, logger)
	return srv.Handler(), tok
}

// authedGET builds a GET request with a Bearer token.
func authedGET(path, token string) *http.Request {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// ---------------------------------------------------------------------------
// Auth enforcement — every pprof path must require a token
// ---------------------------------------------------------------------------

func TestPprofIndex_RequiresAuth(t *testing.T) {
	h, _ := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/debug/pprof/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestPprofCmdline_RequiresAuth(t *testing.T) {
	h, _ := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/debug/pprof/cmdline", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestPprofProfile_RequiresAuth(t *testing.T) {
	h, _ := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/debug/pprof/profile", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestPprofSymbol_RequiresAuth(t *testing.T) {
	h, _ := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/debug/pprof/symbol", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestPprofTrace_RequiresAuth(t *testing.T) {
	h, _ := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/debug/pprof/trace", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestPprofHeap_RequiresAuth(t *testing.T) {
	h, _ := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/debug/pprof/heap", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestPprofGoroutine_RequiresAuth(t *testing.T) {
	h, _ := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/debug/pprof/goroutine", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Authed access — handler returns 200 and non-empty body for instant profiles
// ---------------------------------------------------------------------------

func TestPprofIndex_AuthedReturns200(t *testing.T) {
	h, tok := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedGET("/debug/pprof/", tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"goroutine", "heap", "allocs"} {
		if !strings.Contains(body, want) {
			t.Errorf("pprof index missing profile %q in body", want)
		}
	}
}

func TestPprofCmdline_AuthedReturns200(t *testing.T) {
	h, tok := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedGET("/debug/pprof/cmdline", tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestPprofHeap_AuthedReturnsNonEmptyBinary(t *testing.T) {
	h, tok := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedGET("/debug/pprof/heap", tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if rr.Body.Len() == 0 {
		t.Fatal("heap profile body is empty")
	}
}

func TestPprofGoroutine_AuthedReturnsNonEmptyBinary(t *testing.T) {
	h, tok := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedGET("/debug/pprof/goroutine", tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if rr.Body.Len() == 0 {
		t.Fatal("goroutine profile body is empty")
	}
}

func TestPprofAllocs_AuthedReturns200(t *testing.T) {
	h, tok := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedGET("/debug/pprof/allocs", tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestPprofSymbol_AuthedReturns200(t *testing.T) {
	h, tok := newPprofServer(t)
	rr := httptest.NewRecorder()
	// GET with no addresses — pprof responds with num_symbols=0 but 200.
	h.ServeHTTP(rr, authedGET("/debug/pprof/symbol", tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// X-API-Key header also grants access
// ---------------------------------------------------------------------------

func TestPprofIndex_XAPIKeyGrantsAccess(t *testing.T) {
	const tok = "pprof-test-token-xyz"
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := api.NewAPIServer(api.Config{APIToken: tok}, &pprofMockServer{}, logger)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/debug/pprof/", nil)
	req.Header.Set("X-API-Key", tok)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 with X-API-Key, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Wrong token → 401
// ---------------------------------------------------------------------------

func TestPprofIndex_WrongToken401(t *testing.T) {
	h, _ := newPprofServer(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedGET("/debug/pprof/", "wrong-token"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for wrong token, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Server with empty APIToken — auth middleware passes everything through
// ---------------------------------------------------------------------------

func TestPprofIndex_EmptyToken_ServesOK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := api.NewAPIServer(api.Config{}, &pprofMockServer{}, logger)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/debug/pprof/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 with empty token, got %d", rr.Code)
	}
}
