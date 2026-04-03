package api_test

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavad93/vpn/server/api"
)

// mockQRServer implements api.QRServerIface for testing.
type mockQRServer struct {
	pubKey     [32]byte
	listenAddr string
}

func (m *mockQRServer) PublicKey() [32]byte   { return m.pubKey }
func (m *mockQRServer) VPNListenAddr() string { return m.listenAddr }

func newAPIServerWithQR(t *testing.T, cfg api.Config, listenAddr string) (*api.APIServer, *mockQRServer, *mockServer) {
	t.Helper()
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	qrSrv := &mockQRServer{pubKey: pub, listenAddr: listenAddr}
	mock := &mockServer{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	apiSrv := api.NewAPIServer(cfg, mock, logger)
	apiSrv.SetQRServer(qrSrv)
	return apiSrv, qrSrv, mock
}

// ---------------------------------------------------------------------------
// GET /api/v1/qr/server-info
// ---------------------------------------------------------------------------

func TestQRServerInfo(t *testing.T) {
	apiSrv, qrSrv, _ := newAPIServerWithQR(t, api.Config{}, "203.0.113.10:443")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/server-info", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp["host"] != "203.0.113.10" {
		t.Errorf("host = %v, want 203.0.113.10", resp["host"])
	}
	if resp["port"] != float64(443) {
		t.Errorf("port = %v, want 443", resp["port"])
	}
	wantKey := hex.EncodeToString(qrSrv.pubKey[:])
	if resp["server_key"] != wantKey {
		t.Errorf("server_key = %v, want %s", resp["server_key"], wantKey)
	}
}

func TestQRServerInfoWildcardAddr(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{}, "0.0.0.0:443")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/server-info", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	if resp["host"] != "" {
		t.Errorf("wildcard host should be empty string, got %v", resp["host"])
	}
}

func TestQRServerInfoIPv6Wildcard(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{}, "[::]:1194")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/server-info", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp) //nolint:errcheck
	if resp["host"] != "" {
		t.Errorf("IPv6 wildcard host should be empty string, got %v", resp["host"])
	}
	if resp["port"] != float64(1194) {
		t.Errorf("port = %v, want 1194", resp["port"])
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/qr/generate — PNG response
// ---------------------------------------------------------------------------

func TestQRGeneratePNG(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{}, "203.0.113.10:443")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/qr/generate", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	body := rr.Body.Bytes()
	if len(body) < 4 {
		t.Fatalf("PNG body too short: %d bytes", len(body))
	}
	if string(body[:4]) != "\x89PNG" {
		t.Errorf("not a valid PNG; first 4 bytes: %x", body[:4])
	}
}

func TestQRGenerateAddsKeyToAllowlist(t *testing.T) {
	apiSrv, _, mock := newAPIServerWithQR(t, api.Config{}, "1.2.3.4:443")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/qr/generate", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", rr.Code)
	}
	if len(mock.keys) != 1 {
		t.Errorf("allowlist has %d keys, want 1", len(mock.keys))
	}
}

func TestQRGenerateMultipleAddsMultipleKeys(t *testing.T) {
	apiSrv, _, mock := newAPIServerWithQR(t, api.Config{}, "1.2.3.4:443")

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/qr/generate", nil)
		rr := httptest.NewRecorder()
		apiSrv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("call %d: status %d", i, rr.Code)
		}
	}
	if len(mock.keys) != 3 {
		t.Errorf("allowlist has %d keys, want 3", len(mock.keys))
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/qr/generate?format=json
// ---------------------------------------------------------------------------

func TestQRGenerateJSON(t *testing.T) {
	apiSrv, qrSrv, _ := newAPIServerWithQR(t, api.Config{}, "203.0.113.10:443")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/generate?format=json", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d; body: %s", rr.Code, rr.Body.String())
	}
	var cfg api.ClientConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Host != "203.0.113.10" {
		t.Errorf("host = %q, want 203.0.113.10", cfg.Host)
	}
	if cfg.Port != 443 {
		t.Errorf("port = %d, want 443", cfg.Port)
	}
	wantServerKey := hex.EncodeToString(qrSrv.pubKey[:])
	if cfg.ServerKey != wantServerKey {
		t.Errorf("server_key = %q, want %s", cfg.ServerKey, wantServerKey)
	}
	if len(cfg.PrivateKey) != 64 {
		t.Errorf("private_key length = %d, want 64 hex chars", len(cfg.PrivateKey))
	}
	if cfg.DNS != "1.1.1.1" {
		t.Errorf("dns = %q, want 1.1.1.1", cfg.DNS)
	}
}

func TestQRGenerateCustomDNS(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{}, "1.2.3.4:443")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/generate?format=json&dns=8.8.8.8", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var cfg api.ClientConfig
	json.NewDecoder(rr.Body).Decode(&cfg) //nolint:errcheck
	if cfg.DNS != "8.8.8.8" {
		t.Errorf("dns = %q, want 8.8.8.8", cfg.DNS)
	}
}

func TestQRGenerateGETAlsoWorks(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{}, "1.2.3.4:443")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/generate", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
}

// ---------------------------------------------------------------------------
// Auth enforcement
// ---------------------------------------------------------------------------

func TestQREndpointsRequireAuth(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{APIToken: "secret"}, "1.2.3.4:443")

	endpoints := []struct{ method, path string }{
		{"GET", "/api/v1/qr/server-info"},
		{"POST", "/api/v1/qr/generate"},
		{"GET", "/api/v1/qr/generate"},
	}
	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		rr := httptest.NewRecorder()
		apiSrv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d, want 401", ep.method, ep.path, rr.Code)
		}
	}
}

func TestQREndpointsAcceptBearerToken(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{APIToken: "tok"}, "1.2.3.4:443")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/server-info", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status %d, want 200", rr.Code)
	}
}

func TestQREndpointsAcceptAPIKey(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{APIToken: "tok"}, "1.2.3.4:443")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/server-info", nil)
	req.Header.Set("X-API-Key", "tok")
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status %d, want 200", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Unique keys per generate call
// ---------------------------------------------------------------------------

func TestQRGenerateDifferentKeysEachTime(t *testing.T) {
	apiSrv, _, _ := newAPIServerWithQR(t, api.Config{}, "1.2.3.4:443")

	var keys []string
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/generate?format=json", nil)
		rr := httptest.NewRecorder()
		apiSrv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("call %d: status %d", i, rr.Code)
		}
		var cfg api.ClientConfig
		json.NewDecoder(rr.Body).Decode(&cfg) //nolint:errcheck
		for _, prev := range keys {
			if prev == cfg.PrivateKey {
				t.Errorf("duplicate private key on call %d", i)
			}
		}
		keys = append(keys, cfg.PrivateKey)
	}
}

// ---------------------------------------------------------------------------
// URI format validation
// ---------------------------------------------------------------------------

func TestQRGeneratedURIFormat(t *testing.T) {
	apiSrv, qrSrv, _ := newAPIServerWithQR(t, api.Config{}, "10.0.0.1:443")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/qr/generate?format=json", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	var cfg api.ClientConfig
	json.NewDecoder(rr.Body).Decode(&cfg) //nolint:errcheck

	uri := "cavadvpn://config?host=" + cfg.Host +
		"&port=443" +
		"&server_key=" + hex.EncodeToString(qrSrv.pubKey[:]) +
		"&private_key=" + cfg.PrivateKey +
		"&dns=" + cfg.DNS

	if !strings.HasPrefix(uri, "cavadvpn://config?") {
		t.Errorf("URI should start with cavadvpn://config?: %s", uri)
	}
}
