package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cavad93/vpn/server/api"
)

func TestGetClientVersionDefault(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	rec := do(t, h, http.MethodGet, "/api/v1/client/version", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var info api.ClientVersionInfo
	decodeJSON(t, rec, &info)
	if info.Version == "" {
		t.Error("expected non-empty default version")
	}
}

func TestGetClientVersionNoAuthRequired(t *testing.T) {
	t.Parallel()
	// Even with a token configured, GET /api/v1/client/version must be
	// accessible without credentials so headless clients can poll freely.
	h := newServer(t, api.Config{ListenAddr: ":0", APIToken: "secret"}, &mockServer{})
	rec := do(t, h, http.MethodGet, "/api/v1/client/version", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 without auth on GET, got %d", rec.Code)
	}
}

func TestSetClientVersionRequiresAuth(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.Config{ListenAddr: ":0", APIToken: "token"}, &mockServer{})

	body, _ := json.Marshal(api.ClientVersionInfo{Version: "2.0.0", DownloadURL: "u", SHA256: "h"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/client/version", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestSetAndGetClientVersion(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.Config{ListenAddr: ":0", APIToken: "tok"}, &mockServer{})

	want := api.ClientVersionInfo{
		Version:      "3.1.4",
		DownloadURL:  "https://example.com/cavadvpn-3.1.4.zip",
		SHA256:       "deadbeef",
		ReleaseNotes: "performance improvements",
		MinOSVersion: "12.0",
	}

	body, _ := json.Marshal(want)
	rec := do(t, h, http.MethodPost, "/api/v1/client/version", "tok", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Now GET should return the updated value.
	rec2 := do(t, h, http.MethodGet, "/api/v1/client/version", "", "")
	var got api.ClientVersionInfo
	decodeJSON(t, rec2, &got)

	if got.Version != want.Version {
		t.Errorf("version: want %q, got %q", want.Version, got.Version)
	}
	if got.DownloadURL != want.DownloadURL {
		t.Errorf("download_url: want %q, got %q", want.DownloadURL, got.DownloadURL)
	}
	if got.SHA256 != want.SHA256 {
		t.Errorf("sha256: want %q, got %q", want.SHA256, got.SHA256)
	}
	if got.ReleaseNotes != want.ReleaseNotes {
		t.Errorf("release_notes: want %q, got %q", want.ReleaseNotes, got.ReleaseNotes)
	}
}

func TestSetClientVersionEmptyVersionRejected(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	rec := do(t, h, http.MethodPost, "/api/v1/client/version", "", `{"version":"","download_url":"u","sha256":"h"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty version, got %d", rec.Code)
	}
}

func TestSetClientVersionInvalidJSON(t *testing.T) {
	t.Parallel()
	h := newServer(t, api.DefaultConfig(), &mockServer{})
	rec := do(t, h, http.MethodPost, "/api/v1/client/version", "", "not-json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", rec.Code)
	}
}
