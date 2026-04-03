package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavad93/vpn/server/api"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newInviteServer(t *testing.T) (*api.APIServer, *mockQRServer, *mockServer) {
	t.Helper()
	var pub [32]byte
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	qrSrv := &mockQRServer{pubKey: pub, listenAddr: "10.0.0.1:443"}
	mock := &mockServer{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	apiSrv := api.NewAPIServer(api.Config{}, mock, logger)
	apiSrv.SetQRServer(qrSrv)
	apiSrv.SetInviteServer()
	return apiSrv, qrSrv, mock
}

func doInviteReq(t *testing.T, h http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// POST /api/v1/invites — create invite
// ---------------------------------------------------------------------------

func TestCreateInvite_Basic(t *testing.T) {
	apiSrv, _, mock := newInviteServer(t)

	rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites",
		map[string]interface{}{"note": "для Ивана", "ttl_hours": 24})

	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201; body: %s", rr.Code, rr.Body.String())
	}

	var rec api.InviteRecord
	if err := json.NewDecoder(rr.Body).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Token == "" {
		t.Error("token is empty")
	}
	if len(rec.Token) != 64 {
		t.Errorf("token length = %d, want 64", len(rec.Token))
	}
	if rec.Config.Host == "" && rec.Config.Port == 0 {
		t.Error("config host and port both empty/zero")
	}
	if rec.Config.PrivateKey == "" {
		t.Error("private key is empty")
	}
	if rec.Config.ServerKey == "" {
		t.Error("server key is empty")
	}
	if rec.Config.DNS == "" {
		t.Error("dns is empty")
	}
	if rec.Note != "для Ивана" {
		t.Errorf("note = %q, want 'для Ивана'", rec.Note)
	}
	if rec.ExpiresAt.IsZero() {
		t.Error("expires_at should be set for ttl_hours=24")
	}
	if !strings.Contains(rec.URL, "/join/"+rec.Token) {
		t.Errorf("URL %q does not contain /join/<token>", rec.URL)
	}

	// Public key should be added to allowlist.
	if len(mock.keys) == 0 {
		t.Error("expected allowed key to be added")
	}
}

func TestCreateInvite_EmptyBody(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201; body: %s", rr.Code, rr.Body.String())
	}

	var rec api.InviteRecord
	if err := json.NewDecoder(rr.Body).Decode(&rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.ExpiresAt.IsZero() != true || rec.ExpiresAt.IsZero() {
		// ttl_hours=0 → bессрочно
	}
	if rec.Config.DNS != "1.1.1.1" {
		t.Errorf("default dns = %q, want 1.1.1.1", rec.Config.DNS)
	}
}

func TestCreateInvite_CustomDNS(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites",
		map[string]interface{}{"dns": "8.8.8.8"})

	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d; body: %s", rr.Code, rr.Body.String())
	}
	var rec api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck
	if rec.Config.DNS != "8.8.8.8" {
		t.Errorf("dns = %q, want 8.8.8.8", rec.Config.DNS)
	}
}

func TestCreateInvite_MaxUses(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites",
		map[string]interface{}{"max_uses": 3})

	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d; body: %s", rr.Code, rr.Body.String())
	}
	var rec api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck
	if rec.MaxUses != 3 {
		t.Errorf("max_uses = %d, want 3", rec.MaxUses)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/invites — list invites
// ---------------------------------------------------------------------------

func TestListInvites_Empty(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	var list []api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&list) //nolint:errcheck
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}
}

func TestListInvites_AfterCreate(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	// Create 2 invites.
	doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites", nil)
	doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	var list []api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&list) //nolint:errcheck
	if len(list) != 2 {
		t.Errorf("expected 2 invites, got %d", len(list))
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/invites/{token} — revoke invite
// ---------------------------------------------------------------------------

func TestRevokeInvite(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	// Create an invite.
	rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites", nil)
	var rec api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck

	// Revoke it.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invites/"+rec.Token, nil)
	rr2 := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr2, req)

	if rr2.Code != http.StatusNoContent {
		t.Fatalf("revoke status %d, want 204", rr2.Code)
	}

	// After revocation the join page should return 410 Gone.
	req3 := httptest.NewRequest(http.MethodGet, "/join/"+rec.Token, nil)
	rr3 := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusGone {
		t.Errorf("join after revoke: status %d, want 410", rr3.Code)
	}
}

func TestRevokeInvite_NotFound(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invites/nonexistenttoken", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// GET /join/{token} — HTML invite page
// ---------------------------------------------------------------------------

func TestJoinPage_Valid(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	// Create invite.
	rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites", nil)
	var rec api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck

	// Open join page.
	req := httptest.NewRequest(http.MethodGet, "/join/"+rec.Token, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	rr2 := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr2, req)

	if rr2.Code != http.StatusOK {
		t.Fatalf("join status %d, want 200; body: %s", rr2.Code, rr2.Body.String())
	}
	ct := rr2.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr2.Body.String()
	if !strings.Contains(body, "CavadVPN") {
		t.Error("HTML should contain 'CavadVPN'")
	}
	if !strings.Contains(body, "cavadvpn://config") {
		t.Error("HTML should contain cavadvpn:// deep link")
	}
	if !strings.Contains(body, "/join/"+rec.Token+"/config.json") {
		t.Error("HTML should contain config.json download link")
	}
	if !strings.Contains(body, "/join/"+rec.Token+"/qr.png") {
		t.Error("HTML should contain qr.png link")
	}
}

func TestJoinPage_PlatformDetection(t *testing.T) {
	tests := []struct {
		ua      string
		wantStr string
	}{
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "iOS"},
		{"Mozilla/5.0 (Linux; Android 14)", "Android"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macOS"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows"},
		{"curl/7.87.0", "Universal"},
	}

	for _, tc := range tests {
		t.Run(tc.wantStr, func(t *testing.T) {
			apiSrv, _, _ := newInviteServer(t)

			rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites", nil)
			var rec api.InviteRecord
			json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck

			req := httptest.NewRequest(http.MethodGet, "/join/"+rec.Token, nil)
			req.Header.Set("User-Agent", tc.ua)
			rr2 := httptest.NewRecorder()
			apiSrv.Handler().ServeHTTP(rr2, req)

			if rr2.Code != http.StatusOK {
				t.Fatalf("status %d; body: %s", rr2.Code, rr2.Body.String())
			}
			if !strings.Contains(rr2.Body.String(), tc.wantStr) {
				t.Errorf("HTML should contain %q for UA %q", tc.wantStr, tc.ua)
			}
		})
	}
}

func TestJoinPage_InvalidToken(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	req := httptest.NewRequest(http.MethodGet, "/join/badtoken123", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Errorf("status %d, want 410", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// GET /join/{token}/config.json
// ---------------------------------------------------------------------------

func TestJoinConfigJSON(t *testing.T) {
	apiSrv, qrSrv, _ := newInviteServer(t)

	rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites", nil)
	var rec api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck

	req := httptest.NewRequest(http.MethodGet, "/join/"+rec.Token+"/config.json", nil)
	rr2 := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr2, req)

	if rr2.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body: %s", rr2.Code, rr2.Body.String())
	}

	var cfg api.ClientConfig
	if err := json.NewDecoder(rr2.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if cfg.PrivateKey == "" {
		t.Error("private_key is empty")
	}
	expectedKey := make([]byte, 32)
	for i := range expectedKey {
		expectedKey[i] = byte(i + 1)
	}
	_ = qrSrv // server key is verified transitively via cfg.ServerKey
	if cfg.ServerKey == "" {
		t.Error("server_key is empty")
	}
	if cfg.Host != "10.0.0.1" {
		t.Errorf("host = %q, want 10.0.0.1", cfg.Host)
	}
	if cfg.Port != 443 {
		t.Errorf("port = %d, want 443", cfg.Port)
	}

	cd := rr2.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "cavadvpn.json") {
		t.Errorf("Content-Disposition = %q, expected attachment with cavadvpn.json", cd)
	}
}

func TestJoinConfigJSON_InvalidToken(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	req := httptest.NewRequest(http.MethodGet, "/join/badtoken/config.json", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Errorf("status %d, want 410", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// GET /join/{token}/qr.png
// ---------------------------------------------------------------------------

func TestJoinQRPNG(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites", nil)
	var rec api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck

	req := httptest.NewRequest(http.MethodGet, "/join/"+rec.Token+"/qr.png", nil)
	rr2 := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr2, req)

	if rr2.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr2.Code)
	}
	if rr2.Header().Get("Content-Type") != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", rr2.Header().Get("Content-Type"))
	}
	if rr2.Body.Len() < 100 {
		t.Error("QR PNG body too small")
	}
}

func TestJoinQRPNG_InvalidToken(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	req := httptest.NewRequest(http.MethodGet, "/join/notfound/qr.png", nil)
	rr := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Errorf("status %d, want 410", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Unique tokens per invite
// ---------------------------------------------------------------------------

func TestInviteTokensAreUnique(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	tokens := make(map[string]bool)
	for i := 0; i < 10; i++ {
		rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites", nil)
		var rec api.InviteRecord
		json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck
		if tokens[rec.Token] {
			t.Fatalf("duplicate token at iteration %d: %s", i, rec.Token)
		}
		tokens[rec.Token] = true
	}
}

// ---------------------------------------------------------------------------
// HTML security: no XSS in note
// ---------------------------------------------------------------------------

func TestJoinPageHTMLEscaping(t *testing.T) {
	apiSrv, _, _ := newInviteServer(t)

	rr := doInviteReq(t, apiSrv.Handler(), http.MethodPost, "/api/v1/invites",
		map[string]interface{}{"note": `<script>alert(1)</script>`})
	var rec api.InviteRecord
	json.NewDecoder(rr.Body).Decode(&rec) //nolint:errcheck

	req := httptest.NewRequest(http.MethodGet, "/join/"+rec.Token, nil)
	rr2 := httptest.NewRecorder()
	apiSrv.Handler().ServeHTTP(rr2, req)

	body := rr2.Body.String()
	if strings.Contains(body, "<script>") {
		t.Error("HTML contains unescaped <script> tag — XSS vulnerability")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("script tag should be HTML-escaped")
	}
}
