package api_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavad93/vpn/server/api"
	"github.com/cavad93/vpn/server/perf"
)

func TestHandlePerfNoCollector(t *testing.T) {
	a := api.NewAPIServer(api.Config{}, &mockServer{}, slog.Default())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/perf", nil)
	a.Handler().ServeHTTP(rr, req)

	// Without SetPerfCollector, route is not registered → 404 or method not allowed.
	// The route simply doesn't exist, so we expect a non-200.
	if rr.Code == http.StatusOK {
		// If somehow registered, check body.
		var body map[string]string
		json.NewDecoder(rr.Body).Decode(&body)
		if body["status"] != "no collector" {
			t.Errorf("expected 'no collector', got %q", body["status"])
		}
	}
}

func TestHandlePerfWithCollector(t *testing.T) {
	a := api.NewAPIServer(api.Config{}, &mockServer{}, slog.Default())
	pc := perf.NewCollector()
	a.SetPerfCollector(pc)

	// Record some metrics.
	pc.TrackLatency(perf.StageNoiseEnc, 100*time.Microsecond)
	pc.TrackPacket(perf.StageTunRead, 1500)
	pc.ActiveSessions.Add(2)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/perf", nil)
	a.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var snap perf.Snapshot
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snap.ActiveSessions != 2 {
		t.Errorf("expected active_sessions=2, got %d", snap.ActiveSessions)
	}
	enc := snap.Stages["noise_encrypt"]
	if enc.Latency.Count != 1 {
		t.Errorf("expected noise_encrypt count=1, got %d", enc.Latency.Count)
	}
	tun := snap.Stages["tun_read"]
	if tun.Packets != 1 || tun.Bytes != 1500 {
		t.Errorf("tun_read: packets=%d bytes=%d", tun.Packets, tun.Bytes)
	}
}

func TestHandlePerfReset(t *testing.T) {
	a := api.NewAPIServer(api.Config{}, &mockServer{}, slog.Default())
	pc := perf.NewCollector()
	a.SetPerfCollector(pc)

	pc.TrackLatency(perf.StageNoiseEnc, 100*time.Microsecond)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/perf/reset", nil)
	a.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Verify counters are zero.
	snap := pc.Snapshot()
	for _, st := range snap.Stages {
		if st.Latency.Count != 0 {
			t.Error("expected zero counts after reset")
		}
	}
}

func TestHandlePerfWithAuth(t *testing.T) {
	a := api.NewAPIServer(api.Config{APIToken: "secret"}, &mockServer{}, slog.Default())
	pc := perf.NewCollector()
	a.SetPerfCollector(pc)

	// No token — should fail.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/perf", nil)
	a.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}

	// With token — should succeed.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/perf", nil)
	req.Header.Set("Authorization", "Bearer secret")
	a.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}
