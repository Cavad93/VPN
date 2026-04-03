package api

// update_api.go — Client auto-update version endpoint.
//
// Endpoint (no authentication required so headless clients can check):
//
//	GET /api/v1/client/version
//	  → {"version":"1.0.0","download_url":"…","sha256":"…","release_notes":"…","min_os_version":"…"}
//
//	POST /api/v1/client/version  (auth required)
//	  ← {"version":"…","download_url":"…","sha256":"…","release_notes":"…","min_os_version":"…"}
//	  Sets the advertised client version info.
//
// The server stores exactly one ClientVersionInfo in memory. On startup it
// defaults to "1.0.0" with empty download fields so existing clients see
// "up-to-date" until the admin pushes a real update.

import (
	"encoding/json"
	"net/http"
	"sync"
)

// ClientVersionInfo is the JSON structure returned to auto-update clients.
type ClientVersionInfo struct {
	Version       string `json:"version"`
	DownloadURL   string `json:"download_url"`
	SHA256        string `json:"sha256"`
	ReleaseNotes  string `json:"release_notes"`
	MinOSVersion  string `json:"min_os_version"`
}

// updateStore holds the current advertised client version info.
type updateStore struct {
	mu   sync.RWMutex
	info ClientVersionInfo
}

func newUpdateStore() *updateStore {
	return &updateStore{
		info: ClientVersionInfo{
			Version: "1.0.0",
		},
	}
}

func (s *updateStore) get() ClientVersionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.info
}

func (s *updateStore) set(info ClientVersionInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.info = info
}

// ── APIServer integration ──────────────────────────────────────────────────

// initUpdateStore lazily creates the store (called once from registerRoutes).
func (a *APIServer) initUpdateStore() {
	if a.updateStore == nil {
		a.updateStore = newUpdateStore()
	}
}

// handleGetClientVersion serves GET /api/v1/client/version (no auth).
func (a *APIServer) handleGetClientVersion(w http.ResponseWriter, r *http.Request) {
	a.initUpdateStore()
	info := a.updateStore.get()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// handleSetClientVersion serves POST /api/v1/client/version (auth required).
func (a *APIServer) handleSetClientVersion(w http.ResponseWriter, r *http.Request) {
	a.initUpdateStore()
	var req ClientVersionInfo
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Version == "" {
		http.Error(w, "version is required", http.StatusBadRequest)
		return
	}
	a.updateStore.set(req)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(req)
}
