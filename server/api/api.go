// Package api implements the REST management API for the VPN server.
//
// Endpoints:
//
//	GET    /api/v1/health           — health check (no auth)
//	GET    /api/v1/sessions         — list active sessions
//	GET    /api/v1/sessions/{id}    — get single session
//	DELETE /api/v1/sessions/{id}    — disconnect session
//	GET    /api/v1/keys             — list allowlist keys
//	POST   /api/v1/keys             — add key  {"key":"<hex>"}
//	DELETE /api/v1/keys/{key}       — remove key
//	GET    /api/v1/stats            — aggregate traffic statistics
//
// Authentication: all endpoints except /health require
//
//	Authorization: Bearer <token>
//
// or X-API-Key: <token> when Config.APIToken is non-empty.
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/cavad93/vpn/server/perf"
)

// SessionInfo holds read-only statistics for one active client session.
type SessionInfo struct {
	ID          uint64    `json:"id"`
	RemoteKey   string    `json:"remote_key"`
	AssignedIP  string    `json:"assigned_ip"`
	BytesIn     uint64    `json:"bytes_in"`
	BytesOut    uint64    `json:"bytes_out"`
	ConnectedAt time.Time `json:"connected_at"`
	Duration    string    `json:"duration"`
}

// ServerIface is the subset of the VPN server that the REST API requires.
type ServerIface interface {
	// Sessions returns a snapshot of all active client sessions.
	Sessions() []SessionInfo
	// DisconnectSession terminates the session with the given ID.
	// Returns true if the session existed and was cancelled.
	DisconnectSession(id uint64) bool
	// AddAllowedKey adds a client public key to the allowlist.
	AddAllowedKey(key [32]byte)
	// RemoveAllowedKey removes a client public key from the allowlist.
	RemoveAllowedKey(key [32]byte)
	// AllowedKeys returns a copy of the current allowlist.
	// Returns nil when no allowlist is configured (open access).
	AllowedKeys() [][32]byte
}

// Config holds configuration for the API server.
type Config struct {
	// ListenAddr is the TCP address to listen on (e.g. "127.0.0.1:8080").
	ListenAddr string
	// APIToken is the Bearer token required for all calls except GET /health.
	// If empty, authentication is disabled (dev/testing only; not for production).
	APIToken string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr: "127.0.0.1:8080",
	}
}

// APIServer is the HTTP management API server.
type APIServer struct {
	cfg         Config
	srv         ServerIface
	qrSrv       QRServerIface
	invites     *InviteStore
	notifSvc    NotificationService
	logger        *slog.Logger
	mux           *http.ServeMux
	logBuf        *LogBuffer
	updateStore   *updateStore
	perfCollector *perf.Collector
}

// NewAPIServer creates a new APIServer and registers all routes.
func NewAPIServer(cfg Config, srv ServerIface, logger *slog.Logger) *APIServer {
	a := &APIServer{
		cfg:    cfg,
		srv:    srv,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	a.registerRoutes()
	return a
}

// Handler returns the underlying http.Handler, useful for testing.
func (a *APIServer) Handler() http.Handler {
	return a.mux
}

// Run starts the HTTP server and blocks until ctx is cancelled or a fatal
// listen error occurs.
func (a *APIServer) Run(ctx context.Context) error {
	hs := &http.Server{
		Addr:         a.cfg.ListenAddr,
		Handler:      a.mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("api: listen: %w", err)
		}
		close(errCh)
	}()

	a.logger.Info("api server listening", "addr", a.cfg.ListenAddr)

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := hs.Shutdown(shutCtx); err != nil {
			a.logger.Warn("api shutdown error", "err", err)
		}
		return <-errCh
	case err := <-errCh:
		return err
	}
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

func (a *APIServer) registerRoutes() {
	// Web dashboard and logs.
	a.registerDashboardRoutes()

	// Health — no authentication.
	a.mux.HandleFunc("GET /api/v1/health", a.handleHealth)

	// Sessions
	a.mux.HandleFunc("GET /api/v1/sessions", a.auth(a.handleListSessions))
	a.mux.HandleFunc("GET /api/v1/sessions/{id}", a.auth(a.handleGetSession))
	a.mux.HandleFunc("DELETE /api/v1/sessions/{id}", a.auth(a.handleDeleteSession))

	// Allowlist keys
	a.mux.HandleFunc("GET /api/v1/keys", a.auth(a.handleListKeys))
	a.mux.HandleFunc("POST /api/v1/keys", a.auth(a.handleAddKey))
	a.mux.HandleFunc("DELETE /api/v1/keys/{key}", a.auth(a.handleRemoveKey))

	// Aggregate statistics
	a.mux.HandleFunc("GET /api/v1/stats", a.auth(a.handleStats))

	// Client auto-update — GET is public so headless clients can poll freely.
	a.mux.HandleFunc("GET /api/v1/client/version", a.handleGetClientVersion)
	a.mux.HandleFunc("POST /api/v1/client/version", a.auth(a.handleSetClientVersion))
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

// auth wraps next with Bearer-token authentication when a.cfg.APIToken is set.
func (a *APIServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.APIToken == "" {
			next(w, r)
			return
		}
		token := bearerToken(r)
		if token == "" {
			token = r.Header.Get("X-API-Key")
		}
		if token != a.cfg.APIToken {
			writeError(w, http.StatusUnauthorized, "invalid or missing API token")
			return
		}
		next(w, r)
	}
}

// bearerToken extracts the token from the Authorization: Bearer <token> header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		return auth[len(prefix):]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleHealth returns {"status":"ok"} — no authentication required.
func (a *APIServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleListSessions returns all active client sessions.
func (a *APIServer) handleListSessions(w http.ResponseWriter, _ *http.Request) {
	sessions := a.srv.Sessions()
	if sessions == nil {
		sessions = []SessionInfo{}
	}
	writeJSON(w, http.StatusOK, sessions)
}

// handleGetSession returns a single session by numeric ID.
func (a *APIServer) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSessionID(w, r)
	if !ok {
		return
	}
	for _, s := range a.srv.Sessions() {
		if s.ID == id {
			writeJSON(w, http.StatusOK, s)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("session %d not found", id))
}

// handleDeleteSession disconnects a client session by numeric ID.
func (a *APIServer) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSessionID(w, r)
	if !ok {
		return
	}
	if !a.srv.DisconnectSession(id) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("session %d not found", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected"})
}

// handleListKeys returns all hex-encoded keys from the allowlist.
func (a *APIServer) handleListKeys(w http.ResponseWriter, _ *http.Request) {
	keys := a.srv.AllowedKeys()
	hexKeys := make([]string, len(keys))
	for i, k := range keys {
		hexKeys[i] = hex.EncodeToString(k[:])
	}
	writeJSON(w, http.StatusOK, map[string][]string{"keys": hexKeys})
}

// addKeyRequest is the JSON body for POST /api/v1/keys.
type addKeyRequest struct {
	Key string `json:"key"` // hex-encoded 32-byte X25519 public key
}

// handleAddKey adds a client public key to the server allowlist.
func (a *APIServer) handleAddKey(w http.ResponseWriter, r *http.Request) {
	var req addKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	key, err := parseHexKey(req.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.srv.AddAllowedKey(key)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added", "key": req.Key})
}

// handleRemoveKey removes a client public key from the allowlist.
func (a *APIServer) handleRemoveKey(w http.ResponseWriter, r *http.Request) {
	hexKey := r.PathValue("key")
	key, err := parseHexKey(hexKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.srv.RemoveAllowedKey(key)
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "key": hexKey})
}

// StatsResponse holds aggregate server traffic statistics.
type StatsResponse struct {
	ActiveSessions int    `json:"active_sessions"`
	TotalBytesIn   uint64 `json:"total_bytes_in"`
	TotalBytesOut  uint64 `json:"total_bytes_out"`
}

// handleStats returns aggregate statistics across all active sessions.
func (a *APIServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	sessions := a.srv.Sessions()
	var totalIn, totalOut uint64
	for _, s := range sessions {
		totalIn += s.BytesIn
		totalOut += s.BytesOut
	}
	writeJSON(w, http.StatusOK, StatsResponse{
		ActiveSessions: len(sessions),
		TotalBytesIn:   totalIn,
		TotalBytesOut:  totalOut,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseSessionID extracts and parses the {id} path variable as uint64.
func parseSessionID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid session id %q", idStr))
		return 0, false
	}
	return id, true
}

// parseHexKey decodes a 64-hex-character (32-byte) X25519 key.
func parseHexKey(hexStr string) ([32]byte, error) {
	var key [32]byte
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return key, fmt.Errorf("key: invalid hex encoding: %w", err)
	}
	if len(b) != 32 {
		return key, fmt.Errorf("key: expected 32 bytes, got %d", len(b))
	}
	copy(key[:], b)
	return key, nil
}

// writeJSON serialises v as JSON and writes it with the given HTTP status.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// errorResponse is the standard JSON error envelope.
type errorResponse struct {
	Error string `json:"error"`
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}
