package api

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

//go:embed web
var webFiles embed.FS

// LogEntry is a single captured log record stored in the LogBuffer.
type LogEntry struct {
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

// LogBuffer is a thread-safe fixed-capacity ring buffer of LogEntry values.
// Oldest entries are overwritten when the buffer is full.
type LogBuffer struct {
	entries []LogEntry
	cap     int
	pos     int // next write index
	count   int // number of valid entries (≤ cap)
	mu      chan struct{}
}

// NewLogBuffer returns a LogBuffer with the given capacity.
// If cap ≤ 0 it defaults to 200.
func NewLogBuffer(cap int) *LogBuffer {
	if cap <= 0 {
		cap = 200
	}
	mu := make(chan struct{}, 1)
	mu <- struct{}{}
	return &LogBuffer{
		entries: make([]LogEntry, cap),
		cap:     cap,
		mu:      mu,
	}
}

func (b *LogBuffer) lock()   { <-b.mu }
func (b *LogBuffer) unlock() { b.mu <- struct{}{} }

// Add appends e to the ring buffer, overwriting the oldest entry if full.
func (b *LogBuffer) Add(e LogEntry) {
	b.lock()
	defer b.unlock()
	b.entries[b.pos] = e
	b.pos = (b.pos + 1) % b.cap
	if b.count < b.cap {
		b.count++
	}
}

// Entries returns buffered entries in chronological order (oldest first).
// If limit > 0 only the most recent min(limit, count) entries are returned.
func (b *LogBuffer) Entries(limit int) []LogEntry {
	b.lock()
	defer b.unlock()

	n := b.count
	if limit > 0 && limit < n {
		n = limit
	}
	if n == 0 {
		return []LogEntry{}
	}

	// oldest-of-n position in the ring
	start := ((b.pos - n) % b.cap + b.cap) % b.cap

	result := make([]LogEntry, n)
	for i := 0; i < n; i++ {
		result[i] = b.entries[(start+i)%b.cap]
	}
	return result
}

// Handler returns a slog.Handler that writes records to this LogBuffer.
func (b *LogBuffer) Handler() slog.Handler {
	return &logBufHandler{buf: b}
}

// ---------------------------------------------------------------------------
// logBufHandler — slog.Handler implementation
// ---------------------------------------------------------------------------

type logBufHandler struct {
	buf   *LogBuffer
	attrs []slog.Attr
}

func (h *logBufHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *logBufHandler) Handle(_ context.Context, r slog.Record) error {
	var attrs map[string]any
	total := r.NumAttrs() + len(h.attrs)
	if total > 0 {
		attrs = make(map[string]any, total)
		for _, a := range h.attrs {
			attrs[a.Key] = fmtAttrValue(a.Value)
		}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = fmtAttrValue(a.Value)
			return true
		})
	}

	h.buf.Add(LogEntry{
		Time:    r.Time,
		Level:   levelString(r.Level),
		Message: r.Message,
		Attrs:   attrs,
	})
	return nil
}

func (h *logBufHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(combined, h.attrs)
	copy(combined[len(h.attrs):], attrs)
	return &logBufHandler{buf: h.buf, attrs: combined}
}

func (h *logBufHandler) WithGroup(name string) slog.Handler {
	// Groups are flattened; just return the same handler.
	return h
}

func levelString(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

func fmtAttrValue(v slog.Value) any {
	switch v.Kind() {
	case slog.KindBool:
		return v.Bool()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time()
	default:
		return v.String()
	}
}

// ---------------------------------------------------------------------------
// Dashboard routes (registered in registerRoutes)
// ---------------------------------------------------------------------------

// SetLogBuffer attaches a LogBuffer so that GET /api/v1/logs is served.
// Call this before Run.
func (a *APIServer) SetLogBuffer(lb *LogBuffer) {
	a.logBuf = lb
}

// registerDashboardRoutes adds the web-UI and log routes.
// It is called from registerRoutes.
func (a *APIServer) registerDashboardRoutes() {
	// Strip the "web/" prefix so requests hit "/" → index.html.
	sub, err := fs.Sub(webFiles, "web")
	if err != nil {
		a.logger.Error("dashboard: failed to sub embed.FS", "err", err)
		return
	}
	fileServer := http.FileServer(http.FS(sub))
	a.mux.Handle("GET /", fileServer)

	// Logs endpoint — always registered; returns empty array if no buffer set.
	a.mux.HandleFunc("GET /api/v1/logs", a.auth(a.handleLogs))
}

// handleLogs returns recent log entries as a JSON array.
// Query param: limit (default 200, max 1000).
func (a *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if s := r.URL.Query().Get("limit"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	if a.logBuf == nil {
		writeJSON(w, http.StatusOK, []LogEntry{})
		return
	}
	writeJSON(w, http.StatusOK, a.logBuf.Entries(limit))
}
