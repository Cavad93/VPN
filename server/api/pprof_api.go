package api

// pprof_api.go — exposes Go runtime profiling endpoints on the management API.
//
// All /debug/pprof/* routes are protected by the same Bearer-token auth used
// by every other non-health endpoint.  The API server already listens on
// loopback (127.0.0.1:8080), so these endpoints are not reachable from the
// public internet.  Adding auth on top gives defence-in-depth (e.g. shared
// hosting or container environments where loopback is shared).
//
// Usage:
//
//	# CPU profile — 30 s sample
//	curl -s -H "Authorization: Bearer $TOKEN" \
//	     "http://127.0.0.1:8080/debug/pprof/profile?seconds=30" -o cpu.prof
//	go tool pprof cpu.prof
//
//	# Heap snapshot
//	curl -s -H "Authorization: Bearer $TOKEN" \
//	     "http://127.0.0.1:8080/debug/pprof/heap" -o heap.prof
//	go tool pprof heap.prof
//
//	# Goroutine dump
//	curl -s -H "Authorization: Bearer $TOKEN" \
//	     "http://127.0.0.1:8080/debug/pprof/goroutine?debug=1"
//
//	# Allocation trace — 5 s
//	curl -s -H "Authorization: Bearer $TOKEN" \
//	     "http://127.0.0.1:8080/debug/pprof/trace?seconds=5" -o trace.out
//	go tool trace trace.out
//
//	# Index page (lists all profiles)
//	curl -s -H "Authorization: Bearer $TOKEN" \
//	     "http://127.0.0.1:8080/debug/pprof/"

import (
	"net/http"
	// Blank import registers handlers with http.DefaultServeMux; we proxy them
	// through our own mux wrapped in auth middleware.
	_ "net/http/pprof"
)

// RegisterPprofRoutes attaches all standard Go pprof endpoints to the API
// server's mux, each behind the same Bearer-token auth used elsewhere.
//
// Routes registered:
//
//	GET /debug/pprof/             — index of available profiles
//	GET /debug/pprof/cmdline      — process command line
//	GET /debug/pprof/profile      — CPU profile (?seconds=N, default 30)
//	GET /debug/pprof/symbol       — symbol lookup for addresses
//	GET /debug/pprof/trace        — execution trace (?seconds=N, default 1)
//	GET /debug/pprof/{name}       — named runtime profile (heap, goroutine, …)
func (a *APIServer) RegisterPprofRoutes() {
	// http.DefaultServeMux already has the pprof handlers thanks to the blank
	// import above.  We forward each request there after checking auth.
	proxy := func(w http.ResponseWriter, r *http.Request) {
		http.DefaultServeMux.ServeHTTP(w, r)
	}

	authed := a.auth(proxy)

	// Explicit named routes first (Go 1.22 pattern router requires exact paths
	// for non-wildcard matching — the trailing-slash catch-all below handles
	// sub-paths like /debug/pprof/heap).
	// Explicit routes for endpoints that need additional method coverage.
	// POST /symbol is used by `go tool pprof` for bulk symbol resolution.
	a.mux.HandleFunc("POST /debug/pprof/symbol", authed)

	// Catch-all for the index (/debug/pprof/) and all named profiles
	// (/debug/pprof/cmdline, /debug/pprof/heap, /debug/pprof/goroutine,
	// /debug/pprof/profile, /debug/pprof/symbol GET, /debug/pprof/trace, …).
	// Must use a method-qualified pattern ("GET /…") to avoid conflicting
	// with the dashboard "GET /" catch-all registered in dashboard.go.
	a.mux.HandleFunc("GET /debug/pprof/", authed)
}
