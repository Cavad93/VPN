package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- coverHandler unit tests -----------------------------------------------

func TestCoverIndexPage(t *testing.T) {
	h := coverHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("index status: got %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	checks := []string{
		"Pork Kitchen",
		"Slow-Roasted Pork Shoulder",
		"Pulled Pork",
		"/recipe1",
		"/recipe2",
		"/contacts",
		"/about",
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Errorf("index page missing %q", want)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type: got %q, want text/html", ct)
	}
	// No Server header — consistent with Go TLS fingerprint (no mismatch).
	if srv := rec.Header().Get("Server"); srv != "" {
		t.Errorf("Server header should be empty, got %q", srv)
	}
}

func TestCoverRecipe1Page(t *testing.T) {
	h := coverHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/recipe1", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("recipe1 status: got %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Slow-Roasted Pork Shoulder",
		"bone-in pork shoulder",
		"garlic",
		"rosemary",
		"Step 1",
		"Step 5",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("recipe1 page missing %q", want)
		}
	}
}

func TestCoverRecipe2Page(t *testing.T) {
	h := coverHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/recipe2", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("recipe2 status: got %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Pulled Pork",
		"Dry Rub",
		"smoked paprika",
		"Vinegar Sauce",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("recipe2 page missing %q", want)
		}
	}
}

func TestCoverContactsPage(t *testing.T) {
	h := coverHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/contacts", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("contacts status: got %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Contact Us",
		"porkkitchen.com",
		"Frequently Asked Questions",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("contacts page missing %q", want)
		}
	}
}

func TestCoverAboutPage(t *testing.T) {
	h := coverHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/about", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("about status: got %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"About Pork Kitchen",
		"Our Philosophy",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("about page missing %q", want)
		}
	}
}

func TestCover404Page(t *testing.T) {
	h := coverHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/nonexistent-path", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("404 status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Page Not Found") {
		t.Error("404 page missing 'Page Not Found'")
	}
	if !strings.Contains(body, "/recipe1") {
		t.Error("404 page missing link to /recipe1")
	}
}

func TestCoverAllPagesHaveNginxHeader(t *testing.T) {
	h := coverHandler()
	paths := []string{"/", "/recipe1", "/recipe2", "/contacts", "/about", "/nonexistent"}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(rec, req)
		if srv := rec.Header().Get("Server"); srv != "" {
			t.Errorf("path %s: Server should be empty, got %q", path, srv)
		}
	}
}

func TestCoverAllPagesHaveConnectionClose(t *testing.T) {
	h := coverHandler()
	paths := []string{"/", "/recipe1", "/recipe2", "/contacts", "/about"}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(rec, req)
		if conn := rec.Header().Get("Connection"); conn != "close" {
			t.Errorf("path %s: Connection=%q, want close", path, conn)
		}
	}
}

func TestCoverAllPagesHaveNavigation(t *testing.T) {
	h := coverHandler()
	paths := []string{"/", "/recipe1", "/recipe2", "/contacts", "/about"}
	navLinks := []string{"/recipe1", "/recipe2", "/contacts", "/about"}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(rec, req)
		body := rec.Body.String()
		for _, link := range navLinks {
			if !strings.Contains(body, link) {
				t.Errorf("path %s: missing nav link %s", path, link)
			}
		}
	}
}

// --- coverResponseWriter tests ---------------------------------------------

func TestCoverResponseWriterBuffersOutput(t *testing.T) {
	rw := &coverResponseWriter{header: make(http.Header)}
	rw.Header().Set("X-Test", "yes")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("hello"))

	if rw.code != http.StatusOK {
		t.Fatalf("code: got %d, want %d", rw.code, http.StatusOK)
	}
	if rw.buf.String() != "hello" {
		t.Fatalf("body: got %q, want %q", rw.buf.String(), "hello")
	}
	if rw.header.Get("X-Test") != "yes" {
		t.Fatalf("header X-Test: got %q, want %q", rw.header.Get("X-Test"), "yes")
	}
}

func TestCoverResponseWriterDefaultsToOK(t *testing.T) {
	rw := &coverResponseWriter{header: make(http.Header)}
	// WriteHeader is not called — code should remain 0 (caller checks and defaults to 200).
	rw.Write([]byte("data"))
	if rw.code != 0 {
		t.Fatalf("code should be 0 when WriteHeader not called, got %d", rw.code)
	}
}

// --- serveCoverSite integration tests --------------------------------------

func TestServeCoverSiteHTTPGet(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	go func() {
		cConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")) //nolint:errcheck
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		serveCoverSite(sConn)
	}()

	cConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(cConn)

	<-done

	if !strings.Contains(string(resp), "Pork Kitchen") {
		t.Fatalf("expected cover website content, got: %q", truncate(resp, 200))
	}
	if !strings.Contains(string(resp), "200 OK") {
		t.Fatalf("expected HTTP 200, got: %q", truncate(resp, 200))
	}
}

func TestServeCoverSiteRecipePage(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	go func() {
		cConn.Write([]byte("GET /recipe1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")) //nolint:errcheck
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		serveCoverSite(sConn)
	}()

	cConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(cConn)

	<-done

	if !strings.Contains(string(resp), "Pork Shoulder") {
		t.Fatalf("expected recipe content, got: %q", truncate(resp, 200))
	}
}

func TestServeCoverSite404(t *testing.T) {
	cConn, sConn := newLocalTCPPair(t)

	go func() {
		cConn.Write([]byte("GET /nonexistent HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")) //nolint:errcheck
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		serveCoverSite(sConn)
	}()

	cConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(cConn)

	<-done

	if !strings.Contains(string(resp), "404") {
		t.Fatalf("expected 404 response, got: %q", truncate(resp, 200))
	}
	if !strings.Contains(string(resp), "Page Not Found") {
		t.Fatalf("expected Page Not Found in body, got: %q", truncate(resp, 200))
	}
}

// --- helpers ---------------------------------------------------------------

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
