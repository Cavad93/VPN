package main

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// --- TLS certificate fingerprint tests ------------------------------------
//
// These tests verify that auto-generated VLESS TLS certificates do NOT contain
// "CavadVPN" in any Subject/SAN field (which would be an instant fingerprint
// for DPI systems) and that the certificate properties match common CDN/DV
// certificate conventions (90-day validity, no IP SANs, ECDSA-only KeyUsage).

// TestEnsureTLSCertNoCavadVPN verifies that the generated cert uses the
// provided domain instead of the old hardcoded "CavadVPN" string.
func TestEnsureTLSCertNoCavadVPN(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	domain := "cdn.jsdelivr.net"
	if err := ensureTLSCert(certPath, keyPath, domain, slog.Default()); err != nil {
		t.Fatalf("ensureTLSCert: %v", err)
	}

	cert := parseCertFromFile(t, certPath)

	// CN must be the provided domain.
	if got := cert.Subject.CommonName; got != domain {
		t.Errorf("CN: got %q, want %q", got, domain)
	}

	// DNS SAN must contain the provided domain.
	if len(cert.DNSNames) == 0 {
		t.Fatal("no DNS SANs in certificate")
	}
	if cert.DNSNames[0] != domain {
		t.Errorf("DNSNames[0]: got %q, want %q", cert.DNSNames[0], domain)
	}

	// MUST NOT contain "CavadVPN" anywhere in the raw certificate bytes.
	if strings.Contains(string(cert.Raw), "CavadVPN") {
		t.Error("certificate raw bytes contain 'CavadVPN' fingerprint")
	}
}

// TestEnsureTLSCertValidity90Days verifies the cert lifetime is ≤ 91 days
// (matching Let's Encrypt style) rather than the previous 10-year lifetime
// which is a strong non-web-server fingerprint.
func TestEnsureTLSCertValidity90Days(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := ensureTLSCert(certPath, keyPath, "unpkg.com", slog.Default()); err != nil {
		t.Fatalf("ensureTLSCert: %v", err)
	}
	cert := parseCertFromFile(t, certPath)

	// Validity window includes the 1-hour back-date (NotBefore = now-1h).
	const maxDays = 92 // 90 days + 1h back-date + 1 day buffer
	if got := cert.NotAfter.Sub(cert.NotBefore); got > time.Duration(maxDays)*24*time.Hour {
		t.Errorf("cert validity %v exceeds %d days (should match Let's Encrypt 90-day style)", got, maxDays)
	}
}

// TestEnsureTLSCertNoIPSANs verifies that auto-generated certs carry no IP
// SANs — real CDN / DV certificates never contain IP SANs; presence of IP
// SANs is characteristic of internal / k8s / VPN-style certificates.
func TestEnsureTLSCertNoIPSANs(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := ensureTLSCert(certPath, keyPath, "fastly.jsdelivr.net", slog.Default()); err != nil {
		t.Fatalf("ensureTLSCert: %v", err)
	}
	cert := parseCertFromFile(t, certPath)

	if len(cert.IPAddresses) != 0 {
		t.Errorf("cert has IP SANs %v; CDN certificates should not carry IP SANs", cert.IPAddresses)
	}
}

// TestEnsureTLSCertECDSAKeyUsage verifies KeyUsage is DigitalSignature only.
// ECDSA keys do not participate in RSA key exchange, so KeyEncipherment must
// NOT be set — its presence would be a minor but detectable fingerprint for
// scanners that compare KeyUsage against the key type.
func TestEnsureTLSCertECDSAKeyUsage(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := ensureTLSCert(certPath, keyPath, "cdnjs.cloudflare.com", slog.Default()); err != nil {
		t.Fatalf("ensureTLSCert: %v", err)
	}
	cert := parseCertFromFile(t, certPath)

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsageDigitalSignature must be set for ECDSA cert")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("KeyUsageKeyEncipherment must NOT be set for ECDSA cert (RSA-only flag)")
	}
}

// TestEnsureTLSCertIdempotent verifies that calling ensureTLSCert again when
// files already exist does not overwrite them (idempotent operation).
func TestEnsureTLSCertIdempotent(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := ensureTLSCert(certPath, keyPath, "cdn.jsdelivr.net", slog.Default()); err != nil {
		t.Fatalf("first call: %v", err)
	}
	original, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	// Second call: files exist, must be no-op.
	if err := ensureTLSCert(certPath, keyPath, "different.domain.com", slog.Default()); err != nil {
		t.Fatalf("second call: %v", err)
	}
	after, _ := os.ReadFile(certPath)
	if string(original) != string(after) {
		t.Error("ensureTLSCert overwrote existing cert file (should be idempotent)")
	}
}

// TestPickTLSHostnameExplicit verifies that a non-empty TLSHostname is returned as-is.
func TestPickTLSHostnameExplicit(t *testing.T) {
	cfg := VLESSConfig{TLSHostname: "my.custom.domain.example"}
	if got := pickTLSHostname(cfg); got != "my.custom.domain.example" {
		t.Errorf("pickTLSHostname: got %q, want %q", got, "my.custom.domain.example")
	}
}

// TestPickTLSHostnameFallbackIsCDN verifies that an empty TLSHostname falls
// back to a CDN domain from tlsCoverDomains and never returns "CavadVPN".
func TestPickTLSHostnameFallbackIsCDN(t *testing.T) {
	cfg := VLESSConfig{} // No TLSHostname
	got := pickTLSHostname(cfg)
	if got == "" {
		t.Fatal("pickTLSHostname returned empty string")
	}
	if got == "CavadVPN" {
		t.Fatal("pickTLSHostname must never return 'CavadVPN'")
	}
	found := false
	for _, d := range tlsCoverDomains {
		if got == d {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("pickTLSHostname returned unknown domain %q (not in tlsCoverDomains)", got)
	}
}

// --- helpers ---------------------------------------------------------------

// parseCertFromFile reads certPath, decodes the first PEM block, and parses
// the X.509 certificate. Calls t.Fatal on any error.
func parseCertFromFile(t *testing.T, certPath string) *x509.Certificate {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block found in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
