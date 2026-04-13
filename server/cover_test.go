package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
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

// --- Certificate rotation tests -----------------------------------------------

// generateTestCertWithExpiry creates a self-signed ECDSA cert with a specific
// NotAfter time and writes it to dir/cert.pem + dir/key.pem.
// Returns the cert and key paths.
func generateTestCertWithExpiry(t *testing.T, dir string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateTestCertWithExpiry: generate key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("generateTestCertWithExpiry: create cert: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	cf, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("generateTestCertWithExpiry: create cert file: %v", err)
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}) //nolint:errcheck
	cf.Close()

	keyDER, _ := x509.MarshalECPrivateKey(priv)
	kf, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("generateTestCertWithExpiry: create key file: %v", err)
	}
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}) //nolint:errcheck
	kf.Close()
	return certPath, keyPath
}

// TestCertNotAfter_ValidCert verifies that certNotAfter correctly parses the
// NotAfter field from a fresh 90-day self-signed certificate.
func TestCertNotAfter_ValidCert(t *testing.T) {
	dir := t.TempDir()
	want := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	certPath, _ := generateTestCertWithExpiry(t, dir, want)

	got := certNotAfter(certPath)
	if got.IsZero() {
		t.Fatal("certNotAfter returned zero time for a valid cert")
	}
	// Allow ±2 s for test execution time.
	diff := got.Sub(want)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("certNotAfter: got %v, want ~%v (diff %v)", got, want, diff)
	}
}

// TestCertNotAfter_MissingFile verifies that certNotAfter returns the zero
// time when the cert file does not exist.
func TestCertNotAfter_MissingFile(t *testing.T) {
	got := certNotAfter(filepath.Join(t.TempDir(), "nonexistent.pem"))
	if !got.IsZero() {
		t.Errorf("certNotAfter on missing file: got %v, want zero time", got)
	}
}

// TestCertNotAfter_InvalidPEM verifies that certNotAfter returns the zero time
// for a file that exists but contains invalid PEM data.
func TestCertNotAfter_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	os.WriteFile(path, []byte("this is not valid PEM"), 0644) //nolint:errcheck
	got := certNotAfter(path)
	if !got.IsZero() {
		t.Errorf("certNotAfter on invalid PEM: got %v, want zero time", got)
	}
}

// TestCertNeedsRotation_NewCert verifies that a freshly generated 90-day cert
// does not trigger rotation with the default 30-day threshold.
func TestCertNeedsRotation_NewCert(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := generateTestCertWithExpiry(t, dir, time.Now().Add(90*24*time.Hour))
	if certNeedsRotation(certPath, 30*24*time.Hour) {
		t.Error("certNeedsRotation: fresh 90-day cert should NOT need rotation with 30-day threshold")
	}
}

// TestCertNeedsRotation_ExpiringCert verifies that a cert expiring in 1 day
// triggers rotation with the default 30-day threshold.
func TestCertNeedsRotation_ExpiringCert(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := generateTestCertWithExpiry(t, dir, time.Now().Add(24*time.Hour))
	if !certNeedsRotation(certPath, 30*24*time.Hour) {
		t.Error("certNeedsRotation: cert expiring in 1 day SHOULD need rotation with 30-day threshold")
	}
}

// TestCertNeedsRotation_ExpiredCert verifies that an already-expired cert
// triggers rotation.
func TestCertNeedsRotation_ExpiredCert(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := generateTestCertWithExpiry(t, dir, time.Now().Add(-1*time.Hour))
	if !certNeedsRotation(certPath, 30*24*time.Hour) {
		t.Error("certNeedsRotation: expired cert SHOULD need rotation")
	}
}

// TestCertNeedsRotation_MissingFile verifies that a missing cert file triggers
// rotation (treat as "unknown → must generate").
func TestCertNeedsRotation_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.pem")
	if !certNeedsRotation(path, 30*24*time.Hour) {
		t.Error("certNeedsRotation: missing file SHOULD need rotation")
	}
}

// TestCertNeedsRotation_ExactThreshold verifies boundary behaviour: a cert
// that expires in exactly 30 days should still trigger rotation (time.Until <
// threshold, not ≤).
func TestCertNeedsRotation_ExactThreshold(t *testing.T) {
	dir := t.TempDir()
	threshold := 30 * 24 * time.Hour
	// Cert expires in threshold - 1 minute → needs rotation.
	certPath, _ := generateTestCertWithExpiry(t, dir, time.Now().Add(threshold-time.Minute))
	if !certNeedsRotation(certPath, threshold) {
		t.Error("certNeedsRotation: cert just under threshold SHOULD need rotation")
	}
}

// TestCertRotation_OldFilesDeletedAndNewCertGenerated verifies the full
// rotation cycle: when an expiring cert exists, the rotation logic removes
// the old files and generates a fresh cert with a longer lifetime.
func TestCertRotation_OldFilesDeletedAndNewCertGenerated(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Plant an expiring cert (1 day left — within 30-day threshold).
	generateTestCertWithExpiry(t, dir, time.Now().Add(24*time.Hour))
	oldNotAfter := certNotAfter(certPath)

	// Simulate what rotateCert() does: detect expiry, delete, regenerate.
	if certNeedsRotation(certPath, 30*24*time.Hour) {
		os.Remove(certPath) //nolint:errcheck
		os.Remove(keyPath)  //nolint:errcheck
	}
	if err := ensureTLSCert(certPath, keyPath, "cdn.jsdelivr.net", slog.Default()); err != nil {
		t.Fatalf("ensureTLSCert after rotation: %v", err)
	}

	newNotAfter := certNotAfter(certPath)
	if newNotAfter.IsZero() {
		t.Fatal("new cert NotAfter is zero")
	}
	if !newNotAfter.After(oldNotAfter) {
		t.Errorf("new cert NotAfter (%v) should be later than old NotAfter (%v)", newNotAfter, oldNotAfter)
	}
	// New cert should have ~90-day validity.
	remaining := time.Until(newNotAfter)
	if remaining < 89*24*time.Hour {
		t.Errorf("new cert has only %v remaining — expected ~90 days", remaining)
	}
	// New cert must not need rotation with the 30-day threshold.
	if certNeedsRotation(certPath, 30*24*time.Hour) {
		t.Error("fresh cert SHOULD NOT need rotation immediately after generation")
	}
}
