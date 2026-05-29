package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// buildSNIExtension
// ---------------------------------------------------------------------------

func TestBuildSNIExtensionFormat(t *testing.T) {
	t.Parallel()
	host := "www.google.com"
	ext := buildSNIExtension(host)

	// extension type must be 0x0000
	if ext[0] != 0x00 || ext[1] != 0x00 {
		t.Errorf("extension type = %02x%02x, want 0000", ext[0], ext[1])
	}

	// extension data length
	extDataLen := int(binary.BigEndian.Uint16(ext[2:4]))
	if extDataLen != len(ext)-4 {
		t.Errorf("ext_data_len field %d, actual data %d", extDataLen, len(ext)-4)
	}

	// server name list length
	listLen := int(binary.BigEndian.Uint16(ext[4:6]))
	// list = name_type(1) + name_len(2) + name
	wantListLen := 1 + 2 + len(host)
	if listLen != wantListLen {
		t.Errorf("list_len = %d, want %d", listLen, wantListLen)
	}

	// name type must be 0x00 (host_name)
	if ext[6] != 0x00 {
		t.Errorf("name_type = %02x, want 0x00", ext[6])
	}

	// name length
	nameLen := int(binary.BigEndian.Uint16(ext[7:9]))
	if nameLen != len(host) {
		t.Errorf("name_len = %d, want %d", nameLen, len(host))
	}

	// name bytes
	got := string(ext[9 : 9+nameLen])
	if got != host {
		t.Errorf("name = %q, want %q", got, host)
	}
}

func TestBuildSNIExtensionTotalLength(t *testing.T) {
	t.Parallel()
	host := "example.com"
	ext := buildSNIExtension(host)
	// ext_type(2) + ext_data_len(2) + list_len(2) + name_type(1) + name_len(2) + name
	want := 2 + 2 + 2 + 1 + 2 + len(host)
	if len(ext) != want {
		t.Errorf("len(ext) = %d, want %d", len(ext), want)
	}
}

func TestBuildSNIExtensionShortDomain(t *testing.T) {
	t.Parallel()
	ext := buildSNIExtension("a.io")
	if len(ext) < 9 {
		t.Fatalf("extension too short: %d bytes", len(ext))
	}
}

func TestBuildSNIExtensionLongDomain(t *testing.T) {
	t.Parallel()
	// 63-char label is the DNS maximum
	host := strings.Repeat("a", 63) + ".example.com"
	ext := buildSNIExtension(host)
	nameLen := int(binary.BigEndian.Uint16(ext[7:9]))
	if nameLen != len(host) {
		t.Errorf("name_len = %d, want %d", nameLen, len(host))
	}
}

// ---------------------------------------------------------------------------
// buildSupportedVersionsExtension
// ---------------------------------------------------------------------------

func TestBuildSupportedVersionsExtension(t *testing.T) {
	t.Parallel()
	ext := buildSupportedVersionsExtension()

	// type = 0x002b
	if ext[0] != 0x00 || ext[1] != 0x2b {
		t.Errorf("ext type = %02x%02x, want 002b", ext[0], ext[1])
	}
	// data length = 3
	extDataLen := binary.BigEndian.Uint16(ext[2:4])
	if extDataLen != 3 {
		t.Errorf("ext_data_len = %d, want 3", extDataLen)
	}
	// version list length = 2
	if ext[4] != 0x02 {
		t.Errorf("version list len byte = %02x, want 02", ext[4])
	}
	// TLS 1.3 = 0x0304
	if ext[5] != 0x03 || ext[6] != 0x04 {
		t.Errorf("version = %02x%02x, want 0304", ext[5], ext[6])
	}
}

// ---------------------------------------------------------------------------
// buildClientHelloWithSNI
// ---------------------------------------------------------------------------

func TestBuildClientHelloWithSNIFormat(t *testing.T) {
	t.Parallel()
	hello := buildClientHelloWithSNI("www.google.com")

	// Must be a TLS handshake record
	if hello[0] != tlsRecordHandshake {
		t.Errorf("content type = %02x, want handshake %02x", hello[0], tlsRecordHandshake)
	}
	// Record version must be 0x03 0x01 (legacy TLS 1.0). Chrome and all major
	// browsers use this in the ClientHello record header for backwards
	// compatibility (RFC 8446 §5.1). Using 0x03 0x03 here is a known
	// non-browser JA3 fingerprint signal that DPI systems detect.
	if hello[1] != 0x03 || hello[2] != 0x01 {
		t.Errorf("record version = %02x%02x, want 0301 (legacy TLS 1.0 per Chrome)", hello[1], hello[2])
	}
	// First byte of handshake payload must be ClientHello type
	if hello[ObfsHeaderSize] != tlsHelloClient {
		t.Errorf("handshake type = %02x, want ClientHello %02x", hello[ObfsHeaderSize], tlsHelloClient)
	}
}

func TestBuildClientHelloWithSNIRandomness(t *testing.T) {
	t.Parallel()
	h1 := buildClientHelloWithSNI("www.cloudflare.com")
	h2 := buildClientHelloWithSNI("www.cloudflare.com")
	if bytes.Equal(h1, h2) {
		t.Fatal("two ClientHellos with same SNI should differ due to random fields")
	}
}

func TestBuildClientHelloWithSNIContainsDomain(t *testing.T) {
	t.Parallel()
	domain := "fonts.googleapis.com"
	hello := buildClientHelloWithSNI(domain)
	if !bytes.Contains(hello, []byte(domain)) {
		t.Errorf("ClientHello bytes do not contain domain %q", domain)
	}
}

func TestBuildClientHelloWithSNILarger(t *testing.T) {
	t.Parallel()
	// ClientHello with SNI should be larger than one without.
	plain := buildClientHello()
	withSNI := buildClientHelloWithSNI("www.google.com")
	if len(withSNI) <= len(plain) {
		t.Errorf("len(withSNI)=%d should exceed len(plain)=%d", len(withSNI), len(plain))
	}
}

// ---------------------------------------------------------------------------
// ExtractSNI
// ---------------------------------------------------------------------------

// makeClientHelloBody returns the raw ClientHello body (after the 4-byte
// handshake header) for a call to buildClientHelloWithSNI.
func makeClientHelloBody(t *testing.T, sni string) []byte {
	t.Helper()
	hello := buildClientHelloWithSNI(sni)
	// hello = TLS record header(5) + hs_type(1) + hs_len(3) + body
	if len(hello) < ObfsHeaderSize+4 {
		t.Fatalf("hello too short: %d", len(hello))
	}
	return hello[ObfsHeaderSize+4:]
}

func TestExtractSNIRoundtrip(t *testing.T) {
	t.Parallel()
	domains := []string{
		"www.google.com",
		"www.youtube.com",
		"example.org",
		"a.b.c.d.e",
	}
	for _, domain := range domains {
		body := makeClientHelloBody(t, domain)
		got := ExtractSNI(body)
		if got != domain {
			t.Errorf("ExtractSNI(%q) = %q, want %q", domain, got, domain)
		}
	}
}

func TestExtractSNINoExtensions(t *testing.T) {
	t.Parallel()
	// buildClientHello() produces a ClientHello without extensions or SNI.
	hello := buildClientHello()
	body := hello[ObfsHeaderSize+4:]
	got := ExtractSNI(body)
	if got != "" {
		t.Errorf("ExtractSNI on plain ClientHello = %q, want empty", got)
	}
}

func TestExtractSNITooShort(t *testing.T) {
	t.Parallel()
	// Body shorter than 35 bytes must return "".
	got := ExtractSNI([]byte{0x03, 0x03})
	if got != "" {
		t.Errorf("expected empty on short input, got %q", got)
	}
}

func TestExtractSNIEmptyBody(t *testing.T) {
	t.Parallel()
	if got := ExtractSNI(nil); got != "" {
		t.Errorf("expected empty on nil, got %q", got)
	}
	if got := ExtractSNI([]byte{}); got != "" {
		t.Errorf("expected empty on empty slice, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// StaticSNI
// ---------------------------------------------------------------------------

func TestStaticSNISelect(t *testing.T) {
	t.Parallel()
	s := &StaticSNI{Domain: "www.youtube.com"}
	for i := 0; i < 10; i++ {
		if got := s.Select(); got != "www.youtube.com" {
			t.Errorf("StaticSNI.Select() = %q, want www.youtube.com", got)
		}
	}
}

func TestStaticSNIImplementsInterface(t *testing.T) {
	t.Parallel()
	var _ SNISelector = &StaticSNI{Domain: "x.com"}
}

// ---------------------------------------------------------------------------
// RandomSNI
// ---------------------------------------------------------------------------

func TestNewRandomSNIDefaultDomains(t *testing.T) {
	t.Parallel()
	r := NewRandomSNI()
	if len(r.Domains) == 0 {
		t.Fatal("NewRandomSNI().Domains must not be empty")
	}
}

func TestRandomSNISelectFromList(t *testing.T) {
	t.Parallel()
	domains := []string{"a.com", "b.com", "c.com"}
	r := &RandomSNI{Domains: domains}

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		d := r.Select()
		found := false
		for _, allowed := range domains {
			if d == allowed {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("RandomSNI.Select() returned %q not in domain list", d)
		}
		seen[d] = true
	}
	// After 200 draws from 3 domains, we expect to have seen all of them.
	if len(seen) < len(domains) {
		t.Errorf("only %d/%d domains seen after 200 draws", len(seen), len(domains))
	}
}

func TestRandomSNISelectEmptyList(t *testing.T) {
	t.Parallel()
	r := &RandomSNI{Domains: []string{}}
	got := r.Select()
	if got == "" {
		t.Error("RandomSNI.Select() returned empty string for empty Domains list")
	}
}

func TestRandomSNIImplementsInterface(t *testing.T) {
	t.Parallel()
	var _ SNISelector = &RandomSNI{}
}

func TestNewRandomSNIDoesNotMutateDefault(t *testing.T) {
	t.Parallel()
	r1 := NewRandomSNI()
	r2 := NewRandomSNI()
	r1.Domains[0] = "changed.com"
	if r2.Domains[0] == "changed.com" {
		t.Error("NewRandomSNI should return independent copies of the domain list")
	}
}

// ---------------------------------------------------------------------------
// ObfsConn.WithSNI integration
// ---------------------------------------------------------------------------

// newObfsPairWithSNI creates a client/server pair where the client uses the
// given SNISelector.
func newObfsPairWithSNI(t *testing.T, selector SNISelector) (*ObfsConn, *ObfsConn) {
	t.Helper()
	cRaw, sRaw := net.Pipe()

	var (
		client, server *ObfsConn
		wg             sync.WaitGroup
		cErr, sErr     error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		client = NewObfsConn(cRaw).WithSNI(selector)
		cErr = client.ClientHandshake()
	}()
	go func() {
		defer wg.Done()
		server = NewObfsConn(sRaw)
		sErr = server.ServerHandshake()
	}()
	wg.Wait()

	if cErr != nil {
		t.Fatalf("ClientHandshake (SNI): %v", cErr)
	}
	if sErr != nil {
		t.Fatalf("ServerHandshake (SNI): %v", sErr)
	}
	return client, server
}

func TestWithSNIStaticHandshakeSucceeds(t *testing.T) {
	t.Parallel()
	client, server := newObfsPairWithSNI(t, &StaticSNI{Domain: "cdn.jsdelivr.net"})
	client.Close()
	server.Close()
}

func TestWithSNIRandomHandshakeSucceeds(t *testing.T) {
	t.Parallel()
	client, server := newObfsPairWithSNI(t, NewRandomSNI())
	client.Close()
	server.Close()
}

func TestWithSNIDataTransfer(t *testing.T) {
	t.Parallel()
	client, server := newObfsPairWithSNI(t, &StaticSNI{Domain: "www.cloudflare.com"})
	defer client.Close()
	defer server.Close()

	msg := []byte("hello via SNI-spoofed connection")
	go func() {
		if _, err := client.Write(msg); err != nil {
			t.Errorf("Write: %v", err)
		}
	}()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

func TestWithSNIDoesNotBreakNilSelector(t *testing.T) {
	t.Parallel()
	// WithSNI(nil) should be safe — ClientHandshake falls back to plain ClientHello.
	cRaw, sRaw := net.Pipe()
	var wg sync.WaitGroup
	var cErr, sErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		c := NewObfsConn(cRaw).WithSNI(nil)
		cErr = c.ClientHandshake()
		cRaw.Close()
	}()
	go func() {
		defer wg.Done()
		s := NewObfsConn(sRaw)
		sErr = s.ServerHandshake()
		sRaw.Close()
	}()
	wg.Wait()
	if cErr != nil {
		t.Fatalf("ClientHandshake with nil SNI: %v", cErr)
	}
	if sErr != nil {
		t.Fatalf("ServerHandshake: %v", sErr)
	}
}

func TestWithSNIClientHelloContainsDomain(t *testing.T) {
	t.Parallel()
	// Intercept the raw ClientHello to verify the domain appears on the wire.
	domain := "cdn.jsdelivr.net"
	cRaw, sRaw := net.Pipe()

	var captured []byte
	var mu sync.Mutex
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		// Read the ClientHello, then reply with a ServerHello so the client
		// handshake completes without blocking.
		buf := make([]byte, 4096)
		n, err := sRaw.Read(buf)
		if n > 0 {
			mu.Lock()
			captured = append(captured, buf[:n]...)
			mu.Unlock()
		}
		if err == nil {
			sRaw.Write(buildServerHello()) //nolint:errcheck
		}
		sRaw.Close()
	}()

	c := NewObfsConn(cRaw).WithSNI(&StaticSNI{Domain: domain})
	_ = c.ClientHandshake()
	cRaw.Close()
	<-serverDone

	mu.Lock()
	defer mu.Unlock()
	if !bytes.Contains(captured, []byte(domain)) {
		t.Errorf("domain %q not found in raw ClientHello bytes", domain)
	}
}

func TestWithSNIChaining(t *testing.T) {
	t.Parallel()
	cRaw, _ := net.Pipe()
	defer cRaw.Close()
	c := NewObfsConn(cRaw).WithSNI(&StaticSNI{Domain: "www.youtube.com"})
	if c == nil {
		t.Fatal("WithSNI must return a non-nil *ObfsConn")
	}
	if c.sniSelector == nil {
		t.Fatal("sniSelector must be set after WithSNI")
	}
}
