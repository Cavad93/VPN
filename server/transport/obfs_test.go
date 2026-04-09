package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
)

// newObfsPair creates two connected ObfsConns backed by net.Pipe.
// It runs the handshake concurrently and returns (client, server).
func newObfsPair(t *testing.T) (*ObfsConn, *ObfsConn) {
	t.Helper()
	cRaw, sRaw := net.Pipe()

	var (
		client *ObfsConn
		server *ObfsConn
		wg     sync.WaitGroup
		cErr   error
		sErr   error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		client = NewObfsConn(cRaw)
		cErr = client.ClientHandshake()
	}()
	go func() {
		defer wg.Done()
		server = NewObfsConn(sRaw)
		sErr = server.ServerHandshake()
	}()
	wg.Wait()

	if cErr != nil {
		t.Fatalf("ClientHandshake: %v", cErr)
	}
	if sErr != nil {
		t.Fatalf("ServerHandshake: %v", sErr)
	}
	return client, server
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

func TestObfsHandshakeSucceeds(t *testing.T) {
	t.Parallel()
	client, server := newObfsPair(t)
	client.Close()
	server.Close()
}

func TestObfsHandshakeWrongMessageType(t *testing.T) {
	t.Parallel()
	// Server sends a ClientHello instead of a ServerHello — client must reject it.
	cRaw, sRaw := net.Pipe()

	go func() {
		// Drain the client's ClientHello first, then reply with the wrong type.
		hdr := make([]byte, ObfsHeaderSize)
		if _, err := io.ReadFull(sRaw, hdr); err != nil {
			sRaw.Close()
			return
		}
		length := binary.BigEndian.Uint16(hdr[3:5])
		body := make([]byte, length)
		io.ReadFull(sRaw, body) //nolint:errcheck
		// Send ClientHello (wrong: client expects ServerHello).
		sRaw.Write(buildClientHello()) //nolint:errcheck
		sRaw.Close()
	}()

	client := NewObfsConn(cRaw)
	err := client.ClientHandshake()
	if err == nil {
		t.Fatal("expected error when receiving wrong handshake message type")
	}
	cRaw.Close()
}

func TestObfsHandshakeTruncatedRecord(t *testing.T) {
	t.Parallel()
	cRaw, sRaw := net.Pipe()

	go func() {
		// Drain the client's ClientHello first, then send a truncated record.
		hdr := make([]byte, ObfsHeaderSize)
		if _, err := io.ReadFull(sRaw, hdr); err != nil {
			sRaw.Close()
			return
		}
		length := binary.BigEndian.Uint16(hdr[3:5])
		body := make([]byte, length)
		io.ReadFull(sRaw, body) //nolint:errcheck
		// Write only the TLS record header with no body — client expects body bytes.
		truncated := []byte{tlsRecordHandshake, tlsVersionMajor, tlsVersionMinor, 0x00, 0x10}
		sRaw.Write(truncated) //nolint:errcheck
		sRaw.Close()
	}()

	client := NewObfsConn(cRaw)
	err := client.ClientHandshake()
	if err == nil {
		t.Fatal("expected error on truncated record body")
	}
	cRaw.Close()
}

// ---------------------------------------------------------------------------
// Write / Read roundtrip
// ---------------------------------------------------------------------------

func TestObfsWriteReadSmall(t *testing.T) {
	t.Parallel()
	client, server := newObfsPair(t)
	defer client.Close()
	defer server.Close()

	msg := []byte("hello obfs")
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

func TestObfsWriteReadBidirectional(t *testing.T) {
	t.Parallel()
	client, server := newObfsPair(t)
	defer client.Close()
	defer server.Close()

	ping := []byte("ping")
	pong := []byte("pong")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := client.Write(ping); err != nil {
			t.Errorf("client Write: %v", err)
		}
		buf := make([]byte, len(pong))
		if _, err := io.ReadFull(client, buf); err != nil {
			t.Errorf("client Read: %v", err)
		}
		if !bytes.Equal(buf, pong) {
			t.Errorf("client received %q, want %q", buf, pong)
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, len(ping))
		if _, err := io.ReadFull(server, buf); err != nil {
			t.Errorf("server Read: %v", err)
		}
		if !bytes.Equal(buf, ping) {
			t.Errorf("server received %q, want %q", buf, ping)
		}
		if _, err := server.Write(pong); err != nil {
			t.Errorf("server Write: %v", err)
		}
	}()

	wg.Wait()
}

func TestObfsWriteReadLargePayload(t *testing.T) {
	t.Parallel()
	// 48 KB — forces multiple 16383-byte records.
	client, server := newObfsPair(t)
	defer client.Close()
	defer server.Close()

	data := make([]byte, 48*1024)
	for i := range data {
		data[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := client.Write(data); err != nil {
			t.Errorf("Write: %v", err)
		}
	}()

	received := make([]byte, len(data))
	if _, err := io.ReadFull(server, received); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(received, data) {
		t.Fatal("large payload mismatch")
	}
	wg.Wait()
}

func TestObfsReadBuffering(t *testing.T) {
	t.Parallel()
	// Send one 10-byte record; read it back in 2-byte chunks to exercise partial-record draining.
	client, server := newObfsPair(t)
	defer client.Close()
	defer server.Close()

	msg := []byte("0123456789")
	go func() {
		if _, err := client.Write(msg); err != nil {
			t.Errorf("Write: %v", err)
		}
	}()

	var got []byte
	buf := make([]byte, 2)
	for len(got) < len(msg) {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// ---------------------------------------------------------------------------
// Wire-format checks
// ---------------------------------------------------------------------------

func TestObfsAppDataRecordFormat(t *testing.T) {
	t.Parallel()
	payload := []byte("test payload")
	rec := buildAppDataRecord(payload)

	if len(rec) != ObfsHeaderSize+len(payload) {
		t.Fatalf("record length %d, want %d", len(rec), ObfsHeaderSize+len(payload))
	}
	if rec[0] != tlsRecordAppData {
		t.Errorf("content type %02x, want %02x", rec[0], tlsRecordAppData)
	}
	if rec[1] != tlsVersionMajor || rec[2] != tlsVersionMinor {
		t.Errorf("version %02x %02x, want %02x %02x", rec[1], rec[2], tlsVersionMajor, tlsVersionMinor)
	}
	length := binary.BigEndian.Uint16(rec[3:5])
	if int(length) != len(payload) {
		t.Errorf("length field %d, want %d", length, len(payload))
	}
	if !bytes.Equal(rec[5:], payload) {
		t.Errorf("payload mismatch")
	}
}

func TestObfsClientHelloFormat(t *testing.T) {
	t.Parallel()
	hello := buildClientHello()

	// Must be a handshake record.
	if hello[0] != tlsRecordHandshake {
		t.Errorf("content type %02x, want handshake %02x", hello[0], tlsRecordHandshake)
	}
	// First byte of handshake payload must be ClientHello type.
	if hello[ObfsHeaderSize] != tlsHelloClient {
		t.Errorf("handshake type %02x, want ClientHello %02x", hello[ObfsHeaderSize], tlsHelloClient)
	}
}

func TestObfsServerHelloFormat(t *testing.T) {
	t.Parallel()
	hello := buildServerHello()

	if hello[0] != tlsRecordHandshake {
		t.Errorf("content type %02x, want handshake %02x", hello[0], tlsRecordHandshake)
	}
	if hello[ObfsHeaderSize] != tlsHelloServer {
		t.Errorf("handshake type %02x, want ServerHello %02x", hello[ObfsHeaderSize], tlsHelloServer)
	}
}

func TestObfsClientHelloRandomness(t *testing.T) {
	t.Parallel()
	// Two ClientHellos must differ (random fields).
	h1 := buildClientHello()
	h2 := buildClientHello()
	if bytes.Equal(h1, h2) {
		t.Fatal("ClientHello bytes should differ between calls (random fields)")
	}
}

func TestObfsServerHelloRandomness(t *testing.T) {
	t.Parallel()
	h1 := buildServerHello()
	h2 := buildServerHello()
	if bytes.Equal(h1, h2) {
		t.Fatal("ServerHello bytes should differ between calls (random fields)")
	}
}

func TestObfsClientHelloWithSNIContainsSNI(t *testing.T) {
	t.Parallel()
	// buildClientHelloWithSNI (from sni.go) must embed the SNI extension (type 0x0000).
	hello := buildClientHelloWithSNI("www.youtube.com")
	if len(hello) < ObfsHeaderSize+4 {
		t.Fatalf("ClientHello too short: %d bytes", len(hello))
	}
	// Search for the SNI extension type bytes 0x00 0x00 in the record.
	found := false
	for i := 0; i+1 < len(hello); i++ {
		if hello[i] == 0x00 && hello[i+1] == 0x00 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("SNI extension type 0x0000 not found in ClientHello with SNI")
	}
}

func TestObfsBuildSNIExtension(t *testing.T) {
	t.Parallel()
	// buildSNIExtension is defined in sni.go.
	hostname := "www.youtube.com"
	ext := buildSNIExtension(hostname)

	// Extension type must be 0x0000 (SNI).
	if ext[0] != 0x00 || ext[1] != 0x00 {
		t.Errorf("SNI extension type %02x%02x, want 0000", ext[0], ext[1])
	}
	// The hostname bytes must appear in the extension.
	if !bytes.Contains(ext, []byte(hostname)) {
		t.Errorf("hostname %q not found in SNI extension", hostname)
	}
}

func TestObfsDifferentSNIDomainsDifferentHellos(t *testing.T) {
	t.Parallel()
	// ClientHellos with different SNIs must produce different on-wire bytes.
	h1 := buildClientHelloWithSNI("www.youtube.com")
	h2 := buildClientHelloWithSNI("www.cloudflare.com")
	// The domain names are different lengths so the records must differ.
	if bytes.Equal(h1, h2) {
		t.Fatal("ClientHellos with different SNI domains should differ")
	}
}

func TestObfsWithSNIHandshake(t *testing.T) {
	t.Parallel()
	// Verify that ObfsConn.WithSNI produces a ClientHello that the server
	// accepts — i.e. the SNI-enhanced hello is backward-compatible.
	cRaw, sRaw := net.Pipe()

	var (
		cErr error
		sErr error
		wg   sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		client := NewObfsConn(cRaw).WithSNI(NewRandomSNI())
		cErr = client.ClientHandshake()
		client.Close()
	}()
	go func() {
		defer wg.Done()
		server := NewObfsConn(sRaw)
		sErr = server.ServerHandshake()
		server.Close()
	}()
	wg.Wait()

	if cErr != nil {
		t.Fatalf("client WithSNI ClientHandshake: %v", cErr)
	}
	if sErr != nil {
		t.Fatalf("server ServerHandshake: %v", sErr)
	}
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestObfsReadWrongContentType(t *testing.T) {
	t.Parallel()
	cRaw, sRaw := net.Pipe()
	defer cRaw.Close()

	go func() {
		// Send a handshake record where an app_data record is expected.
		rec := []byte{tlsRecordHandshake, tlsVersionMajor, tlsVersionMinor, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}
		sRaw.Write(rec)
		sRaw.Close()
	}()

	conn := NewObfsConn(cRaw)
	buf := make([]byte, 10)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected error on wrong content type for Read")
	}
}

func TestObfsReadZeroLengthRecord(t *testing.T) {
	t.Parallel()
	cRaw, sRaw := net.Pipe()
	defer cRaw.Close()

	go func() {
		// Send a record with length=0, which is invalid.
		rec := []byte{tlsRecordAppData, tlsVersionMajor, tlsVersionMinor, 0x00, 0x00}
		sRaw.Write(rec)
		sRaw.Close()
	}()

	conn := NewObfsConn(cRaw)
	buf := make([]byte, 10)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected error on zero-length record")
	}
}

func TestObfsReadEOF(t *testing.T) {
	t.Parallel()
	cRaw, sRaw := net.Pipe()
	sRaw.Close() // immediate EOF

	conn := NewObfsConn(cRaw)
	buf := make([]byte, 10)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected error on closed connection")
	}
	cRaw.Close()
}

// ---------------------------------------------------------------------------
// ChangeCipherSpec (CCS) — TLS 1.3 middlebox compatibility
// ---------------------------------------------------------------------------

func TestObfsBuildChangeCipherSpec(t *testing.T) {
	t.Parallel()
	ccs := buildChangeCipherSpec()
	expected := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	if !bytes.Equal(ccs, expected) {
		t.Fatalf("CCS record mismatch:\n  got:  %x\n  want: %x", ccs, expected)
	}
}

func TestObfsServerHandshakeSendsCCS(t *testing.T) {
	// Verify that ServerHandshake sends ServerHello + CCS.
	// We manually read the raw wire output to check for the CCS record.
	t.Parallel()

	cRaw, sRaw := net.Pipe()
	defer cRaw.Close()
	defer sRaw.Close()

	// Server runs handshake in background.
	var sErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		server := NewObfsConn(sRaw)
		sErr = server.ServerHandshake()
	}()

	// Client: send a valid ClientHello first.
	clientHello := buildClientHello()
	if _, err := cRaw.Write(clientHello); err != nil {
		t.Fatal(err)
	}

	// Read raw output from server.
	rawBuf := make([]byte, 4096)
	n, err := cRaw.Read(rawBuf)
	if err != nil {
		t.Fatalf("read server response: %v", err)
	}

	<-done
	if sErr != nil {
		t.Fatalf("ServerHandshake: %v", sErr)
	}

	// Parse: first record should be ServerHello (0x16), second should be CCS (0x14).
	offset := 0
	// Record 1: ServerHello
	if rawBuf[offset] != 0x16 {
		t.Fatalf("first record type: got 0x%02x, want 0x16", rawBuf[offset])
	}
	shLen := int(rawBuf[offset+3])<<8 | int(rawBuf[offset+4])
	offset += 5 + shLen

	// Record 2: CCS
	if offset >= n {
		t.Fatal("no CCS record found after ServerHello")
	}
	if rawBuf[offset] != 0x14 {
		t.Fatalf("second record type: got 0x%02x, want 0x14 (CCS)", rawBuf[offset])
	}
	ccsLen := int(rawBuf[offset+3])<<8 | int(rawBuf[offset+4])
	if ccsLen != 1 {
		t.Fatalf("CCS payload length: got %d, want 1", ccsLen)
	}
	if rawBuf[offset+5] != 0x01 {
		t.Fatalf("CCS payload: got 0x%02x, want 0x01", rawBuf[offset+5])
	}
}

func TestObfsClientHandshakeSkipsCCS(t *testing.T) {
	// Verify that ClientHandshake successfully handles a ServerHello + CCS.
	// This tests the readRecord CCS-skip logic end-to-end.
	t.Parallel()

	client, server := newObfsPair(t)
	defer client.Close()
	defer server.Close()

	// If we get here without error, CCS was handled correctly.
	// Send data through to verify the connection still works.
	testData := []byte("hello after CCS handshake")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		client.Write(testData)
	}()

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("read after handshake: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(buf, testData) {
		t.Fatalf("data mismatch: got %q, want %q", buf, testData)
	}
}

func TestObfsReadRecordSkipsCCSMidStream(t *testing.T) {
	// Verify that readRecord skips CCS records even if they appear between
	// other records (defensive coding — shouldn't happen in practice but the
	// code should handle it gracefully).
	t.Parallel()

	cRaw, sRaw := net.Pipe()
	defer cRaw.Close()
	defer sRaw.Close()

	conn := NewObfsConn(cRaw)

	// Feed: CCS record + ServerHello record on sRaw.
	go func() {
		// CCS
		sRaw.Write([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01})
		// ServerHello (minimal valid record)
		body := make([]byte, 36)
		body[0] = 0x02 // ServerHello msg type
		body[1] = 0x00
		body[2] = 0x00
		body[3] = 0x20 // 32 bytes body
		rec := make([]byte, 5+len(body))
		rec[0] = 0x16
		rec[1] = 0x03
		rec[2] = 0x03
		rec[3] = byte(len(body) >> 8)
		rec[4] = byte(len(body))
		copy(rec[5:], body)
		sRaw.Write(rec)
	}()

	// readHandshakeRecord should skip the CCS and return ServerHello.
	err := conn.readHandshakeRecord(tlsHelloServer)
	if err != nil {
		t.Fatalf("readHandshakeRecord should skip CCS: %v", err)
	}
}
