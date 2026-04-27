package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

func TestGenerateVLESSUUID(t *testing.T) {
	uuid, err := GenerateVLESSUUID()
	if err != nil {
		t.Fatal(err)
	}
	// version nibble must be 4
	if uuid[6]>>4 != 4 {
		t.Errorf("version nibble = %d, want 4", uuid[6]>>4)
	}
	// variant bits must be 10xxxxxx
	if uuid[8]>>6 != 2 {
		t.Errorf("variant bits = %d, want 2", uuid[8]>>6)
	}
}

func TestFormatUUID(t *testing.T) {
	uuid := [16]byte{
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xab,
		0x4c, 0xde,
		0x8f, 0x01,
		0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
	}
	got := FormatUUID(uuid)
	want := "01234567-89ab-4cde-8f01-23456789abcd"
	if got != want {
		t.Errorf("FormatUUID = %q, want %q", got, want)
	}
}

func TestParseUUID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"with dashes", "01234567-89ab-4cde-8f01-23456789abcd", "0123456789ab4cde8f0123456789abcd"},
		{"without dashes", "0123456789ab4cde8f0123456789abcd", "0123456789ab4cde8f0123456789abcd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuid, err := ParseUUID(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			got := hex.EncodeToString(uuid[:])
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseUUID_Invalid(t *testing.T) {
	tests := []string{
		"too-short",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // invalid hex
		"",
	}
	for _, input := range tests {
		if _, err := ParseUUID(input); err == nil {
			t.Errorf("ParseUUID(%q) should fail", input)
		}
	}
}

func TestVLESSParseRequest_IPv4(t *testing.T) {
	uuid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	var buf bytes.Buffer
	buf.WriteByte(VLESSVersion0)  // version
	buf.Write(uuid[:])            // uuid
	buf.WriteByte(0)              // addons_len = 0
	buf.WriteByte(VLESSCmdTCP)    // command
	binary.Write(&buf, binary.BigEndian, uint16(443)) // port
	buf.WriteByte(VLESSAddrIPv4)  // addr type
	buf.Write([]byte{10, 8, 0, 1}) // ipv4

	req, err := VLESSParseRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.Version != 0 {
		t.Errorf("version = %d, want 0", req.Version)
	}
	if req.UUID != uuid {
		t.Error("uuid mismatch")
	}
	if req.Command != VLESSCmdTCP {
		t.Errorf("command = %d, want %d", req.Command, VLESSCmdTCP)
	}
	if req.Port != 443 {
		t.Errorf("port = %d, want 443", req.Port)
	}
	if req.Addr != "10.8.0.1" {
		t.Errorf("addr = %q, want %q", req.Addr, "10.8.0.1")
	}
}

func TestVLESSParseRequest_IPv6(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(VLESSVersion0)
	buf.Write(make([]byte, 16)) // uuid
	buf.WriteByte(0)            // addons_len
	buf.WriteByte(VLESSCmdTCP)
	binary.Write(&buf, binary.BigEndian, uint16(80))
	buf.WriteByte(VLESSAddrIPv6)
	// ::1
	ipv6 := make([]byte, 16)
	ipv6[15] = 1
	buf.Write(ipv6)

	req, err := VLESSParseRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.Addr != "::1" {
		t.Errorf("addr = %q, want %q", req.Addr, "::1")
	}
}

func TestVLESSParseRequest_Domain(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(VLESSVersion0)
	buf.Write(make([]byte, 16)) // uuid
	buf.WriteByte(0)            // addons_len
	buf.WriteByte(VLESSCmdTCP)
	binary.Write(&buf, binary.BigEndian, uint16(443))
	buf.WriteByte(VLESSAddrDomain)
	domain := "example.com"
	buf.WriteByte(byte(len(domain)))
	buf.WriteString(domain)

	req, err := VLESSParseRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.Addr != "example.com" {
		t.Errorf("addr = %q, want %q", req.Addr, "example.com")
	}
}

func TestVLESSParseRequest_DomainMaxLen(t *testing.T) {
	// Domain length is encoded as a single byte (max 255).
	// The stack [255]byte buffer in VLESSParseRequest must handle the full range.
	domain := make([]byte, 255)
	for i := range domain {
		domain[i] = 'a' + byte(i%26)
	}
	var buf bytes.Buffer
	buf.WriteByte(VLESSVersion0)
	buf.Write(make([]byte, 16)) // uuid
	buf.WriteByte(0)            // addons_len
	buf.WriteByte(VLESSCmdTCP)
	binary.Write(&buf, binary.BigEndian, uint16(443))
	buf.WriteByte(VLESSAddrDomain)
	buf.WriteByte(255) // max domain length
	buf.Write(domain)

	req, err := VLESSParseRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.Addr != string(domain) {
		t.Errorf("255-byte domain not parsed correctly: got len=%d, want 255", len(req.Addr))
	}
}

func TestVLESSParseRequest_WithAddons(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(VLESSVersion0)
	buf.Write(make([]byte, 16)) // uuid
	buf.WriteByte(5)            // addons_len = 5
	buf.Write([]byte{1, 2, 3, 4, 5}) // addon bytes (skipped)
	buf.WriteByte(VLESSCmdTCP)
	binary.Write(&buf, binary.BigEndian, uint16(8080))
	buf.WriteByte(VLESSAddrIPv4)
	buf.Write([]byte{192, 168, 1, 1})

	req, err := VLESSParseRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.Port != 8080 {
		t.Errorf("port = %d, want 8080", req.Port)
	}
	if req.Addr != "192.168.1.1" {
		t.Errorf("addr = %q", req.Addr)
	}
}

func TestVLESSParseRequest_UnknownAddrType(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(VLESSVersion0)
	buf.Write(make([]byte, 16))
	buf.WriteByte(0)
	buf.WriteByte(VLESSCmdTCP)
	binary.Write(&buf, binary.BigEndian, uint16(443))
	buf.WriteByte(0xFF) // unknown addr type

	_, err := VLESSParseRequest(&buf)
	if err == nil {
		t.Fatal("expected error for unknown addr type")
	}
	if !strings.Contains(err.Error(), "unknown addr type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVLESSParseRequest_TruncatedHeader(t *testing.T) {
	// Only 5 bytes — not enough for header
	_, err := VLESSParseRequest(bytes.NewReader([]byte{0, 1, 2, 3, 4}))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestVLESSWriteResponse(t *testing.T) {
	var buf bytes.Buffer
	if err := VLESSWriteResponse(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 2 {
		t.Errorf("response length = %d, want 2", buf.Len())
	}
	if buf.Bytes()[0] != VLESSVersion0 {
		t.Errorf("response version = %d, want %d", buf.Bytes()[0], VLESSVersion0)
	}
	if buf.Bytes()[1] != 0 {
		t.Errorf("response addons_len = %d, want 0", buf.Bytes()[1])
	}
}

func TestVLESSRoundTrip(t *testing.T) {
	// Simulate: client sends request → server parses → server responds
	uuid, _ := GenerateVLESSUUID()

	// Build request
	var reqBuf bytes.Buffer
	reqBuf.WriteByte(VLESSVersion0)
	reqBuf.Write(uuid[:])
	reqBuf.WriteByte(0)
	reqBuf.WriteByte(VLESSCmdTCP)
	binary.Write(&reqBuf, binary.BigEndian, uint16(443))
	reqBuf.WriteByte(VLESSAddrIPv4)
	reqBuf.Write([]byte{10, 8, 0, 1})

	// Parse
	req, err := VLESSParseRequest(&reqBuf)
	if err != nil {
		t.Fatal(err)
	}
	if req.UUID != uuid {
		t.Error("uuid mismatch in roundtrip")
	}

	// Write response
	var respBuf bytes.Buffer
	if err := VLESSWriteResponse(&respBuf); err != nil {
		t.Fatal(err)
	}

	// Verify response is minimal (2 bytes)
	resp := respBuf.Bytes()
	if len(resp) != 2 || resp[0] != 0 || resp[1] != 0 {
		t.Errorf("unexpected response: %v", resp)
	}
}

func TestUUIDUniqueness(t *testing.T) {
	seen := make(map[[16]byte]bool)
	for i := 0; i < 100; i++ {
		uuid, err := GenerateVLESSUUID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[uuid] {
			t.Fatal("duplicate UUID generated")
		}
		seen[uuid] = true
	}
}

func TestParseUUID_FormatUUID_Roundtrip(t *testing.T) {
	uuid, _ := GenerateVLESSUUID()
	str := FormatUUID(uuid)
	parsed, err := ParseUUID(str)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != uuid {
		t.Error("roundtrip failed")
	}
}

// Ensure we consume the reader fully for a valid request (no leftover bytes).
func TestVLESSParseRequest_ConsumesExactly(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(VLESSVersion0)
	buf.Write(make([]byte, 16))
	buf.WriteByte(0)
	buf.WriteByte(VLESSCmdTCP)
	binary.Write(&buf, binary.BigEndian, uint16(443))
	buf.WriteByte(VLESSAddrIPv4)
	buf.Write([]byte{1, 2, 3, 4})
	buf.WriteString("extra-payload-data") // trailing data after header

	r := bytes.NewReader(buf.Bytes())
	req, err := VLESSParseRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if req.Addr != "1.2.3.4" {
		t.Errorf("addr = %q", req.Addr)
	}
	// The reader should have "extra-payload-data" remaining
	remaining, _ := io.ReadAll(r)
	if string(remaining) != "extra-payload-data" {
		t.Errorf("remaining = %q, want %q", remaining, "extra-payload-data")
	}
}
