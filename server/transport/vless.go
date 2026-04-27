// Package transport — VLESS protocol implementation.
//
// VLESS is a lightweight proxy protocol used by V2Ray/Xray clients.
// This implements the server side: parse client requests and send responses.
//
// Wire format (client → server, first message only):
//
//	version(1) + uuid(16) + addons_len(1) + [addons] + command(1)
//	+ port(2, BE) + addr_type(1) + addr(variable) + payload...
//
// Wire format (server → client, first message only):
//
//	version(1) + addons_len(1)
//
// After the initial exchange, data flows raw (no framing).
package transport

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
)

// VLESS protocol constants.
const (
	VLESSVersion0 = 0

	VLESSCmdTCP = 1 // TCP proxy (what we use for VPN tunneling)
	VLESSCmdUDP = 2 // UDP proxy
	VLESSCmdMux = 3 // Mux (not used)

	VLESSAddrIPv4   = 1 // 4 bytes
	VLESSAddrDomain = 2 // 1-byte length + domain string
	VLESSAddrIPv6   = 3 // 16 bytes
)

// VLESSRequest is a parsed VLESS client request header.
type VLESSRequest struct {
	Version  byte
	UUID     [16]byte
	Command  byte
	Port     uint16
	AddrType byte
	Addr     string // IPv4/IPv6 string or domain name
	// Payload that arrived in the same read as the header (may be empty).
	Payload []byte
}

// VLESSParseRequest reads and parses a VLESS request from the reader.
// Any bytes after the header in the initial read are returned as req.Payload.
func VLESSParseRequest(r io.Reader) (*VLESSRequest, error) {
	// Read version(1) + uuid(16) + addons_len(1) = 18 bytes minimum header
	var hdr [18]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("vless: read header: %w", err)
	}

	req := &VLESSRequest{
		Version: hdr[0],
	}
	copy(req.UUID[:], hdr[1:17])
	addonsLen := int(hdr[17])

	// Skip addons (we don't use them but must consume the bytes).
	// addons_len is a single byte so max 255 — use a stack buffer to avoid heap alloc.
	if addonsLen > 0 {
		var scratch [255]byte
		if _, err := io.ReadFull(r, scratch[:addonsLen]); err != nil {
			return nil, fmt.Errorf("vless: read addons: %w", err)
		}
	}

	// command(1) + port(2) + addr_type(1) = 4 bytes
	var cmdPortType [4]byte
	if _, err := io.ReadFull(r, cmdPortType[:]); err != nil {
		return nil, fmt.Errorf("vless: read cmd/port/type: %w", err)
	}
	req.Command = cmdPortType[0]
	req.Port = binary.BigEndian.Uint16(cmdPortType[1:3])
	req.AddrType = cmdPortType[3]

	// Read address based on type
	switch req.AddrType {
	case VLESSAddrIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, fmt.Errorf("vless: read ipv4: %w", err)
		}
		req.Addr = net.IP(ip[:]).String()
	case VLESSAddrIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, fmt.Errorf("vless: read ipv6: %w", err)
		}
		req.Addr = net.IP(ip[:]).String()
	case VLESSAddrDomain:
		var domLen [1]byte
		if _, err := io.ReadFull(r, domLen[:]); err != nil {
			return nil, fmt.Errorf("vless: read domain len: %w", err)
		}
		dom := make([]byte, domLen[0])
		if _, err := io.ReadFull(r, dom); err != nil {
			return nil, fmt.Errorf("vless: read domain: %w", err)
		}
		req.Addr = string(dom)
	default:
		return nil, fmt.Errorf("vless: unknown addr type 0x%02x", req.AddrType)
	}

	return req, nil
}

// VLESSWriteResponse writes the server response header (version + 0 addons).
func VLESSWriteResponse(w io.Writer) error {
	_, err := w.Write([]byte{VLESSVersion0, 0x00})
	return err
}

// GenerateVLESSUUID creates a random UUID for VLESS authentication.
func GenerateVLESSUUID() ([16]byte, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return uuid, err
	}
	// Set version 4 (random) and variant 1 (RFC 4122)
	uuid[6] = (uuid[6] & 0x0F) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3F) | 0x80 // variant 1
	return uuid, nil
}

// FormatUUID returns the standard UUID string representation.
// Uses a stack-allocated [36]byte buffer — 1 heap alloc (string conversion) vs 6 previously.
func FormatUUID(uuid [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], uuid[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], uuid[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], uuid[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], uuid[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], uuid[10:16])
	return string(buf[:])
}

// ParseUUID parses a UUID string (with or without dashes) into 16 bytes.
// Uses a stack-allocated [32]byte hex buffer — O(n) single pass, zero heap allocs.
func ParseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	var hexBuf [32]byte
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			if n >= 32 {
				return uuid, errors.New("vless: UUID too long")
			}
			hexBuf[n] = s[i]
			n++
		}
	}
	if n != 32 {
		return uuid, errors.New("vless: invalid UUID length")
	}
	if _, err := hex.Decode(uuid[:], hexBuf[:]); err != nil {
		return uuid, fmt.Errorf("vless: invalid UUID hex: %w", err)
	}
	return uuid, nil
}
