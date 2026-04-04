package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/cavad93/vpn/server/transport"
)

// VLESSConfig holds VLESS+WS+TLS listener configuration.
type VLESSConfig struct {
	// ListenAddr is the TLS listen address (e.g. "0.0.0.0:443").
	ListenAddr string
	// UUID is the VLESS authentication UUID.
	UUID [16]byte
	// WSPath is the WebSocket endpoint path (e.g. "/tunnel").
	WSPath string
	// TLSCert and TLSKey are paths to the TLS certificate and key files.
	TLSCert string
	TLSKey  string
}

// RunVLESS starts the VLESS+WS+TLS listener. Blocks until ctx is cancelled.
func (s *Server) RunVLESS(ctx context.Context, cfg VLESSConfig) error {
	// Auto-generate self-signed cert if files don't exist.
	if err := ensureTLSCert(cfg.TLSCert, cfg.TLSKey, s.logger); err != nil {
		return fmt.Errorf("vless: ensure TLS cert: %w", err)
	}

	tlsCert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("vless: load TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"}, // WS requires HTTP/1.1, no h2
	}

	ln, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("vless: listen %s: %w", cfg.ListenAddr, err)
	}

	s.logger.Info("VLESS+WS+TLS listening", "addr", cfg.ListenAddr, "path", cfg.WSPath)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Warn("vless accept error", "err", err)
				continue
			}
		}
		go s.handleVLESSConn(ctx, conn, cfg)
	}
}

// vlessActiveConns tracks active VLESS proxy connections for stats.
var vlessActiveConns atomic.Int64

// handleVLESSConn handles a single VLESS+WS connection as a TCP proxy.
// V2Ray clients use VLESS as a proxy protocol: each TCP connection from the
// phone (e.g. to google.com:443) becomes a separate VLESS request with the
// destination address. We dial the destination and relay data bidirectionally.
func (s *Server) handleVLESSConn(ctx context.Context, conn net.Conn, cfg VLESSConfig) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	// Force TLS handshake and log result
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			s.logger.Warn("vless TLS handshake failed", "err", err, "remote", remote)
			return
		}
		state := tlsConn.ConnectionState()
		s.logger.Info("vless TLS ok", "proto", state.NegotiatedProtocol, "remote", remote)
	}

	// Set a deadline for the WS upgrade + VLESS header phase
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// 1. WebSocket upgrade
	ws, err := transport.WSUpgrade(conn, cfg.WSPath)
	if err != nil {
		s.logger.Warn("vless ws upgrade failed", "err", err, "remote", remote)
		return
	}
	defer ws.Close()

	s.logger.Info("vless ws upgraded", "remote", remote)

	// 2. Parse VLESS request (contains destination addr:port)
	req, err := transport.VLESSParseRequest(ws)
	if err != nil {
		if errors.Is(err, io.EOF) {
			s.logger.Info("vless client closed after upgrade (cert rejected?)", "remote", remote)
		} else {
			s.logger.Warn("vless parse request failed", "err", err, "remote", remote)
		}
		return
	}

	// Clear handshake deadline
	conn.SetDeadline(time.Time{})

	// 3. Authenticate UUID
	if req.UUID != cfg.UUID {
		s.logger.Warn("vless auth failed", "uuid", transport.FormatUUID(req.UUID))
		return
	}

	// 4. Only support TCP proxy (V2Ray command 1)
	if req.Command != transport.VLESSCmdTCP {
		s.logger.Warn("vless unsupported command", "cmd", req.Command)
		return
	}

	// 5. Dial the destination that V2Ray client wants to reach
	dest := net.JoinHostPort(req.Addr, fmt.Sprintf("%d", req.Port))
	target, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		s.logger.Debug("vless dial failed", "dest", dest, "err", err)
		return
	}
	defer target.Close()

	// 6. Send VLESS response (version + 0 addons) — tells client we're ready
	if err := transport.VLESSWriteResponse(ws); err != nil {
		s.logger.Warn("vless write response failed", "err", err)
		return
	}

	vlessActiveConns.Add(1)
	defer vlessActiveConns.Add(-1)

	s.logger.Debug("vless relay", "dest", dest, "remote", conn.RemoteAddr())

	// 7. Forward initial payload (if any arrived with the VLESS header)
	if len(req.Payload) > 0 {
		if _, err := target.Write(req.Payload); err != nil {
			return
		}
	}

	// 8. Bidirectional relay: WS ↔ destination
	done := make(chan struct{}, 1)

	// destination → V2Ray client
	go func() {
		io.Copy(ws, target) //nolint:errcheck
		done <- struct{}{}
	}()

	// V2Ray client → destination
	io.Copy(target, ws) //nolint:errcheck

	// Wait for the other direction or context cancel
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// generateVLESSLink builds a vless:// URI for V2Ray clients.
func generateVLESSLink(uuid [16]byte, host string, port int, wsPath string) string {
	uuidStr := transport.FormatUUID(uuid)
	return fmt.Sprintf("vless://%s@%s:%d?type=ws&security=tls&allowInsecure=1&path=%s#CavadVPN",
		uuidStr, host, port, wsPath)
}

// vlessUUIDFile is the file where the VLESS UUID is persisted.
const vlessUUIDFile = "vless_uuid.txt"

// loadOrGenerateVLESSUUID loads UUID from file or generates and saves a new one.
func loadOrGenerateVLESSUUID(path string, logger *slog.Logger) ([16]byte, error) {
	data, err := readFileBytes(path)
	if err == nil && len(data) > 0 {
		uuid, err := transport.ParseUUID(string(data))
		if err == nil {
			logger.Info("loaded VLESS UUID", "uuid", transport.FormatUUID(uuid))
			return uuid, nil
		}
	}

	uuid, err := transport.GenerateVLESSUUID()
	if err != nil {
		return uuid, fmt.Errorf("generate UUID: %w", err)
	}

	if err := writeFileBytes(path, []byte(transport.FormatUUID(uuid))); err != nil {
		logger.Warn("failed to save VLESS UUID", "err", err)
	}

	logger.Info("generated new VLESS UUID", "uuid", transport.FormatUUID(uuid))
	return uuid, nil
}

// ensureTLSCert checks if cert and key files exist. If not, generates a
// self-signed ECDSA P-256 certificate valid for 10 years. This avoids the
// need for OpenSSL or PowerShell certificate generation on Windows Server.
func ensureTLSCert(certPath, keyPath string, logger *slog.Logger) error {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil {
		logger.Info("TLS cert found", "cert", certPath, "key", keyPath)
		return nil
	}

	logger.Info("generating self-signed TLS certificate", "cert", certPath, "key", keyPath)

	// Generate ECDSA P-256 key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Gather local IPs for SAN so cert validation can pass
	var ipAddrs []net.IP
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
						ipAddrs = append(ipAddrs, ipNet.IP)
					}
				}
			}
		}
	}
	ipAddrs = append(ipAddrs, net.IPv4(127, 0, 0, 1))

	// Build self-signed X.509 certificate with IP SANs
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "CavadVPN"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"CavadVPN"},
		IPAddresses:  ipAddrs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	// Write cert PEM
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	// Write key PEM
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyFile.Close()

	logger.Info("self-signed TLS certificate generated", "cert", certPath, "key", keyPath)
	return nil
}

// splitVLESSHostPort splits "host:port" for the VLESS link.
// If host is 0.0.0.0 or ::, returns empty host (user must replace with real IP).
func splitVLESSHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 443
	}
	port := 443
	fmt.Sscanf(portStr, "%d", &port)
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "YOUR_SERVER_IP"
	}
	return host, port
}

// readFileBytes reads the trimmed contents of a file.
func readFileBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Trim whitespace/newlines
	result := make([]byte, 0, len(data))
	for _, b := range data {
		if b != ' ' && b != '\n' && b != '\r' && b != '\t' {
			result = append(result, b)
		}
	}
	return result, nil
}

// writeFileBytes writes data to a file with mode 0600.
func writeFileBytes(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
