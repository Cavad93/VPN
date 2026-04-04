package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cavad93/vpn/server/perf"
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
		NextProtos:   []string{"h2", "http/1.1"},
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

// handleVLESSConn handles a single VLESS+WS connection.
func (s *Server) handleVLESSConn(ctx context.Context, conn net.Conn, cfg VLESSConfig) {
	defer conn.Close()

	// 1. WebSocket upgrade
	ws, err := transport.WSUpgrade(conn, cfg.WSPath)
	if err != nil {
		s.logger.Debug("vless ws upgrade failed", "err", err)
		return
	}
	defer ws.Close()

	// 2. Parse VLESS request
	req, err := transport.VLESSParseRequest(ws)
	if err != nil {
		s.logger.Warn("vless parse request failed", "err", err)
		return
	}

	// 3. Authenticate UUID
	if req.UUID != cfg.UUID {
		s.logger.Warn("vless auth failed", "uuid", transport.FormatUUID(req.UUID))
		return
	}

	// 4. Send VLESS response (version + 0 addons)
	if err := transport.VLESSWriteResponse(ws); err != nil {
		s.logger.Warn("vless write response failed", "err", err)
		return
	}

	// 5. Allocate IP
	ip, err := s.pool.allocate()
	if err != nil {
		s.logger.Warn("vless ip allocation failed", "err", err)
		return
	}

	connCtx, cancel := context.WithCancel(ctx)
	cs := &clientSession{
		id:          s.nextSessionID(),
		rawConn:     conn,
		connectedAt: time.Now(),
		cancel:      cancel,
		assignedIP:  ip,
	}

	// Register session
	s.mu.Lock()
	s.sessions[cs.id] = cs
	s.mu.Unlock()

	packed := binary.BigEndian.Uint32(ip.To4())
	s.ipIndex.Store(packed, cs)

	if s.Perf != nil {
		s.Perf.ActiveSessions.Add(1)
		s.Perf.TotalSessions.Add(1)
	}
	s.logger.Info("vless session", "id", cs.id, "ip", ip.String())
	if s.notifSvc != nil {
		s.notifSvc.NotifySessionConnected(cs.id, ip.String())
	}

	defer func() {
		cancel()
		if s.Perf != nil {
			s.Perf.ActiveSessions.Add(-1)
		}
		s.mu.Lock()
		delete(s.sessions, cs.id)
		s.mu.Unlock()
		s.ipIndex.Delete(packed)
		s.pool.release(ip)
		s.logger.Info("vless session closed", "id", cs.id, "ip", ip.String())
		if s.notifSvc != nil {
			s.notifSvc.NotifySessionDisconnected(cs.id, ip.String())
		}
	}()

	// 6. Create a vlessWriter for the TUN→client direction and add to bond
	vw := &vlessWriter{ws: ws}
	cs.bond.add(vw)
	defer cs.bond.remove(vw)

	// 7. Bidirectional relay: WS → TUN (this goroutine) + TUN → WS (via routeFromTun/bond)
	buf := make([]byte, 65536)
	for {
		select {
		case <-connCtx.Done():
			return
		default:
		}

		n, err := ws.Read(buf)
		if err != nil {
			return
		}
		if n < 20 {
			continue // too short for IPv4
		}

		if s.Perf != nil {
			t0 := time.Now()
			s.tun.Write(buf[:n]) //nolint:errcheck
			s.Perf.TrackLatency(perf.StageTunWrite, time.Since(t0))
			s.Perf.TrackPacket(perf.StageTunWrite, n)
		} else {
			s.tun.Write(buf[:n]) //nolint:errcheck
		}
		cs.bytesIn.Add(uint64(n))
	}
}

// vlessWriter wraps a WSConn for writing IP packets from TUN to VLESS client.
// Implements dataWriter interface.
type vlessWriter struct {
	ws *transport.WSConn
	mu sync.Mutex
}

func (vw *vlessWriter) Write(p []byte) (int, error) {
	vw.mu.Lock()
	defer vw.mu.Unlock()
	return vw.ws.Write(p)
}

func (vw *vlessWriter) Close() error {
	return vw.ws.Close()
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

	// Build self-signed X.509 certificate
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "CavadVPN"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"CavadVPN"},
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
