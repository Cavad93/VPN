package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cavad93/vpn/server/transport"
)

// vlessUDPRespPool pools 65538-byte buffers used in vlessUDPRelay to combine
// the 2-byte length prefix with the UDP payload into a single Write call,
// avoiding the 2-TLS-record overhead of separate header and data writes.
var vlessUDPRespPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2+65536) // 2-byte BE length + max UDP payload
		return &b
	},
}

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
	// TLSHostname is the domain name to embed in the auto-generated self-signed
	// certificate's CN and SAN fields.  If empty, a random CDN hostname from
	// tlsCoverDomains is chosen so the certificate does not fingerprint as a VPN
	// server.  Set to your real domain when using a proper CA-signed certificate.
	TLSHostname string
}

// tlsCoverDomains is a curated pool of CDN hostnames used for the Subject CN
// and SAN of auto-generated self-signed certificates.
//
// Using a CDN-style domain prevents passive fingerprinting: an adversary
// reading the certificate Subject would see a plausible CDN hostname rather
// than a string like "CavadVPN" that immediately identifies the service.
//
// These are NOT used to spoof a real CA chain — the certificate remains
// self-signed and clients must set allowInsecure=1.  The pool is only for
// metadata blending against passive TLS fingerprinting tools (JA3, p0f, etc.).
var tlsCoverDomains = []string{
	"cdn.jsdelivr.net",
	"cdnjs.cloudflare.com",
	"unpkg.com",
	"cdn.statically.io",
	"assets-cdn.github.com",
	"fastly.jsdelivr.net",
	"cdn.bootcdn.net",
}

// pickTLSHostname returns cfg.TLSHostname if set, otherwise selects a random
// entry from tlsCoverDomains.  The result is always a non-empty string.
func pickTLSHostname(cfg VLESSConfig) string {
	if cfg.TLSHostname != "" {
		return cfg.TLSHostname
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(tlsCoverDomains))))
	if err != nil {
		return tlsCoverDomains[0] // fallback on rand failure (should never happen)
	}
	return tlsCoverDomains[n.Int64()]
}

// tlsCertCheckInterval is how often the VLESS listener polls the on-disk cert
// for expiry.  Default 24 h; overridden in tests to a shorter duration.
var tlsCertCheckInterval = 24 * time.Hour

// tlsCertRenewBefore is how far before expiry we start rotating the cert.
// 30 days matches Certbot / ACME client convention ("renew at 60 days,
// expire at 90 days" → 30-day window for retries if generation fails).
var tlsCertRenewBefore = 30 * 24 * time.Hour

// certNotAfter returns the NotAfter timestamp of the first PEM certificate
// block in certPath.  Returns the zero time on any error (missing file,
// corrupt PEM, unparsable DER) so callers can treat the result as
// "unknown → must rotate".
func certNotAfter(certPath string) time.Time {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return cert.NotAfter
}

// certNeedsRotation returns true when the certificate at certPath is missing,
// unreadable, or will expire within renewBefore.
//
// This mirrors the "renew 30 days before expiry" heuristic used by Certbot
// and other ACME clients: starting rotation early leaves time to retry if
// generation fails (e.g. disk full, permissions).
func certNeedsRotation(certPath string, renewBefore time.Duration) bool {
	notAfter := certNotAfter(certPath)
	if notAfter.IsZero() {
		return true // can't read → treat as missing
	}
	return time.Until(notAfter) < renewBefore
}

// RunVLESS starts the VLESS+WS+TLS listener. Blocks until ctx is cancelled.
//
// Certificate lifecycle:
//   - On startup, generates a self-signed cert if none exists.
//   - A background goroutine checks the cert every tlsCertCheckInterval.
//   - When the cert is within tlsCertRenewBefore of expiry the files are
//     deleted and a fresh cert is generated.
//   - The new cert is hot-swapped via atomic.Pointer so in-flight TLS
//     handshakes complete with the old cert while new connections use the
//     new one — no listener restart required.
func (s *Server) RunVLESS(ctx context.Context, cfg VLESSConfig) error {
	domain := pickTLSHostname(cfg)

	// rotateCert regenerates the cert files if they need rotation, then loads
	// and returns the *tls.Certificate.  Safe to call concurrently because
	// ensureTLSCert is called only after the old files are removed.
	rotateCert := func() (*tls.Certificate, error) {
		if certNeedsRotation(cfg.TLSCert, tlsCertRenewBefore) {
			s.logger.Info("rotating TLS cert", "cert", cfg.TLSCert, "key", cfg.TLSKey)
			_ = os.Remove(cfg.TLSCert)
			_ = os.Remove(cfg.TLSKey)
		}
		if err := ensureTLSCert(cfg.TLSCert, cfg.TLSKey, domain, s.logger); err != nil {
			return nil, fmt.Errorf("vless: ensure TLS cert: %w", err)
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("vless: load TLS cert: %w", err)
		}
		return &cert, nil
	}

	// Initial cert: generate if missing, load.
	cert, err := rotateCert()
	if err != nil {
		return err
	}

	// currentCert is atomically swapped during background rotation.
	// GetCertificate is called on every TLS handshake — atomic.Load() is O(1)
	// and contention-free.
	var currentCert atomic.Pointer[tls.Certificate]
	currentCert.Store(cert)

	tlsConfig := &tls.Config{
		// GetCertificate replaces a static Certificates slice so that rotated
		// certs are picked up without restarting the listener.  It is called
		// for every handshake because Certificates is left empty.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return currentCert.Load(), nil
		},
		MinVersion: tls.VersionTLS12,
		// Only http/1.1 — VLESS/WS requires HTTP/1.1 for WebSocket upgrade.
		// Advertising h2 causes "unexpected SETTINGS frame" errors because
		// our handler speaks HTTP/1.1 but clients negotiate h2.
		NextProtos:       []string{"http/1.1"},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	}

	ln, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("vless: listen %s: %w", cfg.ListenAddr, err)
	}

	s.logger.Info("VLESS+TLS listening (auto-detect: raw TCP or WebSocket)", "addr", cfg.ListenAddr, "path", cfg.WSPath)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Background rotation loop: check expiry every tlsCertCheckInterval.
	// When the cert is within tlsCertRenewBefore of expiry, regenerate and
	// hot-swap via atomic.Pointer — zero downtime for active connections.
	go func() {
		ticker := time.NewTicker(tlsCertCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !certNeedsRotation(cfg.TLSCert, tlsCertRenewBefore) {
					continue
				}
				s.logger.Info("TLS cert expiring soon, rotating", "cert", cfg.TLSCert)
				newCert, err := rotateCert()
				if err != nil {
					s.logger.Error("TLS cert rotation failed", "err", err)
					continue // retry on next tick
				}
				currentCert.Store(newCert)
				s.logger.Info("TLS cert rotated and hot-swapped", "cert", cfg.TLSCert)
			}
		}
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
		setConnTTL64(conn) // Anti-fingerprint: TTL=64 on Windows
		go s.handleVLESSConn(ctx, conn, cfg)
	}
}

// vlessActiveConns tracks active VLESS proxy connections for stats.
var vlessActiveConns atomic.Int64

// handleVLESSConn handles a single VLESS connection as a TCP proxy.
// Auto-detects protocol: if first byte is 0x00 (VLESS version), uses raw TCP.
// If first bytes look like HTTP (GET/POST), does WebSocket upgrade first.
// V2Ray clients use VLESS as a proxy protocol: each TCP connection from the
// phone becomes a separate VLESS request with destination address.
func (s *Server) handleVLESSConn(ctx context.Context, conn net.Conn, cfg VLESSConfig) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	// Force TLS handshake — silent close on failure (no info leakage to probes).
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			s.logger.Debug("vless TLS handshake failed", "err", err, "remote", remote)
			return
		}
	}

	// Set a deadline for the handshake phase
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Peek first byte to auto-detect protocol
	br := bufio.NewReaderSize(conn, 4096)
	first, err := br.Peek(1)
	if err != nil {
		s.logger.Debug("vless peek failed", "err", err, "remote", remote)
		return
	}

	// Choose reader: raw VLESS over TLS or VLESS over WebSocket
	var reader io.Reader
	var writer io.Writer
	var closer func()

	if first[0] == 0x00 {
		// Raw VLESS: first byte is version 0
		s.logger.Debug("vless raw TCP", "remote", remote)
		reader = br
		writer = conn
		closer = func() {}
	} else if first[0] == 'G' || first[0] == 'P' || first[0] == 'H' {
		// HTTP-like: parse request first, then check for WebSocket upgrade.
		// Must parse before WSUpgrade because WSUpgrade consumes the request
		// from the reader — if it fails, the request is gone and cover site
		// gets an empty buffer (→ 400 Bad Request).
		httpReq, err := http.ReadRequest(br)
		if err != nil {
			s.logger.Debug("vless http parse failed", "remote", remote)
			return
		}
		defer httpReq.Body.Close()

		if strings.EqualFold(httpReq.Header.Get("Upgrade"), "websocket") {
			// WebSocket upgrade with already-parsed request
			ws, err := transport.WSUpgradeFromParsedRequest(conn, httpReq, cfg.WSPath)
			if err != nil {
				s.logger.Debug("vless ws upgrade failed, serving cover", "remote", remote)
				serveCoverFromParsedRequest(conn, httpReq)
				return
			}
			s.logger.Debug("vless ws upgraded", "remote", remote)
			reader = ws
			writer = ws
			closer = func() { ws.Close() }
		} else {
			// Regular HTTP (browser/scanner) → serve cover site over HTTPS
			s.logger.Debug("vless serving cover site (no ws upgrade)", "remote", remote)
			serveCoverFromParsedRequest(conn, httpReq)
			return
		}
	} else {
		// Unknown protocol over TLS — close silently
		s.logger.Debug("vless unknown protocol", "remote", remote)
		return
	}
	defer closer()

	// Parse VLESS request
	req, err := transport.VLESSParseRequest(reader)
	if err != nil {
		s.logger.Debug("vless parse failed", "err", err, "remote", remote)
		return
	}

	// Clear handshake deadline
	conn.SetDeadline(time.Time{})

	// Authenticate UUID — on failure, serve cover site.
	if req.UUID != cfg.UUID {
		s.logger.Debug("vless auth failed", "remote", remote)
		return
	}

	dest := net.JoinHostPort(req.Addr, fmt.Sprintf("%d", req.Port))

	switch req.Command {
	case transport.VLESSCmdTCP:
		s.vlessTCPRelay(ctx, reader, writer, req, dest, remote)
	case transport.VLESSCmdUDP:
		s.vlessUDPRelay(ctx, reader, writer, req, dest, remote)
	default:
		s.logger.Warn("vless unsupported command", "cmd", req.Command)
	}
}

// vlessTCPRelay proxies a single TCP connection to the destination.
func (s *Server) vlessTCPRelay(ctx context.Context, reader io.Reader, writer io.Writer, req *transport.VLESSRequest, dest, remote string) {
	target, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		s.logger.Debug("vless tcp dial failed", "dest", dest, "err", err)
		return
	}
	defer target.Close()

	if err := transport.VLESSWriteResponse(writer); err != nil {
		return
	}

	vlessActiveConns.Add(1)
	defer vlessActiveConns.Add(-1)
	s.logger.Info("vless relay", "dest", dest, "remote", remote)

	if len(req.Payload) > 0 {
		target.Write(req.Payload) //nolint:errcheck
	}

	done := make(chan struct{}, 1)
	go func() {
		io.Copy(writer, target) //nolint:errcheck
		done <- struct{}{}
	}()
	io.Copy(target, reader) //nolint:errcheck
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// vlessUDPRelay proxies UDP packets (DNS etc.) to the destination.
// VLESS UDP framing: each datagram is prefixed with 2-byte BE length.
func (s *Server) vlessUDPRelay(ctx context.Context, reader io.Reader, writer io.Writer, req *transport.VLESSRequest, dest, remote string) {
	udpAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		s.logger.Debug("vless udp resolve failed", "dest", dest, "err", err)
		return
	}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		s.logger.Debug("vless udp dial failed", "dest", dest, "err", err)
		return
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(120 * time.Second))

	if err := transport.VLESSWriteResponse(writer); err != nil {
		return
	}

	s.logger.Debug("vless udp relay", "dest", dest, "remote", remote)

	// Forward initial payload (length-prefixed UDP packets)
	if len(req.Payload) > 0 {
		forwardUDPFromStream(req.Payload, udpConn)
	}

	// Client → UDP destination
	go func() {
		lenBuf := make([]byte, 2)
		for {
			if _, err := io.ReadFull(reader, lenBuf); err != nil {
				return
			}
			pktLen := int(lenBuf[0])<<8 | int(lenBuf[1])
			if pktLen <= 0 || pktLen > 65535 {
				return
			}
			pkt := make([]byte, pktLen)
			if _, err := io.ReadFull(reader, pkt); err != nil {
				return
			}
			udpConn.Write(pkt) //nolint:errcheck
			// Refresh deadline on activity
			udpConn.SetDeadline(time.Now().Add(120 * time.Second))
		}
	}()

	// UDP destination → client.
	// Use a pooled buffer to combine the 2-byte BE length prefix with the UDP
	// payload into a single Write call, producing one TLS record instead of two.
	pb := vlessUDPRespPool.Get().(*[]byte)
	defer vlessUDPRespPool.Put(pb)
	resp := *pb
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := udpConn.Read(resp[2:])
		if err != nil {
			return
		}
		resp[0] = byte(n >> 8)
		resp[1] = byte(n)
		if _, err := writer.Write(resp[:n+2]); err != nil {
			return
		}
	}
}

// forwardUDPFromStream extracts length-prefixed UDP datagrams and sends them.
func forwardUDPFromStream(data []byte, conn *net.UDPConn) {
	for len(data) >= 2 {
		pktLen := int(data[0])<<8 | int(data[1])
		data = data[2:]
		if pktLen > len(data) {
			break
		}
		conn.Write(data[:pktLen]) //nolint:errcheck
		data = data[pktLen:]
	}
}

// generateVLESSLinks builds vless:// URIs for both TCP and WS modes.
func generateVLESSLinks(uuid [16]byte, host string, port int, wsPath string) (tcpLink, wsLink string) {
	uuidStr := transport.FormatUUID(uuid)
	tcpLink = fmt.Sprintf("vless://%s@%s:%d?security=tls&allowInsecure=1&fp=chrome#CavadVPN",
		uuidStr, host, port)
	wsLink = fmt.Sprintf("vless://%s@%s:%d?type=ws&security=tls&allowInsecure=1&path=%s#CavadVPN",
		uuidStr, host, port, wsPath)
	return
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
// self-signed ECDSA P-256 certificate.
//
// Anti-fingerprinting design:
//   - domain is embedded as Subject CN and DNS SAN. Caller passes a CDN-style
//     hostname (e.g. "cdn.jsdelivr.net") so the certificate metadata does not
//     reveal that this is a VPN server. Passive fingerprinting tools (JA3,
//     p0f, Censys) inspect Subject/SAN fields — "CavadVPN" is an immediate
//     identification signal; a CDN hostname is not.
//   - KeyUsage is KeyUsageDigitalSignature only. ECDSA keys do not use
//     KeyEncipherment (that bit is for RSA key exchange); including it would
//     be a minor mismatch with real ECDSA TLS certificates.
//   - No IP SANs — real CDN certificates do not carry IP SANs. IP SANs are
//     characteristic of internal PKI / Kubernetes certs and are themselves a
//     fingerprint.
//   - Validity 90 days — matches Let's Encrypt's certificate lifetime since
//     RFC 8555 / ACME became standard. A 10-year validity is a strong signal
//     that the certificate was machine-generated for a non-web purpose.
func ensureTLSCert(certPath, keyPath, domain string, logger *slog.Logger) error {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil {
		logger.Info("TLS cert found", "cert", certPath, "key", keyPath)
		return nil
	}

	logger.Info("generating self-signed TLS certificate", "cert", certPath, "key", keyPath, "domain", domain)

	// Generate ECDSA P-256 key (matches Cloudflare, Let's Encrypt default).
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Build self-signed X.509 certificate.
	//
	// Subject: CN only — DV (domain-validated) certificates issued by Let's
	// Encrypt and major CAs include only CommonName, no O/L/ST/C, to match
	// the minimal-disclosure DV standard.
	//
	// SAN: DNS only — no IP SANs.  RFC 5280 §4.2.1.6 requires at least one
	// SAN for TLS; browsers ignore CN when SAN is present.
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour), // 90 days — Let's Encrypt style
		KeyUsage:     x509.KeyUsageDigitalSignature,       // ECDSA: no KeyEncipherment
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
		// No IPAddresses — CDN certs never carry IP SANs.
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
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}) //nolint:errcheck
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
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}) //nolint:errcheck
	keyFile.Close()

	logger.Info("self-signed TLS certificate generated", "cert", certPath, "key", keyPath, "domain", domain)
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
