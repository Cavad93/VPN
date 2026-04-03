// Package api — qr.go реализует генерацию QR-кодов с конфигурацией VPN клиента.
//
// Эндпоинты:
//
//	POST /api/v1/qr/generate          — новый клиентский ключ + QR-код PNG
//	GET  /api/v1/qr/generate          — то же (удобно для открытия из браузера)
//	GET  /api/v1/qr/generate?format=json — возвращает JSON конфиг вместо PNG
//	GET  /api/v1/qr/server-info       — публичный ключ и адрес сервера (без клиентского ключа)
//
// QR-код содержит URI формата:
//
//	cavadvpn://config?host=HOST&port=PORT&server_key=HEX&private_key=HEX&dns=DNS
//
// Этот формат совместим с Android QrConfig и iOS QRConfig парсерами.
package api

import (
	"encoding/hex"
	"net"
	"net/http"
	"strconv"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/curve25519"

	"github.com/cavad93/vpn/server/crypto"
)

// QRServerIface предоставляет данные сервера, необходимые для генерации QR-кода клиента.
type QRServerIface interface {
	// PublicKey возвращает статический X25519 публичный ключ сервера.
	PublicKey() [32]byte
	// VPNListenAddr возвращает адрес VPN сервера в формате host:port.
	VPNListenAddr() string
}

// ClientConfig — конфигурация VPN клиента, кодируемая в QR-коде.
// Совместима с Android QrConfig и iOS QRConfig парсерами.
type ClientConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	PrivateKey string `json:"private_key"` // hex-кодированный X25519 приватный ключ
	ServerKey  string `json:"server_key"`  // hex-кодированный публичный ключ сервера
	DNS        string `json:"dns"`
}

// configURI строит cavadvpn:// URI из ClientConfig.
func configURI(cfg ClientConfig) string {
	return "cavadvpn://config?host=" + cfg.Host +
		"&port=" + strconv.Itoa(cfg.Port) +
		"&server_key=" + cfg.ServerKey +
		"&private_key=" + cfg.PrivateKey +
		"&dns=" + cfg.DNS
}

// SetQRServer подключает QRServerIface к APIServer и регистрирует QR маршруты.
// Вызывать после NewAPIServer, до первого запроса.
func (a *APIServer) SetQRServer(qrs QRServerIface) {
	a.qrSrv = qrs
	a.mux.HandleFunc("POST /api/v1/qr/generate", a.auth(a.handleQRGenerate))
	a.mux.HandleFunc("GET /api/v1/qr/generate", a.auth(a.handleQRGenerate))
	a.mux.HandleFunc("GET /api/v1/qr/server-info", a.auth(a.handleQRServerInfo))
}

// handleQRGenerate генерирует новую клиентскую пару ключей, добавляет публичный ключ
// в allowlist и возвращает QR-код PNG (или JSON если ?format=json).
func (a *APIServer) handleQRGenerate(w http.ResponseWriter, r *http.Request) {
	if a.qrSrv == nil {
		writeError(w, http.StatusServiceUnavailable, "QR server not configured")
		return
	}

	dns := r.URL.Query().Get("dns")
	if dns == "" {
		dns = "1.1.1.1"
	}

	host, port, err := splitHostPort(a.qrSrv.VPNListenAddr())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid server listen address: "+err.Error())
		return
	}

	// Генерация новой клиентской пары ключей.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed: "+err.Error())
		return
	}

	// Добавляем публичный ключ клиента в allowlist.
	a.srv.AddAllowedKey(kp.PublicKey)

	serverPub := a.qrSrv.PublicKey()
	cfg := ClientConfig{
		Host:       host,
		Port:       port,
		PrivateKey: hex.EncodeToString(kp.PrivateKey[:]),
		ServerKey:  hex.EncodeToString(serverPub[:]),
		DNS:        dns,
	}

	if r.URL.Query().Get("format") == "json" {
		writeJSON(w, http.StatusOK, cfg)
		return
	}

	// Генерируем QR-код PNG.
	uri := configURI(cfg)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "QR encode failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-VPN-Host", host)
	w.Header().Set("X-VPN-Server-Key", cfg.ServerKey)
	w.WriteHeader(http.StatusOK)
	w.Write(png) //nolint:errcheck
}

// handleQRServerInfo возвращает публичный ключ сервера и адрес без генерации клиентского ключа.
// Используется для ручной настройки или отладки.
func (a *APIServer) handleQRServerInfo(w http.ResponseWriter, r *http.Request) {
	if a.qrSrv == nil {
		writeError(w, http.StatusServiceUnavailable, "QR server not configured")
		return
	}

	host, port, err := splitHostPort(a.qrSrv.VPNListenAddr())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid server listen address: "+err.Error())
		return
	}

	serverPub := a.qrSrv.PublicKey()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host":       host,
		"port":       port,
		"server_key": hex.EncodeToString(serverPub[:]),
	})
}

// splitHostPort разбирает addr формата "host:port".
// Если host — это wildcard (0.0.0.0 или ::), возвращает пустую строку
// (клиент должен использовать адрес, по которому он достучался до сервера).
func splitHostPort(addr string) (host string, port int, err error) {
	h, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	// Normalize wildcard addresses to empty string.
	if h == "0.0.0.0" || h == "::" || h == "" {
		h = ""
	}
	return h, p, nil
}

// derivePublicKey вычисляет публичный ключ X25519 из приватного.
// Используется для тестов.
func derivePublicKey(priv [32]byte) ([32]byte, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], pub)
	return out, nil
}
