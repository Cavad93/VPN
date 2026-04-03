// Package api — invite.go реализует систему пригласительных ссылок для VPN клиентов.
//
// Архитектура:
//
//	Admin                         Server                          Friend
//	  │                             │                               │
//	  │  POST /api/v1/invites       │                               │
//	  ├────────────────────────────►│ генерирует токен + ключи      │
//	  │  {token, url, config}       │                               │
//	  │◄────────────────────────────┤                               │
//	  │                             │                               │
//	  │  Отправляет ссылку другу    │                               │
//	  │─────────────────────────────┼──────────────────────────────►│
//	  │                             │    GET /join/{token}          │
//	  │                             │◄──────────────────────────────┤
//	  │                             │  HTML страница с платформой   │
//	  │                             ├──────────────────────────────►│
//	  │                             │    GET /join/{token}/config   │
//	  │                             │◄──────────────────────────────┤
//	  │                             │  JSON конфиг                  │
//	  │                             ├──────────────────────────────►│
//
// Эндпоинты (с аутентификацией):
//
//	POST   /api/v1/invites                 — создать приглашение
//	GET    /api/v1/invites                 — список приглашений
//	DELETE /api/v1/invites/{token}         — отозвать приглашение
//
// Публичные эндпоинты (без аутентификации):
//
//	GET /join/{token}              — HTML страница с платформозависимой инструкцией
//	GET /join/{token}/config.json  — JSON конфиг для ручного импорта
//	GET /join/{token}/qr.png       — QR-код PNG для сканирования
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/cavad93/vpn/server/crypto"
)

// ---------------------------------------------------------------------------
// Invite record
// ---------------------------------------------------------------------------

// InviteRecord хранит одно приглашение.
type InviteRecord struct {
	Token     string       `json:"token"`
	URL       string       `json:"url"`       // полный URL для отправки другу
	Config    ClientConfig `json:"config"`    // конфиг клиента (включает приватный ключ)
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Uses      int          `json:"uses"`      // сколько раз открыта страница /join
	MaxUses   int          `json:"max_uses"`  // 0 = без ограничений
	Note      string       `json:"note"`      // произвольная заметка (для кого ссылка)
}

// expired возвращает true если приглашение истекло.
func (r *InviteRecord) expired() bool {
	return !r.ExpiresAt.IsZero() && time.Now().After(r.ExpiresAt)
}

// valid возвращает true если приглашение можно использовать.
func (r *InviteRecord) valid() bool {
	if r.expired() {
		return false
	}
	if r.MaxUses > 0 && r.Uses >= r.MaxUses {
		return false
	}
	return true
}

// InviteStore — потокобезопасное хранилище приглашений в памяти.
type InviteStore struct {
	mu      sync.RWMutex
	records map[string]*InviteRecord // token → record
}

func newInviteStore() *InviteStore {
	return &InviteStore{records: make(map[string]*InviteRecord)}
}

// add добавляет приглашение в хранилище.
func (s *InviteStore) add(r *InviteRecord) {
	s.mu.Lock()
	s.records[r.Token] = r
	s.mu.Unlock()
}

// get возвращает приглашение по токену (nil если не найдено).
func (s *InviteStore) get(token string) *InviteRecord {
	s.mu.RLock()
	r := s.records[token]
	s.mu.RUnlock()
	return r
}

// incrementUse атомарно увеличивает счётчик использований.
// Возвращает false если лимит превышен или запись не найдена.
func (s *InviteStore) incrementUse(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[token]
	if !ok {
		return false
	}
	if !r.valid() {
		return false
	}
	r.Uses++
	return true
}

// revoke удаляет приглашение из хранилища.
// Возвращает false если запись не найдена.
func (s *InviteStore) revoke(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[token]; !ok {
		return false
	}
	delete(s.records, token)
	return true
}

// list возвращает все приглашения (копию).
func (s *InviteStore) list() []InviteRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]InviteRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, *r)
	}
	return out
}

// ---------------------------------------------------------------------------
// generateToken генерирует криптографически случайный hex токен (32 байта = 64 символа).
// ---------------------------------------------------------------------------

func generateInviteToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// SetInviteServer подключает систему приглашений к APIServer.
// Вызывать после NewAPIServer.
// ---------------------------------------------------------------------------

// SetInviteServer регистрирует все маршруты системы приглашений.
// Публичные маршруты /join/* регистрируются без аутентификации.
func (a *APIServer) SetInviteServer() {
	a.invites = newInviteStore()

	// Admin-only (с аутентификацией)
	a.mux.HandleFunc("POST /api/v1/invites", a.auth(a.handleCreateInvite))
	a.mux.HandleFunc("GET /api/v1/invites", a.auth(a.handleListInvites))
	a.mux.HandleFunc("DELETE /api/v1/invites/{token}", a.auth(a.handleRevokeInvite))

	// Публичные — без аутентификации
	a.mux.HandleFunc("GET /join/{token}", a.handleJoinPage)
	a.mux.HandleFunc("GET /join/{token}/config.json", a.handleJoinConfig)
	a.mux.HandleFunc("GET /join/{token}/qr.png", a.handleJoinQR)
}

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

// createInviteRequest — тело запроса POST /api/v1/invites.
type createInviteRequest struct {
	TTLHours int    `json:"ttl_hours"` // 0 = бессрочно
	MaxUses  int    `json:"max_uses"`  // 0 = без ограничений
	Note     string `json:"note"`      // для кого ссылка
	DNS      string `json:"dns"`       // DNS сервер для клиента
}

// handleCreateInvite создаёт новое приглашение.
// POST /api/v1/invites
func (a *APIServer) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	if a.invites == nil || a.qrSrv == nil {
		writeError(w, http.StatusServiceUnavailable, "invite system not configured")
		return
	}

	var req createInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Разрешаем пустое тело — используем defaults.
		req = createInviteRequest{}
	}

	if req.DNS == "" {
		req.DNS = "1.1.1.1"
	}

	// Генерация токена.
	token, err := generateInviteToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed: "+err.Error())
		return
	}

	// Генерация клиентских ключей.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed: "+err.Error())
		return
	}

	// Добавляем публичный ключ клиента в allowlist сразу.
	a.srv.AddAllowedKey(kp.PublicKey)

	host, port, err := splitHostPort(a.qrSrv.VPNListenAddr())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid server address: "+err.Error())
		return
	}

	serverPub := a.qrSrv.PublicKey()
	cfg := ClientConfig{
		Host:       host,
		Port:       port,
		PrivateKey: hex.EncodeToString(kp.PrivateKey[:]),
		ServerKey:  hex.EncodeToString(serverPub[:]),
		DNS:        req.DNS,
	}

	// Вычисляем срок действия.
	var expiresAt time.Time
	if req.TTLHours > 0 {
		expiresAt = time.Now().Add(time.Duration(req.TTLHours) * time.Hour)
	}

	// Определяем базовый URL из запроса.
	baseURL := inviteBaseURL(r)
	joinURL := baseURL + "/join/" + token

	record := &InviteRecord{
		Token:     token,
		URL:       joinURL,
		Config:    cfg,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		MaxUses:   req.MaxUses,
		Note:      req.Note,
	}
	a.invites.add(record)

	writeJSON(w, http.StatusCreated, record)
}

// handleListInvites возвращает список всех приглашений.
// GET /api/v1/invites
func (a *APIServer) handleListInvites(w http.ResponseWriter, r *http.Request) {
	if a.invites == nil {
		writeError(w, http.StatusServiceUnavailable, "invite system not configured")
		return
	}
	writeJSON(w, http.StatusOK, a.invites.list())
}

// handleRevokeInvite отзывает приглашение.
// DELETE /api/v1/invites/{token}
func (a *APIServer) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	if a.invites == nil {
		writeError(w, http.StatusServiceUnavailable, "invite system not configured")
		return
	}
	token := r.PathValue("token")
	if !a.invites.revoke(token) {
		writeError(w, http.StatusNotFound, "invite not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------

// handleJoinPage отдаёт HTML страницу приглашения с определением платформы.
// GET /join/{token}
func (a *APIServer) handleJoinPage(w http.ResponseWriter, r *http.Request) {
	if a.invites == nil {
		http.Error(w, "invite system not configured", http.StatusServiceUnavailable)
		return
	}

	token := r.PathValue("token")
	rec := a.invites.get(token)
	if rec == nil || !rec.valid() {
		http.Error(w, "Ссылка недействительна или истекла", http.StatusGone)
		return
	}

	// Увеличиваем счётчик просмотров (не использований — VPN ещё не подключён).
	a.invites.incrementUse(token) //nolint:errcheck

	uri := configURI(rec.Config)
	html := buildInviteHTML(token, rec, uri, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}

// handleJoinConfig возвращает JSON конфиг для ручного импорта.
// GET /join/{token}/config.json
func (a *APIServer) handleJoinConfig(w http.ResponseWriter, r *http.Request) {
	if a.invites == nil {
		writeError(w, http.StatusServiceUnavailable, "invite system not configured")
		return
	}

	token := r.PathValue("token")
	rec := a.invites.get(token)
	if rec == nil || !rec.valid() {
		writeError(w, http.StatusGone, "invite not found or expired")
		return
	}

	w.Header().Set("Content-Disposition", `attachment; filename="cavadvpn.json"`)
	writeJSON(w, http.StatusOK, rec.Config)
}

// handleJoinQR возвращает QR-код PNG с cavadvpn:// URI.
// GET /join/{token}/qr.png
func (a *APIServer) handleJoinQR(w http.ResponseWriter, r *http.Request) {
	if a.invites == nil {
		writeError(w, http.StatusServiceUnavailable, "invite system not configured")
		return
	}

	token := r.PathValue("token")
	rec := a.invites.get(token)
	if rec == nil || !rec.valid() {
		writeError(w, http.StatusGone, "invite not found or expired")
		return
	}

	uri := configURI(rec.Config)
	png, err := qrcode.Encode(uri, qrcode.Medium, 300)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "QR encode failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	w.Write(png) //nolint:errcheck
}

// ---------------------------------------------------------------------------
// HTML builder
// ---------------------------------------------------------------------------

// inviteBaseURL возвращает базовый URL вида https://host (или http://host).
func inviteBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host
}

// platform содержит информацию о платформе клиента.
type platform struct {
	Name    string
	Icon    string
	AppName string
	AppHint string // инструкция по установке
}

// detectPlatform определяет платформу по User-Agent.
func detectPlatform(ua string) platform {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return platform{Name: "iOS", Icon: "📱", AppName: "CavadVPN для iOS", AppHint: "Установите .ipa через AltStore"}
	case strings.Contains(ua, "android"):
		return platform{Name: "Android", Icon: "🤖", AppName: "CavadVPN для Android", AppHint: "Скачайте и установите APK (разрешите установку из неизвестных источников)"}
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x"):
		return platform{Name: "macOS", Icon: "🍎", AppName: "CavadVPN для macOS", AppHint: "Установите .pkg двойным кликом"}
	case strings.Contains(ua, "windows"):
		return platform{Name: "Windows", Icon: "🪟", AppName: "CavadVPN для Windows", AppHint: "Запустите .exe установщик от имени администратора"}
	default:
		return platform{Name: "Universal", Icon: "💻", AppName: "CavadVPN", AppHint: "Выберите версию для вашей платформы"}
	}
}

// buildInviteHTML строит HTML страницу приглашения.
func buildInviteHTML(token string, rec *InviteRecord, cavadvpnURI string, r *http.Request) string {
	p := detectPlatform(r.Header.Get("User-Agent"))
	baseURL := inviteBaseURL(r)
	configURL := baseURL + "/join/" + token + "/config.json"
	qrURL := baseURL + "/join/" + token + "/qr.png"

	expiry := "Бессрочно"
	if !rec.ExpiresAt.IsZero() {
		expiry = rec.ExpiresAt.Format("02.01.2006 15:04 MST")
	}

	note := ""
	if rec.Note != "" {
		note = `<p class="note">📝 ` + htmlEscape(rec.Note) + `</p>`
	}

	return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>CavadVPN — Подключение</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f0f0f;color:#e8e8e8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#1a1a2e;border:1px solid #2a2a4a;border-radius:16px;padding:32px;max-width:480px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{font-size:1.8rem;color:#7c83fd;margin-bottom:4px}
.subtitle{color:#888;font-size:.9rem;margin-bottom:24px}
.platform{background:#0f0f1e;border:1px solid #2a2a4a;border-radius:10px;padding:16px;margin-bottom:20px}
.platform-icon{font-size:2rem;margin-bottom:8px}
.platform-name{font-size:1.1rem;font-weight:600;margin-bottom:4px}
.platform-hint{color:#888;font-size:.85rem}
.btn{display:block;text-align:center;text-decoration:none;padding:14px 20px;border-radius:10px;font-size:1rem;font-weight:600;margin-bottom:12px;transition:opacity .2s}
.btn:hover{opacity:.85}
.btn-primary{background:#7c83fd;color:#fff}
.btn-secondary{background:#1e3a5f;color:#60a5fa;border:1px solid #2563eb}
.btn-outline{background:transparent;color:#888;border:1px solid #333;font-size:.85rem;padding:10px 16px}
.qr-wrap{text-align:center;margin:20px 0}
.qr-wrap img{border-radius:8px;max-width:200px;width:100%}
.meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px;padding-top:20px;border-top:1px solid #2a2a4a}
.meta-item{flex:1;min-width:120px;background:#0f0f1e;border-radius:8px;padding:10px;font-size:.8rem}
.meta-label{color:#666;margin-bottom:2px}
.meta-value{font-weight:600;color:#e8e8e8}
.note{color:#aaa;font-size:.85rem;margin-bottom:16px;padding:10px;background:#0f0f1e;border-radius:8px;border-left:3px solid #7c83fd}
.deeplink{margin-top:12px;font-size:.75rem;color:#555;word-break:break-all;padding:8px;background:#0a0a1a;border-radius:6px}
</style>
</head>
<body>
<div class="card">
  <h1>🔐 CavadVPN</h1>
  <p class="subtitle">Ваша персональная пригласительная ссылка</p>

  ` + note + `

  <div class="platform">
    <div class="platform-icon">` + p.Icon + `</div>
    <div class="platform-name">` + p.Name + ` — ` + p.AppName + `</div>
    <div class="platform-hint">` + p.AppHint + `</div>
  </div>

  <a class="btn btn-primary" href="` + htmlEscape(cavadvpnURI) + `">
    ⚡ Открыть в приложении CavadVPN
  </a>

  <a class="btn btn-secondary" href="` + htmlEscape(configURL) + `" download="cavadvpn.json">
    📥 Скачать конфиг (JSON)
  </a>

  <div class="qr-wrap">
    <p style="color:#666;font-size:.8rem;margin-bottom:8px">Или отсканируйте QR-код с другого устройства</p>
    <img src="` + htmlEscape(qrURL) + `" alt="QR-код конфигурации" loading="lazy">
  </div>

  <div class="meta">
    <div class="meta-item">
      <div class="meta-label">Сервер</div>
      <div class="meta-value">` + htmlEscape(rec.Config.Host) + `</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">DNS</div>
      <div class="meta-value">` + htmlEscape(rec.Config.DNS) + `</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Действует до</div>
      <div class="meta-value">` + htmlEscape(expiry) + `</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Открытий</div>
      <div class="meta-value">` + fmt.Sprintf("%d", rec.Uses) + `</div>
    </div>
  </div>

  <details style="margin-top:16px">
    <summary style="cursor:pointer;color:#555;font-size:.8rem">Технические детали</summary>
    <div class="deeplink">` + htmlEscape(cavadvpnURI) + `</div>
  </details>
</div>
</body>
</html>`
}

// htmlEscape экранирует символы HTML для безопасной вставки в атрибуты и текст.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
