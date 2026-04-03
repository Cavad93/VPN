// Package notify implements push notifications for VPN events.
//
// Two notification backends are supported:
//
//   - ntfy — sends messages via ntfy.sh (or any self-hosted ntfy instance).
//     The recipient installs the free ntfy app on their phone and subscribes
//     to their unique topic.  No Apple/Google accounts needed.
//   - webhook — posts a JSON payload to any HTTP endpoint.
//
// Usage:
//
//	svc := notify.NewNotificationService(logger)
//	defer svc.Stop()
//
//	svc.AddSubscriber(&notify.Subscriber{
//	    ID:    "alice",
//	    Type:  "ntfy",
//	    Topic: "cavadvpn-alice-secret",
//	    Events: []string{"disconnect", "server_down"},
//	})
//
//	svc.NotifySessionDisconnected(42, "10.8.0.5")
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Notification value type
// ---------------------------------------------------------------------------

// Notification is a single push message sent to subscribers.
type Notification struct {
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Priority string   `json:"priority,omitempty"` // low | default | high | urgent
	Tags     []string `json:"tags,omitempty"`     // ntfy emoji shortcuts, e.g. ["warning"]
}

// ---------------------------------------------------------------------------
// Notifier interface and implementations
// ---------------------------------------------------------------------------

// Notifier is the backend interface for sending a single push notification.
type Notifier interface {
	SendAlert(ctx context.Context, n Notification) error
}

// ---------------------------------------------------------------------------
// ntfy notifier
// ---------------------------------------------------------------------------

// NtfyNotifier sends push notifications via ntfy.sh (or a self-hosted instance).
// The recipient installs https://ntfy.sh app and subscribes to their Topic.
type NtfyNotifier struct {
	BaseURL string // e.g. "https://ntfy.sh" (no trailing slash)
	Topic   string // unique per-user topic name
	Token   string // optional Bearer token for private topics
	client  *http.Client
}

// ntfyPayload is the JSON body sent to the ntfy HTTP API.
type ntfyPayload struct {
	Topic    string   `json:"topic"`
	Message  string   `json:"message"`
	Title    string   `json:"title,omitempty"`
	Priority string   `json:"priority,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// NewNtfyNotifier creates an NtfyNotifier.  baseURL defaults to
// "https://ntfy.sh" when empty.  token may be empty for public topics.
func NewNtfyNotifier(baseURL, topic, token string) *NtfyNotifier {
	if baseURL == "" {
		baseURL = "https://ntfy.sh"
	}
	return &NtfyNotifier{
		BaseURL: baseURL,
		Topic:   topic,
		Token:   token,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
				// TLS sessions are reused automatically by the transport.
			},
		},
	}
}

// SendAlert publishes a notification to the ntfy topic.
func (n *NtfyNotifier) SendAlert(ctx context.Context, notif Notification) error {
	payload := ntfyPayload{
		Topic:    n.Topic,
		Message:  notif.Message,
		Title:    notif.Title,
		Priority: notif.Priority,
		Tags:     notif.Tags,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ntfy: marshal payload: %w", err)
	}

	url := n.BaseURL + "/" + n.Topic
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ntfy: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy: send: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ntfy: server replied %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Webhook notifier
// ---------------------------------------------------------------------------

// WebhookNotifier sends a JSON POST to a custom HTTP endpoint.
type WebhookNotifier struct {
	URL    string
	Secret string // optional; if set, added as X-Webhook-Secret header
	client *http.Client
}

// NewWebhookNotifier creates a WebhookNotifier.
func NewWebhookNotifier(url, secret string) *WebhookNotifier {
	return &WebhookNotifier{
		URL:    url,
		Secret: secret,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// SendAlert posts the notification as JSON to the webhook URL.
func (w *WebhookNotifier) SendAlert(ctx context.Context, notif Notification) error {
	body, err := json.Marshal(notif)
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Secret != "" {
		req.Header.Set("X-Webhook-Secret", w.Secret)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: send: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: server replied %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Subscriber
// ---------------------------------------------------------------------------

// Subscriber represents a registered notification recipient.
type Subscriber struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`                 // "ntfy" or "webhook"
	NtfyURL    string    `json:"ntfy_url,omitempty"`   // ntfy base URL; defaults to ntfy.sh
	Topic      string    `json:"topic,omitempty"`      // ntfy topic name (required for ntfy type)
	Token      string    `json:"token,omitempty"`      // ntfy auth token (optional)
	WebhookURL string    `json:"webhook_url,omitempty"` // webhook endpoint (required for webhook type)
	Events     []string  `json:"events"`               // ["disconnect","connect","server_down"] or ["*"]
	Note       string    `json:"note,omitempty"`       // human-readable label
	CreatedAt  time.Time `json:"created_at"`

	// notifier is the backend; set by AddSubscriber, not serialised.
	notifier Notifier
}

// ValidEvents lists all event names recognised by the service.
var ValidEvents = []string{"connect", "disconnect", "server_down"}

// ---------------------------------------------------------------------------
// Notification service
// ---------------------------------------------------------------------------

type pendingNotif struct {
	event string
	notif Notification
}

// NotificationService manages subscribers and asynchronously dispatches push
// notifications for VPN events.
//
// All public methods are safe for concurrent use.
type NotificationService struct {
	mu          sync.RWMutex
	subscribers map[string]*Subscriber
	logger      *slog.Logger
	queue       chan pendingNotif
	wg          sync.WaitGroup
	sendMu      sync.Mutex // protects stopped + queue send against Stop race
	stopped     bool
	stopOnce    sync.Once
}

// NewNotificationService creates a new service and starts the background
// dispatch worker.  Call Stop() when the service is no longer needed.
func NewNotificationService(logger *slog.Logger) *NotificationService {
	s := &NotificationService{
		subscribers: make(map[string]*Subscriber),
		logger:      logger,
		queue:       make(chan pendingNotif, 256),
	}
	s.wg.Add(1)
	go s.worker()
	return s
}

// Stop drains the notification queue and stops the background worker.
// Blocks until all in-flight deliveries complete. Safe to call multiple times.
func (s *NotificationService) Stop() {
	s.stopOnce.Do(func() {
		s.sendMu.Lock()
		s.stopped = true
		close(s.queue)
		s.sendMu.Unlock()
	})
	s.wg.Wait()
}

// ---------------------------------------------------------------------------
// worker — dispatches notifications asynchronously with parallel delivery
// ---------------------------------------------------------------------------

// worker reads from the internal queue and dispatches each notification to all
// matching subscribers IN PARALLEL so that one slow recipient does not block
// others.  This is PERF IMPROVEMENT 1: parallel concurrent notification delivery.
func (s *NotificationService) worker() {
	defer s.wg.Done()
	for pn := range s.queue {
		s.dispatch(pn)
	}
}

// dispatch sends pn to all matching subscribers concurrently.
// Each subscriber gets its own goroutine so slow HTTP targets don't block each
// other AND don't stall the notification queue worker.  Delivery is
// fire-and-forget from the worker's perspective: the worker immediately moves
// to the next queued event regardless of how long individual deliveries take.
func (s *NotificationService) dispatch(pn pendingNotif) {
	s.mu.RLock()
	// Collect matching subscribers under the read lock (snapshot).
	var targets []*Subscriber
	for _, sub := range s.subscribers {
		if subscriberWantsEvent(sub, pn.event) {
			targets = append(targets, sub)
		}
	}
	s.mu.RUnlock()

	for _, sub := range targets {
		sub := sub // capture loop variable
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := sub.notifier.SendAlert(ctx, pn.notif); err != nil {
				s.logger.Warn("push notification failed",
					"subscriber", sub.ID,
					"type", sub.Type,
					"event", pn.event,
					"err", err)
			} else {
				s.logger.Debug("push notification sent",
					"subscriber", sub.ID,
					"event", pn.event)
			}
		}()
	}
}

// subscriberWantsEvent returns true if sub is interested in the given event.
func subscriberWantsEvent(sub *Subscriber, event string) bool {
	for _, e := range sub.Events {
		if e == "*" || e == event {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Public event methods
// ---------------------------------------------------------------------------

// Notify queues a notification for the given event (non-blocking).
// If the queue is full the notification is dropped and a warning is logged.
// Safe to call after Stop() — silently ignored.
func (s *NotificationService) Notify(event string, notif Notification) {
	s.sendMu.Lock()
	if s.stopped {
		s.sendMu.Unlock()
		return
	}
	select {
	case s.queue <- pendingNotif{event: event, notif: notif}:
	default:
		s.logger.Warn("notification queue full, dropping event", "event", event)
	}
	s.sendMu.Unlock()
}

// NotifySessionConnected sends a connection alert.
func (s *NotificationService) NotifySessionConnected(sessionID uint64, assignedIP string) {
	s.Notify("connect", Notification{
		Title:    "CavadVPN: новое подключение",
		Message:  fmt.Sprintf("Сессия #%d, IP: %s", sessionID, assignedIP),
		Priority: "default",
		Tags:     []string{"white_check_mark"},
	})
}

// NotifySessionDisconnected sends a disconnect alert.
func (s *NotificationService) NotifySessionDisconnected(sessionID uint64, assignedIP string) {
	s.Notify("disconnect", Notification{
		Title:    "CavadVPN: клиент отключился",
		Message:  fmt.Sprintf("Сессия #%d (%s) завершена", sessionID, assignedIP),
		Priority: "high",
		Tags:     []string{"warning"},
	})
}

// NotifyServerDown sends a critical server-down alert.
func (s *NotificationService) NotifyServerDown(reason string) {
	s.Notify("server_down", Notification{
		Title:    "CavadVPN: сервер недоступен",
		Message:  reason,
		Priority: "urgent",
		Tags:     []string{"rotating_light"},
	})
}

// ---------------------------------------------------------------------------
// Subscriber management
// ---------------------------------------------------------------------------

// AddSubscriber registers a notification recipient.  The subscriber's notifier
// is constructed from its Type/NtfyURL/Topic/WebhookURL fields.
// Returns an error if required fields are missing or the type is unknown.
func (s *NotificationService) AddSubscriber(sub *Subscriber) error {
	if sub.ID == "" {
		return fmt.Errorf("notify: subscriber ID is required")
	}

	notifier, err := buildNotifier(sub)
	if err != nil {
		return err
	}
	sub.notifier = notifier

	if len(sub.Events) == 0 {
		sub.Events = []string{"disconnect", "server_down"}
	}
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = time.Now()
	}

	s.mu.Lock()
	s.subscribers[sub.ID] = sub
	s.mu.Unlock()
	return nil
}

// RemoveSubscriber deletes a subscriber by ID.  Returns true if it existed.
func (s *NotificationService) RemoveSubscriber(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.subscribers[id]
	if ok {
		delete(s.subscribers, id)
	}
	return ok
}

// Subscribers returns a snapshot of all current subscribers.
// The returned slice is safe to read without holding any lock.
func (s *NotificationService) Subscribers() []*Subscriber {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Subscriber, 0, len(s.subscribers))
	for _, sub := range s.subscribers {
		out = append(out, sub)
	}
	return out
}

// GetSubscriber returns the subscriber with the given ID, or nil.
func (s *NotificationService) GetSubscriber(id string) *Subscriber {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.subscribers[id]
}

// SendTest dispatches a test notification to a specific subscriber immediately
// (bypasses the async queue so the HTTP response can report success/failure).
func (s *NotificationService) SendTest(id string) error {
	s.mu.RLock()
	sub := s.subscribers[id]
	s.mu.RUnlock()
	if sub == nil {
		return fmt.Errorf("notify: subscriber %q not found", id)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return sub.notifier.SendAlert(ctx, Notification{
		Title:    "CavadVPN: тест уведомлений",
		Message:  "Тестовое уведомление работает! ✓",
		Priority: "default",
		Tags:     []string{"test_tube"},
	})
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func buildNotifier(sub *Subscriber) (Notifier, error) {
	switch sub.Type {
	case "ntfy":
		if sub.Topic == "" {
			return nil, fmt.Errorf("notify: ntfy subscriber %q requires a topic", sub.ID)
		}
		return NewNtfyNotifier(sub.NtfyURL, sub.Topic, sub.Token), nil

	case "webhook":
		if sub.WebhookURL == "" {
			return nil, fmt.Errorf("notify: webhook subscriber %q requires webhook_url", sub.ID)
		}
		return NewWebhookNotifier(sub.WebhookURL, ""), nil

	default:
		return nil, fmt.Errorf("notify: unknown subscriber type %q (must be ntfy or webhook)", sub.Type)
	}
}
