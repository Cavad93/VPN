package api

// notify_api.go — REST endpoints for managing push notification subscriptions.
//
// Endpoints (all require authentication when APIToken is configured):
//
//	GET    /api/v1/notifications                — list all subscribers
//	POST   /api/v1/notifications                — add subscriber
//	DELETE /api/v1/notifications/{id}           — remove subscriber
//	POST   /api/v1/notifications/{id}/test      — send test notification
//
// Example subscriber JSON:
//
//	{
//	  "id":    "alice",
//	  "type":  "ntfy",
//	  "topic": "cavadvpn-alice-unique-topic",
//	  "events": ["disconnect", "server_down"]
//	}
//
//	{
//	  "id":          "myhook",
//	  "type":        "webhook",
//	  "webhook_url": "https://hooks.example.com/vpn-alert",
//	  "events":      ["*"]
//	}

import (
	"encoding/json"
	"net/http"

	"github.com/cavad93/vpn/server/notify"
)

// NotificationService is the subset of notify.NotificationService used by the API.
type NotificationService interface {
	AddSubscriber(sub *notify.Subscriber) error
	RemoveSubscriber(id string) bool
	Subscribers() []*notify.Subscriber
	GetSubscriber(id string) *notify.Subscriber
	SendTest(id string) error
}

// SetNotificationService attaches a notification service to the API server and
// registers all /api/v1/notifications routes.
func (a *APIServer) SetNotificationService(ns NotificationService) {
	a.notifSvc = ns
	a.mux.HandleFunc("GET /api/v1/notifications", a.auth(a.handleListSubscribers))
	a.mux.HandleFunc("POST /api/v1/notifications", a.auth(a.handleAddSubscriber))
	a.mux.HandleFunc("DELETE /api/v1/notifications/{id}", a.auth(a.handleDeleteSubscriber))
	a.mux.HandleFunc("POST /api/v1/notifications/{id}/test", a.auth(a.handleTestSubscriber))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (a *APIServer) handleListSubscribers(w http.ResponseWriter, r *http.Request) {
	if a.notifSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "notification service not configured")
		return
	}
	writeJSON(w, http.StatusOK, a.notifSvc.Subscribers())
}

func (a *APIServer) handleAddSubscriber(w http.ResponseWriter, r *http.Request) {
	if a.notifSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "notification service not configured")
		return
	}

	var sub notify.Subscriber
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if err := a.notifSvc.AddSubscriber(&sub); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, a.notifSvc.GetSubscriber(sub.ID))
}

func (a *APIServer) handleDeleteSubscriber(w http.ResponseWriter, r *http.Request) {
	if a.notifSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "notification service not configured")
		return
	}

	id := r.PathValue("id")
	if !a.notifSvc.RemoveSubscriber(id) {
		writeError(w, http.StatusNotFound, "subscriber not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *APIServer) handleTestSubscriber(w http.ResponseWriter, r *http.Request) {
	if a.notifSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "notification service not configured")
		return
	}

	id := r.PathValue("id")
	if err := a.notifSvc.SendTest(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}
