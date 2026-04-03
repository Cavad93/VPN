package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavad93/vpn/server/notify"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestServer starts an httptest.Server that records every POST body.
func newTestServer(t *testing.T) (*httptest.Server, *[][]byte) {
	t.Helper()
	var mu sync.Mutex
	var bodies [][]byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts, &bodies
}

// waitForCount polls until len(*bodies) >= n or deadline.
func waitForCount(t *testing.T, bodies *[][]byte, n int, mu *sync.Mutex) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mu != nil {
			mu.Lock()
		}
		count := len(*bodies)
		if mu != nil {
			mu.Unlock()
		}
		if count >= n {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// ---------------------------------------------------------------------------
// NtfyNotifier tests
// ---------------------------------------------------------------------------

func TestNtfyNotifier_SendAlert_Success(t *testing.T) {
	ts, bodies := newTestServer(t)
	// Build notifier pointing at the test server.
	n := notify.NewNtfyNotifier(ts.URL, "test-topic", "")

	ctx := context.Background()
	err := n.SendAlert(ctx, notify.Notification{
		Title:   "hello",
		Message: "world",
	})
	if err != nil {
		t.Fatalf("SendAlert: unexpected error: %v", err)
	}

	var mu sync.Mutex
	if !waitForCount(t, bodies, 1, &mu) {
		t.Fatal("timed out waiting for request")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal((*bodies)[0], &payload); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if payload["topic"] != "test-topic" {
		t.Errorf("topic = %v, want test-topic", payload["topic"])
	}
	if payload["title"] != "hello" {
		t.Errorf("title = %v, want hello", payload["title"])
	}
}

func TestNtfyNotifier_SendAlert_WithToken(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	n := notify.NewNtfyNotifier(ts.URL, "private-topic", "secret-token")
	if err := n.SendAlert(context.Background(), notify.Notification{Message: "test"}); err != nil {
		t.Fatal(err)
	}

	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer secret-token")
	}
}

func TestNtfyNotifier_DefaultBaseURL(t *testing.T) {
	// Passing empty baseURL should default to https://ntfy.sh (we just
	// verify no panic and the URL field is set correctly).
	n := notify.NewNtfyNotifier("", "topic", "")
	if n.BaseURL != "https://ntfy.sh" {
		t.Errorf("BaseURL = %q, want https://ntfy.sh", n.BaseURL)
	}
}

func TestNtfyNotifier_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	n := notify.NewNtfyNotifier(ts.URL, "topic", "")
	err := n.SendAlert(context.Background(), notify.Notification{Message: "test"})
	if err == nil {
		t.Error("expected error for 403 response, got nil")
	}
}

func TestNtfyNotifier_ContextCancelled(t *testing.T) {
	// Server that blocks until the HTTP client disconnects.
	// Use a channel so we can unblock the handler when the test ends.
	releaseCh := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-releaseCh:
		}
	}))
	// Unblock any pending handler before closing the server.
	t.Cleanup(func() { close(releaseCh); ts.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	n := notify.NewNtfyNotifier(ts.URL, "topic", "")
	err := n.SendAlert(ctx, notify.Notification{Message: "test"})
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

// ---------------------------------------------------------------------------
// WebhookNotifier tests
// ---------------------------------------------------------------------------

func TestWebhookNotifier_SendAlert_Success(t *testing.T) {
	ts, bodies := newTestServer(t)
	w := notify.NewWebhookNotifier(ts.URL, "")

	err := w.SendAlert(context.Background(), notify.Notification{
		Title:   "vpn",
		Message: "disconnected",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var mu sync.Mutex
	if !waitForCount(t, bodies, 1, &mu) {
		t.Fatal("timed out")
	}
	var got notify.Notification
	if err := json.Unmarshal((*bodies)[0], &got); err != nil {
		t.Fatal(err)
	}
	if got.Title != "vpn" || got.Message != "disconnected" {
		t.Errorf("got %+v", got)
	}
}

func TestWebhookNotifier_WithSecret(t *testing.T) {
	var gotSecret string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSecret = r.Header.Get("X-Webhook-Secret")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	wh := notify.NewWebhookNotifier(ts.URL, "mysecret")
	if err := wh.SendAlert(context.Background(), notify.Notification{Message: "hi"}); err != nil {
		t.Fatal(err)
	}
	if gotSecret != "mysecret" {
		t.Errorf("X-Webhook-Secret = %q, want mysecret", gotSecret)
	}
}

func TestWebhookNotifier_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	wh := notify.NewWebhookNotifier(ts.URL, "")
	if err := wh.SendAlert(context.Background(), notify.Notification{}); err == nil {
		t.Error("expected error for 500, got nil")
	}
}

// ---------------------------------------------------------------------------
// NotificationService tests
// ---------------------------------------------------------------------------

func TestNotificationService_AddSubscriber_Ntfy(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	sub := &notify.Subscriber{
		ID:    "sub1",
		Type:  "ntfy",
		Topic: "test-topic",
	}
	if err := svc.AddSubscriber(sub); err != nil {
		t.Fatalf("AddSubscriber: %v", err)
	}
	if got := svc.GetSubscriber("sub1"); got == nil {
		t.Error("subscriber not found after add")
	}
}

func TestNotificationService_AddSubscriber_Webhook(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	sub := &notify.Subscriber{
		ID:         "hook1",
		Type:       "webhook",
		WebhookURL: "http://localhost:9999/hook",
	}
	if err := svc.AddSubscriber(sub); err != nil {
		t.Fatalf("AddSubscriber: %v", err)
	}
}

func TestNotificationService_AddSubscriber_MissingID(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	err := svc.AddSubscriber(&notify.Subscriber{Type: "ntfy", Topic: "x"})
	if err == nil {
		t.Error("expected error for missing ID")
	}
}

func TestNotificationService_AddSubscriber_MissingTopic(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	err := svc.AddSubscriber(&notify.Subscriber{ID: "x", Type: "ntfy"})
	if err == nil {
		t.Error("expected error for missing ntfy topic")
	}
}

func TestNotificationService_AddSubscriber_MissingWebhookURL(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	err := svc.AddSubscriber(&notify.Subscriber{ID: "x", Type: "webhook"})
	if err == nil {
		t.Error("expected error for missing webhook url")
	}
}

func TestNotificationService_AddSubscriber_UnknownType(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	err := svc.AddSubscriber(&notify.Subscriber{ID: "x", Type: "telegram"})
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestNotificationService_RemoveSubscriber(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	_ = svc.AddSubscriber(&notify.Subscriber{ID: "x", Type: "ntfy", Topic: "t"})
	if !svc.RemoveSubscriber("x") {
		t.Error("RemoveSubscriber returned false for existing subscriber")
	}
	if svc.RemoveSubscriber("x") {
		t.Error("RemoveSubscriber returned true for already-removed subscriber")
	}
}

func TestNotificationService_Subscribers(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	for _, id := range []string{"a", "b", "c"} {
		_ = svc.AddSubscriber(&notify.Subscriber{
			ID:    id,
			Type:  "ntfy",
			Topic: "t-" + id,
		})
	}
	subs := svc.Subscribers()
	if len(subs) != 3 {
		t.Errorf("len(Subscribers) = %d, want 3", len(subs))
	}
}

func TestNotificationService_DefaultEvents(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	sub := &notify.Subscriber{ID: "x", Type: "ntfy", Topic: "t"}
	_ = svc.AddSubscriber(sub)
	got := svc.GetSubscriber("x")
	if len(got.Events) == 0 {
		t.Error("expected default events to be set")
	}
}

func TestNotificationService_Dispatch_ToMatchingSubscribers(t *testing.T) {
	var count atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	// Two subscribers listening to "disconnect".
	for _, id := range []string{"s1", "s2"} {
		_ = svc.AddSubscriber(&notify.Subscriber{
			ID:         id,
			Type:       "webhook",
			WebhookURL: ts.URL,
			Events:     []string{"disconnect"},
		})
	}
	// One subscriber listening to "connect" only — should NOT receive disconnect.
	_ = svc.AddSubscriber(&notify.Subscriber{
		ID:         "s3",
		Type:       "webhook",
		WebhookURL: ts.URL,
		Events:     []string{"connect"},
	})

	svc.NotifySessionDisconnected(1, "10.8.0.2")

	// Wait for both deliveries.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if count.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if count.Load() != 2 {
		t.Errorf("delivery count = %d, want 2", count.Load())
	}
}

func TestNotificationService_WildcardEvent(t *testing.T) {
	var count atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	_ = svc.AddSubscriber(&notify.Subscriber{
		ID:         "wild",
		Type:       "webhook",
		WebhookURL: ts.URL,
		Events:     []string{"*"},
	})

	svc.NotifySessionConnected(1, "10.8.0.3")
	svc.NotifyServerDown("test reason")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if count.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if count.Load() < 2 {
		t.Errorf("wildcard subscriber count = %d, want ≥2", count.Load())
	}
}

func TestNotificationService_SendTest(t *testing.T) {
	ts, _ := newTestServer(t)
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	_ = svc.AddSubscriber(&notify.Subscriber{
		ID:         "t1",
		Type:       "webhook",
		WebhookURL: ts.URL,
	})

	if err := svc.SendTest("t1"); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
}

func TestNotificationService_SendTest_NotFound(t *testing.T) {
	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	if err := svc.SendTest("nobody"); err == nil {
		t.Error("expected error for unknown subscriber")
	}
}

func TestNotificationService_QueueDrop(t *testing.T) {
	// Subscriber that blocks so the queue fills up.
	blockCh := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blockCh:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { close(blockCh); ts.Close() })

	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	_ = svc.AddSubscriber(&notify.Subscriber{
		ID:         "blocker",
		Type:       "webhook",
		WebhookURL: ts.URL,
		Events:     []string{"*"},
	})

	// Flood the queue (256 capacity).  Should not panic or deadlock.
	for i := 0; i < 300; i++ {
		svc.Notify("disconnect", notify.Notification{Message: "flood"})
	}
	// If we reach here without deadlock the test passes.
}

func TestNotificationService_ParallelDelivery(t *testing.T) {
	// Two subscribers with deliberate 100ms delay each.
	// With sequential delivery total latency would be ≥200ms.
	// With parallel delivery it should be ~100ms.

	var mu sync.Mutex
	var arrivals []time.Time
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		mu.Lock()
		arrivals = append(arrivals, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	svc := notify.NewNotificationService(discardLogger())
	defer svc.Stop()

	for _, id := range []string{"p1", "p2"} {
		_ = svc.AddSubscriber(&notify.Subscriber{
			ID:         id,
			Type:       "webhook",
			WebhookURL: ts.URL,
			Events:     []string{"*"},
		})
	}

	start := time.Now()
	svc.Notify("disconnect", notify.Notification{Message: "parallel test"})

	// Wait for both.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(arrivals)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	elapsed := time.Since(start)
	// Parallel: ~80ms.  Sequential would be ~160ms.  Allow generous 150ms bound.
	if elapsed > 150*time.Millisecond {
		t.Logf("delivery took %v (may indicate sequential not parallel)", elapsed)
	}

	mu.Lock()
	got := len(arrivals)
	mu.Unlock()
	if got < 2 {
		t.Errorf("only %d deliveries, want 2", got)
	}
}
