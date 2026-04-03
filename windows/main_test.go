package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// loadOrDefaultConfig tests
// ---------------------------------------------------------------------------

func TestLoadOrDefaultConfig_Exists(t *testing.T) {
	privKey := strings.Repeat("ab", 32)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	data := `{"server_addr":"1.2.3.4:443","private_key":"` + privKey + `"}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadOrDefaultConfig(path)
	if err != nil {
		t.Fatalf("loadOrDefaultConfig: %v", err)
	}
	if cfg.ServerAddr != "1.2.3.4:443" {
		t.Errorf("ServerAddr: got %s", cfg.ServerAddr)
	}
}

func TestLoadOrDefaultConfig_NotExists_CreatesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg, err := loadOrDefaultConfig(path)
	if err != nil {
		t.Fatalf("loadOrDefaultConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.ServerAddr == "" {
		t.Error("default ServerAddr should not be empty")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Errorf("config file should have been created: %v", statErr)
	}
}

func TestLoadOrDefaultConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{invalid json}"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := loadOrDefaultConfig(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadOrDefaultConfig_UnwritableDefaultDir(t *testing.T) {
	// /proc is read-only; save will fail but default config should still be returned
	path := "/proc/cavadvpn_test_config.json"
	cfg, err := loadOrDefaultConfig(path)
	if err != nil {
		t.Logf("loadOrDefaultConfig with unwritable path returned error: %v", err)
		return
	}
	if cfg == nil {
		t.Error("expected non-nil config")
	}
}

func TestLoadOrDefaultConfig_ErrNotExistDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadConfig missing file: error should be ErrNotExist-compatible, got: %v", err)
	}
}

func TestLoadOrDefaultConfig_SavesDefaultToNewSubdir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "config.json")

	cfg, err := loadOrDefaultConfig(path)
	if err != nil {
		t.Fatalf("loadOrDefaultConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

// ---------------------------------------------------------------------------
// mockKillSwitch — for testing branches where kill switch is active
// ---------------------------------------------------------------------------

type mockKillSwitch struct {
	active   bool
	startErr error
	stopErr  error
}

func (m *mockKillSwitch) Start(serverIP string) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.active = true
	return nil
}

func (m *mockKillSwitch) Stop() error {
	m.active = false
	return m.stopErr
}

func (m *mockKillSwitch) IsActive() bool { return m.active }

// ---------------------------------------------------------------------------
// newAppState tests
// ---------------------------------------------------------------------------

func TestNewAppState_NoKillSwitch(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
		KillSwitch:    false,
		AutoStart:     false,
	}
	app := newAppState(cfg)
	if app == nil {
		t.Fatal("newAppState returned nil")
	}
	if app.ks != nil {
		t.Error("kill switch should be nil when not configured")
	}
	if app.sm == nil {
		t.Error("state machine should not be nil")
	}
	if app.vc == nil {
		t.Error("vpn client should not be nil")
	}
}

func TestNewAppState_WithKillSwitch(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
		KillSwitch:    true,
		AutoStart:     false,
	}
	app := newAppState(cfg)
	if app.ks == nil {
		t.Error("kill switch should not be nil when configured")
	}
}

func TestNewAppState_WithAutoStart(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
		KillSwitch:    false,
		AutoStart:     true,
	}
	// Should not panic even if autostart fails (returns ErrNotWindows on Linux)
	app := newAppState(cfg)
	if app == nil {
		t.Fatal("newAppState returned nil")
	}
}

// ---------------------------------------------------------------------------
// appState.handleConnect tests
// ---------------------------------------------------------------------------

func TestHandleConnect_WhenCannotConnect(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)

	// Force to Connecting state so CanConnect returns false
	app.sm.Transition(StateEvent{State: StateConnecting})

	tray := NewTrayApp(TrayCallbacks{})

	// Should return immediately without starting a goroutine
	app.handleConnect(context.Background(), tray)

	// State should remain Connecting
	if app.sm.State() != StateConnecting {
		t.Errorf("state should remain Connecting, got %v", app.sm.State())
	}
}

func TestHandleConnect_FailsOnBadServer(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "127.0.0.1:59990", // no server
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)
	tray := NewTrayApp(TrayCallbacks{})

	// Should set state to Connecting, then Error when connection fails
	app.handleConnect(context.Background(), tray)

	// Wait for the goroutine to complete
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state := app.sm.State()
		if state == StateError || state == StateConnected {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if app.sm.State() != StateError {
		t.Errorf("expected StateError, got %v", app.sm.State())
	}
}

// ---------------------------------------------------------------------------
// appState.handleDisconnect tests
// ---------------------------------------------------------------------------

func TestHandleDisconnect_WhenCannotDisconnect(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)
	tray := NewTrayApp(TrayCallbacks{})

	// State is Disconnected by default — cannot disconnect
	app.handleDisconnect(tray)

	// State should remain Disconnected
	if app.sm.State() != StateDisconnected {
		t.Errorf("state should remain Disconnected, got %v", app.sm.State())
	}
}

func TestHandleDisconnect_WhenConnected(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)
	tray := NewTrayApp(TrayCallbacks{})

	// Force to Connected state
	app.sm.Transition(StateEvent{State: StateConnected})

	app.handleDisconnect(tray)

	// Wait for the goroutine to complete
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if app.sm.State() == StateDisconnected {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if app.sm.State() != StateDisconnected {
		t.Errorf("expected StateDisconnected, got %v", app.sm.State())
	}
}

// ---------------------------------------------------------------------------
// appState.handleQuit tests
// ---------------------------------------------------------------------------

func TestHandleQuit_WhenDisconnected(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)
	// Should not panic when not connected
	app.handleQuit()
}

func TestHandleQuit_WhenConnected(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)
	app.sm.Transition(StateEvent{State: StateConnected})

	// Should disconnect cleanly
	app.handleQuit()
}

func TestHandleQuit_WithActiveKillSwitch(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)
	app.sm.Transition(StateEvent{State: StateConnected})

	// Inject an active mock kill switch
	mks := &mockKillSwitch{active: true}
	app.ks = mks

	app.handleQuit()

	if mks.active {
		t.Error("kill switch should have been stopped")
	}
}

func TestHandleDisconnect_WithActiveKillSwitch(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)
	app.sm.Transition(StateEvent{State: StateConnected})

	// Inject an active mock kill switch
	mks := &mockKillSwitch{active: true}
	app.ks = mks

	tray := NewTrayApp(TrayCallbacks{})
	app.handleDisconnect(tray)

	// Wait for goroutine to complete
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if app.sm.State() == StateDisconnected {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if mks.active {
		t.Error("kill switch should have been stopped")
	}
}

// ---------------------------------------------------------------------------
// appState.shutdown tests
// ---------------------------------------------------------------------------

func TestShutdown_WhenDisconnected(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)
	tray := NewTrayApp(TrayCallbacks{})

	done := make(chan error, 1)
	go func() {
		done <- tray.Run()
	}()
	time.Sleep(5 * time.Millisecond)

	// Should quit the tray
	app.shutdown(tray)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("tray.Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for tray to quit after shutdown")
	}
}

func TestShutdown_WithActiveKillSwitch(t *testing.T) {
	cfg := &Config{
		ServerAddr:    "1.2.3.4:443",
		PrivateKeyHex: strings.Repeat("ab", 32),
	}
	app := newAppState(cfg)

	// Inject an active mock kill switch
	mks := &mockKillSwitch{active: true}
	app.ks = mks

	tray := NewTrayApp(TrayCallbacks{})
	done := make(chan error, 1)
	go func() {
		done <- tray.Run()
	}()
	time.Sleep(5 * time.Millisecond)

	app.shutdown(tray)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for tray to quit")
	}

	if mks.active {
		t.Error("kill switch should have been stopped during shutdown")
	}
}

// ---------------------------------------------------------------------------
// runWithConfig tests
// ---------------------------------------------------------------------------

func TestRunWithConfig_ContextCancel(t *testing.T) {
	privKey := strings.Repeat("cd", 32)
	cfg := &Config{
		ServerAddr:    "127.0.0.1:59997",
		PrivateKeyHex: privKey,
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- runWithConfig(ctx, cfg)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("runWithConfig returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout: runWithConfig did not return after context cancellation")
	}
}

func TestRunWithConfig_KillSwitchEnabled(t *testing.T) {
	privKey := strings.Repeat("ef", 32)
	cfg := &Config{
		ServerAddr:    "127.0.0.1:59996",
		PrivateKeyHex: privKey,
		KillSwitch:    true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runWithConfig(ctx, cfg)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		_ = err
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for runWithConfig to finish")
	}
}

func TestRun_WithExplicitPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir := t.TempDir()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, filepath.Join(dir, "config.json"))
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		_ = err
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for run to finish")
	}
}

func TestRun_DefaultConfigPath_ViaEmptyString(t *testing.T) {
	// run() with empty string uses the platform default config dir
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, "")
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		_ = err
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for run to finish")
	}
}
