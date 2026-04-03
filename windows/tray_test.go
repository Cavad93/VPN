package main

import (
	"testing"
	"time"
)

func TestNewTrayApp(t *testing.T) {
	tray := NewTrayApp(TrayCallbacks{})
	if tray == nil {
		t.Fatal("NewTrayApp returned nil")
	}
}

func TestTraySetStatus(t *testing.T) {
	tray := NewTrayApp(TrayCallbacks{})

	// SetStatus should not panic for any state
	states := []struct {
		state ConnectionState
		ip    string
	}{
		{StateDisconnected, ""},
		{StateConnecting, ""},
		{StateConnected, "10.8.0.2"},
		{StateDisconnecting, ""},
		{StateError, ""},
	}

	for _, s := range states {
		tray.SetStatus(s.state, s.ip) // should not panic
	}
}

func TestTrayQuitAndRun(t *testing.T) {
	tray := NewTrayApp(TrayCallbacks{
		OnQuit: func() {},
	})

	done := make(chan error, 1)
	go func() {
		done <- tray.Run()
	}()

	// Give Run a moment to start
	time.Sleep(5 * time.Millisecond)

	// Quit should unblock Run
	tray.Quit()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout: Run did not return after Quit")
	}
}

func TestTrayQuitIdempotent(t *testing.T) {
	tray := NewTrayApp(TrayCallbacks{})

	done := make(chan error, 1)
	go func() {
		done <- tray.Run()
	}()
	time.Sleep(5 * time.Millisecond)

	// Calling Quit multiple times should not panic
	tray.Quit()
	tray.Quit()
	tray.Quit()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("timeout after multiple Quit calls")
	}
}

func TestTrayCallbacks(t *testing.T) {
	// Verify callbacks can be set and are stored
	connectCalled := false
	disconnectCalled := false

	callbacks := TrayCallbacks{
		OnConnect: func() {
			connectCalled = true
		},
		OnDisconnect: func() {
			disconnectCalled = true
		},
	}

	tray := NewTrayApp(callbacks)
	if tray == nil {
		t.Fatal("NewTrayApp returned nil")
	}

	// Callbacks are not called just by creating the tray
	if connectCalled {
		t.Error("OnConnect should not be called on creation")
	}
	if disconnectCalled {
		t.Error("OnDisconnect should not be called on creation")
	}
}
