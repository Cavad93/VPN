package main

import (
	"errors"
	"testing"
)

func TestNewKillSwitch(t *testing.T) {
	ks := NewKillSwitch()
	if ks == nil {
		t.Fatal("NewKillSwitch returned nil")
	}
}

func TestKillSwitchStubNotWindows(t *testing.T) {
	ks := NewKillSwitch()

	// On non-Windows, all operations should return ErrNotWindows
	if err := ks.Start("1.2.3.4"); !errors.Is(err, ErrNotWindows) {
		t.Errorf("Start: expected ErrNotWindows, got %v", err)
	}
	if err := ks.Stop(); !errors.Is(err, ErrNotWindows) {
		t.Errorf("Stop: expected ErrNotWindows, got %v", err)
	}
	if ks.IsActive() {
		t.Error("IsActive should be false on non-Windows")
	}
}

func TestKillSwitchErrNotWindowsMessage(t *testing.T) {
	if ErrNotWindows == nil {
		t.Fatal("ErrNotWindows should not be nil")
	}
	if ErrNotWindows.Error() == "" {
		t.Error("ErrNotWindows should have a non-empty message")
	}
}

func TestKillSwitchIsActiveInitially(t *testing.T) {
	ks := NewKillSwitch()
	// Should not be active before Start is called
	if ks.IsActive() {
		t.Error("KillSwitch should not be active initially")
	}
}
