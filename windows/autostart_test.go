package main

import (
	"errors"
	"testing"
)

func TestNewAutoStart(t *testing.T) {
	as := NewAutoStart()
	if as == nil {
		t.Fatal("NewAutoStart returned nil")
	}
}

func TestAutoStartStubNotWindows(t *testing.T) {
	as := NewAutoStart()

	// On non-Windows, all operations should return ErrNotWindows
	if err := as.Enable("/usr/local/bin/cavadvpn"); !errors.Is(err, ErrNotWindows) {
		t.Errorf("Enable: expected ErrNotWindows, got %v", err)
	}
	if err := as.Disable(); !errors.Is(err, ErrNotWindows) {
		t.Errorf("Disable: expected ErrNotWindows, got %v", err)
	}
	enabled, err := as.IsEnabled()
	if !errors.Is(err, ErrNotWindows) {
		t.Errorf("IsEnabled: expected ErrNotWindows, got %v", err)
	}
	if enabled {
		t.Error("IsEnabled should return false on non-Windows")
	}
}

func TestAutoStartEnableEmptyPath(t *testing.T) {
	as := NewAutoStart()
	// Empty path should still return ErrNotWindows on non-Windows
	err := as.Enable("")
	if !errors.Is(err, ErrNotWindows) {
		t.Errorf("Enable with empty path: expected ErrNotWindows, got %v", err)
	}
}
