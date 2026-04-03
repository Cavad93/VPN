//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

const (
	regRunKey  = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	regValName = "CavadVPN"
)

// windowsAutoStart implements AutoStart using reg.exe on Windows.
type windowsAutoStart struct{}

func newAutoStart() AutoStart {
	return &windowsAutoStart{}
}

func (a *windowsAutoStart) Enable(exePath string) error {
	value := fmt.Sprintf(`"%s" -minimized`, exePath)
	out, err := exec.Command("reg", "add", regRunKey,
		"/v", regValName,
		"/t", "REG_SZ",
		"/d", value,
		"/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("autostart: reg add: %s: %w", out, err)
	}
	return nil
}

func (a *windowsAutoStart) Disable() error {
	out, err := exec.Command("reg", "delete", regRunKey,
		"/v", regValName,
		"/f").CombinedOutput()
	if err != nil {
		// Ignore "not found" errors
		if strings.Contains(string(out), "ERROR: The system was unable to find") ||
			strings.Contains(string(out), "not found") {
			return nil
		}
		return fmt.Errorf("autostart: reg delete: %s: %w", out, err)
	}
	return nil
}

func (a *windowsAutoStart) IsEnabled() (bool, error) {
	out, err := exec.Command("reg", "query", regRunKey,
		"/v", regValName).CombinedOutput()
	if err != nil {
		// Value not found means not enabled
		if strings.Contains(string(out), "ERROR: The system was unable to find") ||
			strings.Contains(string(out), "not found") {
			return false, nil
		}
		return false, fmt.Errorf("autostart: reg query: %s: %w", out, err)
	}
	return strings.Contains(string(out), regValName), nil
}
