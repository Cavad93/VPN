//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// isAdmin returns true when the process has administrator privileges.
func isAdmin() bool {
	// SID for the local Administrators group.
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid, nil)
	if err != nil {
		return false
	}
	token := windows.GetCurrentProcessToken()
	ok, err := token.IsMember(adminSID)
	if err != nil {
		return false
	}
	return ok
}

// startMenuDir returns the CavadVPN folder inside the shared Start Menu Programs directory.
func startMenuDir() (string, error) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\CavadVPN`), nil
}

// registerService creates a Windows service named name that runs exePath.
func registerService(name, exePath, configPath string) error {
	args := []string{
		"create", name,
		"binPath=", fmt.Sprintf(`"%s" --config "%s"`, exePath, configPath),
		"start=", "auto",
		"DisplayName=", "CavadVPN Service",
	}
	out, err := exec.Command("sc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("registerService: sc create: %s: %w", out, err)
	}
	// Set failure actions: restart after 30s, 60s, 120s.
	out, err = exec.Command("sc", "failure", name,
		"reset=", "86400",
		"actions=", "restart/30000/restart/60000/restart/120000",
	).CombinedOutput()
	if err != nil {
		// Non-fatal — service is already registered.
		_ = out
	}
	return nil
}

// stopAndRemoveService stops and deletes a Windows service.
func stopAndRemoveService(name string) error {
	// Ignore errors — the service may not exist.
	_ = exec.Command("sc", "stop", name).Run()
	out, err := exec.Command("sc", "delete", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("stopAndRemoveService: sc delete: %s: %w", out, err)
	}
	return nil
}

// addFirewallRule adds an outbound allow rule for exePath.
func addFirewallRule(name, exePath string) error {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name,
		"dir=out",
		"action=allow",
		"program="+exePath,
		"enable=yes",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("addFirewallRule: %s: %w", out, err)
	}
	return nil
}

// removeFirewallRules deletes all firewall rules with the given name.
func removeFirewallRules(name string) error {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+name,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("removeFirewallRules: %s: %w", out, err)
	}
	return nil
}

// createStartMenuShortcut creates a .lnk shortcut in shortcutDir.
func createStartMenuShortcut(name, exePath, shortcutDir string) error {
	if err := os.MkdirAll(shortcutDir, 0755); err != nil {
		return fmt.Errorf("createStartMenuShortcut: mkdir: %w", err)
	}
	lnkPath := filepath.Join(shortcutDir, name+".lnk")
	// Use PowerShell WScript.Shell to create the shortcut.
	script := fmt.Sprintf(
		`$ws = New-Object -ComObject WScript.Shell; `+
			`$sc = $ws.CreateShortcut('%s'); `+
			`$sc.TargetPath = '%s'; `+
			`$sc.Save()`,
		lnkPath, exePath,
	)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("createStartMenuShortcut: powershell: %s: %w", out, err)
	}
	return nil
}

// removeStartMenuShortcut removes the CavadVPN shortcut directory from the Start Menu.
func removeStartMenuShortcut(shortcutDir string) error {
	return os.RemoveAll(shortcutDir)
}

// registerUninstall adds an entry under HKLM uninstall key so the app appears
// in "Add or Remove Programs".
func registerUninstall(appName, installDir, uninstallCmd string) error {
	key, _, err := registry.CreateKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`+appName,
		registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("registerUninstall: create key: %w", err)
	}
	defer key.Close()

	values := map[string]string{
		"DisplayName":     "CavadVPN",
		"DisplayVersion":  "1.0.0",
		"Publisher":       "CavadVPN",
		"InstallLocation": installDir,
		"UninstallString": uninstallCmd,
		"NoModify":        "", // set as DWORD below
		"NoRepair":        "",
	}
	for k, v := range values {
		if k == "NoModify" || k == "NoRepair" {
			_ = key.SetDWordValue(k, 1)
			continue
		}
		if err := key.SetStringValue(k, v); err != nil {
			return fmt.Errorf("registerUninstall: set %s: %w", k, err)
		}
	}
	return nil
}

// removeUninstallEntry deletes the app's registry uninstall entry.
func removeUninstallEntry(appName string) error {
	return registry.DeleteKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`+appName,
	)
}
