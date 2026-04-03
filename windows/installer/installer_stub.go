//go:build !windows

package main

import "errors"

var errNotWindows = errors.New("not supported on this platform")

// isAdmin always returns true on non-Windows so that platform-agnostic install
// steps can proceed during testing without a privilege check.
func isAdmin() bool { return true }

// startMenuDir is not meaningful on non-Windows platforms.
func startMenuDir() (string, error) {
	return "", errNotWindows
}

// registerService is a no-op stub.
func registerService(name, exePath, configPath string) error {
	return errNotWindows
}

// stopAndRemoveService is a no-op stub.
func stopAndRemoveService(name string) error {
	return errNotWindows
}

// addFirewallRule is a no-op stub.
func addFirewallRule(name, exePath string) error {
	return errNotWindows
}

// removeFirewallRules is a no-op stub.
func removeFirewallRules(name string) error {
	return errNotWindows
}

// createStartMenuShortcut is a no-op stub.
func createStartMenuShortcut(name, exePath, shortcutDir string) error {
	return errNotWindows
}

// removeStartMenuShortcut is a no-op stub.
func removeStartMenuShortcut(shortcutDir string) error {
	return errNotWindows
}

// registerUninstall is a no-op stub.
func registerUninstall(appName, installDir, uninstallCmd string) error {
	return errNotWindows
}

// removeUninstallEntry is a no-op stub.
func removeUninstallEntry(appName string) error {
	return errNotWindows
}
