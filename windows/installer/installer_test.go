// Tests for the installer. All tests run on Linux (no Windows-specific calls).
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultInstallDir verifies that DefaultInstallDir returns a non-empty string.
func TestDefaultInstallDir(t *testing.T) {
	dir := DefaultInstallDir()
	if dir == "" {
		t.Fatal("DefaultInstallDir returned empty string")
	}
}

// TestWriteDefaultConfig checks that writeDefaultConfig creates a valid JSON config file.
func TestWriteDefaultConfig(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")

	opts := InstallOptions{
		InstallDir: tmp,
		ServerAddr: "10.0.0.1:443",
		ServerKey:  "aabbcc",
	}
	if err := writeDefaultConfig(configPath, opts); err != nil {
		t.Fatalf("writeDefaultConfig: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg defaultConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if cfg.ServerAddr != "10.0.0.1:443" {
		t.Errorf("ServerAddr = %q, want %q", cfg.ServerAddr, "10.0.0.1:443")
	}
	if cfg.ServerKeyHex != "aabbcc" {
		t.Errorf("ServerKeyHex = %q, want %q", cfg.ServerKeyHex, "aabbcc")
	}
	if cfg.DNSServer == "" {
		t.Error("DNSServer should not be empty")
	}
	if cfg.MTU == 0 {
		t.Error("MTU should not be zero")
	}
}

// TestCopyCurrentExe verifies that copyCurrentExe copies the running binary to a temp dir.
func TestCopyCurrentExe(t *testing.T) {
	tmp := t.TempDir()
	dest, err := copyCurrentExe(tmp)
	if err != nil {
		t.Fatalf("copyCurrentExe: %v", err)
	}
	if dest == "" {
		t.Fatal("copyCurrentExe returned empty destination path")
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat dest %s: %v", dest, err)
	}
	if info.Size() == 0 {
		t.Error("copied exe has size 0")
	}
}

// TestInstallOptionsValidation tests the Validate method.
func TestInstallOptionsValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    InstallOptions
		wantErr bool
	}{
		{
			name:    "valid options",
			opts:    InstallOptions{InstallDir: "/tmp/cavad", ServerAddr: "1.2.3.4:443"},
			wantErr: false,
		},
		{
			name:    "empty install dir",
			opts:    InstallOptions{ServerAddr: "1.2.3.4:443"},
			wantErr: true,
		},
		{
			name:    "empty server addr",
			opts:    InstallOptions{InstallDir: "/tmp/cavad"},
			wantErr: true,
		},
		{
			name:    "both empty",
			opts:    InstallOptions{},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestRunInstallMissingDir verifies that RunInstall returns an error when the
// destination dir cannot be created (e.g. parent is a file, not a directory).
func TestRunInstallMissingDir(t *testing.T) {
	tmp := t.TempDir()

	// Create a regular file where a directory is expected.
	barrier := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(barrier, []byte("x"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	opts := InstallOptions{
		InstallDir: filepath.Join(barrier, "CavadVPN"),
		ServerAddr: "127.0.0.1:443",
	}
	err := RunInstall(opts)
	if err == nil {
		t.Error("expected error when install dir cannot be created, got nil")
	}
}

// TestRunUninstallNoop verifies that RunUninstall succeeds gracefully when the
// installation directory does not exist.
func TestRunUninstallNoop(t *testing.T) {
	opts := InstallOptions{
		InstallDir: filepath.Join(t.TempDir(), "nonexistent"),
		ServerAddr: "127.0.0.1:443",
	}
	if err := RunUninstall(opts); err != nil {
		t.Errorf("RunUninstall on non-existent dir should succeed, got: %v", err)
	}
}

// TestCreateInstallDir checks directory creation.
func TestCreateInstallDir(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "sub", "cavadvpn")
	if err := createInstallDir(dir); err != nil {
		t.Fatalf("createInstallDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
}

// TestRemoveInstallDir verifies that config.json is preserved during uninstall.
func TestRemoveInstallDir(t *testing.T) {
	tmp := t.TempDir()

	// Create some files including config.json.
	if err := os.WriteFile(filepath.Join(tmp, "config.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "cavadvpn.exe"), []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := removeInstallDir(tmp); err != nil {
		t.Fatalf("removeInstallDir: %v", err)
	}

	// config.json should still exist.
	if _, err := os.Stat(filepath.Join(tmp, "config.json")); os.IsNotExist(err) {
		t.Error("config.json was removed, but should be preserved")
	}

	// cavadvpn.exe should be gone.
	if _, err := os.Stat(filepath.Join(tmp, "cavadvpn.exe")); !os.IsNotExist(err) {
		t.Error("cavadvpn.exe should have been removed")
	}
}

// TestRunInstall_EndToEnd runs a basic install + verify + uninstall cycle on the
// current (non-Windows) platform. Windows-only steps are skipped via stubs.
func TestRunInstall_EndToEnd(t *testing.T) {
	tmp := t.TempDir()
	opts := InstallOptions{
		InstallDir: tmp,
		ServerAddr: "192.168.1.1:443",
		ServerKey:  "",
		InstallSvc: false, // service registration is a no-op on Linux
		Silent:     true,
	}

	if err := RunInstall(opts); err != nil {
		t.Fatalf("RunInstall: %v", err)
	}

	// config.json must exist.
	configPath := filepath.Join(tmp, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config.json missing after install: %v", err)
	}
	var cfg defaultConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config.json invalid JSON: %v", err)
	}
	if cfg.ServerAddr != "192.168.1.1:443" {
		t.Errorf("ServerAddr = %q, want %q", cfg.ServerAddr, "192.168.1.1:443")
	}

	// cavadvpn.exe must exist.
	if _, err := os.Stat(filepath.Join(tmp, "cavadvpn.exe")); err != nil {
		t.Errorf("cavadvpn.exe missing after install: %v", err)
	}

	// Second install should not overwrite config.json.
	opts2 := opts
	opts2.ServerAddr = "10.0.0.1:443"
	if err := RunInstall(opts2); err != nil {
		t.Fatalf("second RunInstall: %v", err)
	}
	data2, _ := os.ReadFile(configPath)
	var cfg2 defaultConfig
	_ = json.Unmarshal(data2, &cfg2)
	if cfg2.ServerAddr != "192.168.1.1:443" {
		t.Error("second install should not overwrite existing config.json")
	}
}
