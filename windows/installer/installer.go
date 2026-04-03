// Command cavadvpn-setup is the CavadVPN Windows .exe self-installer.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// InstallOptions holds configuration for the installer.
type InstallOptions struct {
	InstallDir  string
	ServerAddr  string
	ServerKey   string
	InstallSvc  bool
	Silent      bool
	Uninstall   bool
}

// DefaultInstallDir returns the platform-appropriate default install directory.
func DefaultInstallDir() string {
	if runtime.GOOS == "windows" {
		// On Windows use %ProgramFiles%\CavadVPN
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		return filepath.Join(pf, "CavadVPN")
	}
	// On other platforms (used during tests) fall back to a temp-relative path.
	return filepath.Join(os.TempDir(), "CavadVPN")
}

// defaultConfig is a minimal JSON config written during installation.
type defaultConfig struct {
	ServerAddr   string `json:"server_addr"`
	ServerKeyHex string `json:"server_key,omitempty"`
	AutoStart    bool   `json:"auto_start"`
	KillSwitch   bool   `json:"kill_switch"`
	DNSServer    string `json:"dns_server,omitempty"`
	MTU          int    `json:"mtu,omitempty"`
}

// Validate checks InstallOptions for obvious errors.
func (o *InstallOptions) Validate() error {
	if o.InstallDir == "" {
		return errors.New("installer: install_dir must not be empty")
	}
	if o.ServerAddr == "" {
		return errors.New("installer: server_addr must not be empty")
	}
	return nil
}

// RunInstall performs the full installation sequence.
// Steps that require Windows APIs are delegated to platform-specific helpers.
func RunInstall(opts InstallOptions) error {
	if opts.InstallDir == "" {
		opts.InstallDir = DefaultInstallDir()
	}
	if opts.ServerAddr == "" {
		opts.ServerAddr = "127.0.0.1:443"
	}

	// 1. Check admin rights (Windows-only; stub always returns true on other platforms).
	if !isAdmin() {
		return errors.New("installer: administrator privileges are required")
	}

	// 2. Create install directory.
	if err := createInstallDir(opts.InstallDir); err != nil {
		return fmt.Errorf("installer: create dir: %w", err)
	}

	// 3. Copy the currently running executable.
	exeDest, err := copyCurrentExe(opts.InstallDir)
	if err != nil {
		return fmt.Errorf("installer: copy exe: %w", err)
	}

	// 4. Write default config (skip if already present).
	configPath := filepath.Join(opts.InstallDir, "config.json")
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
		if err := writeDefaultConfig(configPath, opts); err != nil {
			return fmt.Errorf("installer: write config: %w", err)
		}
	}

	// 5. (Windows) Register Windows service.
	if opts.InstallSvc {
		if err := registerService("CavadVPN", exeDest, configPath); err != nil {
			return fmt.Errorf("installer: register service: %w", err)
		}
	}

	// 6. (Windows) Create Start Menu shortcut.
	if shortcutDir, err := startMenuDir(); err == nil {
		_ = createStartMenuShortcut("CavadVPN", exeDest, shortcutDir)
	}

	// 7. (Windows) Add registry uninstall entry.
	uninstallCmd := fmt.Sprintf(`"%s" --uninstall`, exeDest)
	_ = registerUninstall("CavadVPN", opts.InstallDir, uninstallCmd)

	// 8. (Windows) Add outbound firewall allow rule.
	_ = addFirewallRule("CavadVPN-Allow-Out", exeDest)

	return nil
}

// RunUninstall removes the installation.
// config.json is intentionally preserved so the user's settings are not lost.
func RunUninstall(opts InstallOptions) error {
	if opts.InstallDir == "" {
		opts.InstallDir = DefaultInstallDir()
	}

	// 1. (Windows) Stop and delete service.
	_ = stopAndRemoveService("CavadVPN")

	// 2. (Windows) Remove firewall rules.
	_ = removeFirewallRules("CavadVPN-Allow-Out")

	// 3. (Windows) Remove Start Menu shortcut.
	if shortcutDir, err := startMenuDir(); err == nil {
		_ = removeStartMenuShortcut(shortcutDir)
	}

	// 4. (Windows) Remove registry uninstall entry.
	_ = removeUninstallEntry("CavadVPN")

	// 5. Remove install directory (keep config.json).
	if err := removeInstallDir(opts.InstallDir); err != nil {
		return fmt.Errorf("installer: remove dir: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Platform-agnostic helpers
// ---------------------------------------------------------------------------

// createInstallDir creates the installation directory (and parents) if needed.
func createInstallDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}

// copyCurrentExe copies the running executable to destDir/cavadvpn.exe.
// Returns the destination path.
func copyCurrentExe(destDir string) (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("copyCurrentExe: cannot determine executable path: %w", err)
	}
	// Resolve symlinks so we copy the real binary.
	src, err = filepath.EvalSymlinks(src)
	if err != nil {
		return "", fmt.Errorf("copyCurrentExe: eval symlinks: %w", err)
	}

	dest := filepath.Join(destDir, "cavadvpn.exe")
	if err := copyFile(src, dest); err != nil {
		return "", fmt.Errorf("copyCurrentExe: %w", err)
	}
	return dest, nil
}

// writeDefaultConfig writes a minimal config.json to configPath.
func writeDefaultConfig(configPath string, opts InstallOptions) error {
	cfg := defaultConfig{
		ServerAddr:   opts.ServerAddr,
		ServerKeyHex: opts.ServerKey,
		DNSServer:    "1.1.1.1",
		MTU:          1420,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("writeDefaultConfig: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("writeDefaultConfig: mkdir: %w", err)
	}
	return os.WriteFile(configPath, data, 0600)
}

// removeInstallDir removes everything inside dir except config.json.
func removeInstallDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already gone — success
		}
		return err
	}
	for _, e := range entries {
		if e.Name() == "config.json" {
			continue // preserve user config
		}
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
	// Attempt to remove the directory itself (will fail if config.json remains — that's fine).
	_ = os.Remove(dir)
	return nil
}

// copyFile copies src to dst, overwriting dst if it already exists.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
