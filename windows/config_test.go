package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ServerAddr == "" {
		t.Error("DefaultConfig: ServerAddr should not be empty")
	}
	if cfg.MTU <= 0 {
		t.Error("DefaultConfig: MTU should be positive")
	}
	if cfg.DNSServer == "" {
		t.Error("DefaultConfig: DNSServer should not be empty")
	}
}

func TestLoadConfigFromBytes(t *testing.T) {
	privKey := strings.Repeat("ab", 32) // 64 hex chars

	tests := []struct {
		name    string
		json    string
		wantErr bool
		check   func(*Config)
	}{
		{
			name: "valid minimal config",
			json: `{"server_addr":"1.2.3.4:443","private_key":"` + privKey + `"}`,
			check: func(c *Config) {
				if c.ServerAddr != "1.2.3.4:443" {
					t.Errorf("ServerAddr: got %s, want 1.2.3.4:443", c.ServerAddr)
				}
				if c.PrivateKeyHex != privKey {
					t.Errorf("PrivateKeyHex mismatch")
				}
			},
		},
		{
			name: "full config",
			json: `{"server_addr":"10.0.0.1:8443","private_key":"` + privKey + `","kill_switch":true,"auto_start":true,"dns_server":"8.8.8.8","mtu":1400}`,
			check: func(c *Config) {
				if !c.KillSwitch {
					t.Error("KillSwitch should be true")
				}
				if !c.AutoStart {
					t.Error("AutoStart should be true")
				}
				if c.DNSServer != "8.8.8.8" {
					t.Errorf("DNSServer: got %s, want 8.8.8.8", c.DNSServer)
				}
				if c.MTU != 1400 {
					t.Errorf("MTU: got %d, want 1400", c.MTU)
				}
			},
		},
		{
			name:    "invalid json",
			json:    `{not valid json`,
			wantErr: true,
		},
		{
			name: "defaults preserved for missing fields",
			json: `{"server_addr":"1.2.3.4:443","private_key":"` + privKey + `"}`,
			check: func(c *Config) {
				if c.MTU != 1420 {
					t.Errorf("MTU default: got %d, want 1420", c.MTU)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadConfigFromBytes([]byte(tt.json))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(cfg)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	privKey := strings.Repeat("cd", 32)

	t.Run("file not found", func(t *testing.T) {
		_, err := LoadConfig("/nonexistent/path/config.json")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("valid file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		data := `{"server_addr":"5.6.7.8:443","private_key":"` + privKey + `"}`
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if cfg.ServerAddr != "5.6.7.8:443" {
			t.Errorf("ServerAddr: got %s", cfg.ServerAddr)
		}
	})

	t.Run("invalid json file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte("{bad json}"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(path)
		if err == nil {
			t.Error("expected error for invalid json")
		}
	})
}

func TestSaveConfig(t *testing.T) {
	privKey := strings.Repeat("ef", 32)

	t.Run("save and reload", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "subdir", "config.json")

		cfg := &Config{
			ServerAddr:    "9.9.9.9:443",
			PrivateKeyHex: privKey,
			MTU:           1380,
			DNSServer:     "9.9.9.9",
			KillSwitch:    true,
			AutoStart:     false,
		}

		if err := SaveConfig(path, cfg); err != nil {
			t.Fatalf("SaveConfig: %v", err)
		}

		loaded, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if loaded.ServerAddr != cfg.ServerAddr {
			t.Errorf("ServerAddr mismatch: got %s", loaded.ServerAddr)
		}
		if loaded.MTU != cfg.MTU {
			t.Errorf("MTU mismatch: got %d", loaded.MTU)
		}
		if loaded.KillSwitch != cfg.KillSwitch {
			t.Errorf("KillSwitch mismatch")
		}
	})

	t.Run("file permissions", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		cfg := DefaultConfig()
		cfg.PrivateKeyHex = privKey
		if err := SaveConfig(path, &cfg); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("file permissions: got %o, want 0600", info.Mode().Perm())
		}
	})

	t.Run("json format valid", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		cfg := DefaultConfig()
		cfg.PrivateKeyHex = privKey
		if err := SaveConfig(path, &cfg); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]interface{}
		if err := json.Unmarshal(data, &out); err != nil {
			t.Errorf("saved config is not valid JSON: %v", err)
		}
	})
}

func TestValidateConfig(t *testing.T) {
	validKey := strings.Repeat("a1", 32)

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "empty server addr",
			cfg:     Config{PrivateKeyHex: validKey},
			wantErr: "server_addr",
		},
		{
			name:    "empty private key",
			cfg:     Config{ServerAddr: "1.2.3.4:443"},
			wantErr: "private_key",
		},
		{
			name:    "wrong length private key",
			cfg:     Config{ServerAddr: "1.2.3.4:443", PrivateKeyHex: "abcd"},
			wantErr: "64 hex",
		},
		{
			name:    "invalid hex chars in key",
			cfg:     Config{ServerAddr: "1.2.3.4:443", PrivateKeyHex: strings.Repeat("zz", 32)},
			wantErr: "invalid hex",
		},
		{
			name: "server_key wrong length",
			cfg: Config{
				ServerAddr:    "1.2.3.4:443",
				PrivateKeyHex: validKey,
				ServerKeyHex:  "abcd",
			},
			wantErr: "server_key",
		},
		{
			name:    "negative mtu",
			cfg:     Config{ServerAddr: "1.2.3.4:443", PrivateKeyHex: validKey, MTU: -1},
			wantErr: "mtu",
		},
		{
			name: "valid config",
			cfg:  Config{ServerAddr: "1.2.3.4:443", PrivateKeyHex: validKey, MTU: 1420},
		},
		{
			name: "valid with server key",
			cfg: Config{
				ServerAddr:    "1.2.3.4:443",
				PrivateKeyHex: validKey,
				ServerKeyHex:  validKey,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestConfigDir(t *testing.T) {
	dir, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	if dir == "" {
		t.Error("ConfigDir returned empty string")
	}
}

func TestConfigFilePath(t *testing.T) {
	path, err := ConfigFilePath()
	if err != nil {
		t.Fatalf("ConfigFilePath: %v", err)
	}
	if path == "" {
		t.Error("ConfigFilePath returned empty string")
	}
	if filepath.Base(path) != "config.json" {
		t.Errorf("ConfigFilePath base: got %s, want config.json", filepath.Base(path))
	}
}
