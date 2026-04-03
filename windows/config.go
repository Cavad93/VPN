package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config holds the VPN client configuration.
type Config struct {
	ServerAddr    string `json:"server_addr"`
	PrivateKeyHex string `json:"private_key"`
	ServerKeyHex  string `json:"server_key,omitempty"`
	AutoStart     bool   `json:"auto_start"`
	KillSwitch    bool   `json:"kill_switch"`
	DNSServer     string `json:"dns_server,omitempty"`
	MTU           int    `json:"mtu,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ServerAddr: "127.0.0.1:443",
		MTU:        1420,
		DNSServer:  "1.1.1.1",
	}
}

// Validate checks the configuration for correctness.
func (c *Config) Validate() error {
	if c.ServerAddr == "" {
		return errors.New("config: server_addr is required")
	}
	if c.PrivateKeyHex == "" {
		return errors.New("config: private_key is required")
	}
	if len(c.PrivateKeyHex) != 64 {
		return fmt.Errorf("config: private_key must be 64 hex chars, got %d", len(c.PrivateKeyHex))
	}
	// Validate private key is valid hex
	for _, ch := range strings.ToLower(c.PrivateKeyHex) {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return errors.New("config: private_key contains invalid hex characters")
		}
	}
	if c.ServerKeyHex != "" && len(c.ServerKeyHex) != 64 {
		return fmt.Errorf("config: server_key must be 64 hex chars if set, got %d", len(c.ServerKeyHex))
	}
	if c.MTU < 0 {
		return fmt.Errorf("config: mtu must be non-negative, got %d", c.MTU)
	}
	return nil
}

// ConfigDir returns the platform-appropriate config directory.
func ConfigDir() (string, error) {
	return configDir()
}

// ConfigFilePath returns the default config file path.
func ConfigFilePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// LoadConfig reads and parses a JSON config file from path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &cfg, nil
}

// LoadConfigFromBytes parses a JSON config from a byte slice.
func LoadConfigFromBytes(data []byte) (*Config, error) {
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	return &cfg, nil
}

// SaveConfig writes the config as JSON to path, creating parent directories as needed.
func SaveConfig(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}
