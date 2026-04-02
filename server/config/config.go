// Package config provides YAML-based configuration loading and saving for the
// VPN server, including automatic key-pair generation on the first run.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ServerConfig is the top-level server configuration.
type ServerConfig struct {
	// Listen is the TCP address the VPN server binds to.
	Listen string `yaml:"listen"`

	// TunCIDR is the TUN interface address with subnet (e.g. "10.8.0.1/24").
	TunCIDR string `yaml:"tun_cidr"`

	// PrivateKeyFile is the path where the hex-encoded private key is stored.
	// If the file does not exist it is created with a freshly generated key.
	PrivateKeyFile string `yaml:"private_key_file"`

	// AllowedKeys is a list of hex-encoded client public keys that are
	// permitted to connect. An empty list means any key is accepted.
	AllowedKeys []string `yaml:"allowed_keys"`

	// API holds the REST management API settings.
	API APIConfig `yaml:"api"`

	// Log holds logging settings.
	Log LogConfig `yaml:"log"`
}

// APIConfig holds the REST API settings.
type APIConfig struct {
	// Listen is the address the REST API server binds to.
	// Leave empty to disable the API entirely.
	Listen string `yaml:"listen"`

	// Token is the Bearer token required for all authenticated endpoints.
	// Leave empty to disable authentication (not recommended in production).
	Token string `yaml:"token"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	// Level is one of "debug", "info", "warn", "error".
	Level string `yaml:"level"`

	// Format is "text" or "json".
	Format string `yaml:"format"`
}

// Default returns a ServerConfig populated with sensible defaults.
func Default() ServerConfig {
	return ServerConfig{
		Listen:         "0.0.0.0:443",
		TunCIDR:        "10.8.0.1/24",
		PrivateKeyFile: "server_privkey.hex",
		AllowedKeys:    []string{},
		API: APIConfig{
			Listen: "127.0.0.1:8080",
			Token:  "",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// Load reads a YAML file from path and decodes it into ServerConfig.
// Fields not present in the file retain their zero value; callers should
// start from Default() if they need fallback values.
//
// If path does not exist, Load returns (Default(), nil) and writes a default
// configuration file at that path so the operator can customise it.
func Load(path string) (ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return ServerConfig{}, fmt.Errorf("config: read %s: %w", path, err)
		}

		// File absent — create it with defaults.
		cfg := Default()
		if saveErr := Save(path, cfg); saveErr != nil {
			return cfg, fmt.Errorf("config: write default config to %s: %w", path, saveErr)
		}
		return cfg, nil
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return ServerConfig{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return ServerConfig{}, fmt.Errorf("config: validate %s: %w", path, err)
	}

	return cfg, nil
}

// Save marshals cfg to YAML and writes it to path with mode 0600.
// Parent directories are created as needed.
func Save(path string, cfg ServerConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", filepath.Dir(path), err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}

// Validate checks cfg for obvious errors and returns the first one found.
func (cfg ServerConfig) Validate() error {
	if cfg.Listen == "" {
		return errors.New("config: listen address must not be empty")
	}
	if cfg.TunCIDR == "" {
		return errors.New("config: tun_cidr must not be empty")
	}
	if cfg.PrivateKeyFile == "" {
		return errors.New("config: private_key_file must not be empty")
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if cfg.Log.Level != "" && !validLevels[cfg.Log.Level] {
		return fmt.Errorf("config: invalid log level %q (want debug|info|warn|error)", cfg.Log.Level)
	}

	validFormats := map[string]bool{"text": true, "json": true}
	if cfg.Log.Format != "" && !validFormats[cfg.Log.Format] {
		return fmt.Errorf("config: invalid log format %q (want text|json)", cfg.Log.Format)
	}

	for _, k := range cfg.AllowedKeys {
		if b, err := hex.DecodeString(k); err != nil || len(b) != 32 {
			return fmt.Errorf("config: invalid allowed key %q: must be 64 hex chars", k)
		}
	}

	return nil
}

// ParseAllowedKeys decodes the AllowedKeys field into raw [32]byte slices.
func (cfg ServerConfig) ParseAllowedKeys() ([][32]byte, error) {
	out := make([][32]byte, 0, len(cfg.AllowedKeys))
	for _, k := range cfg.AllowedKeys {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("config: invalid allowed key %q", k)
		}
		var arr [32]byte
		copy(arr[:], b)
		out = append(out, arr)
	}
	return out, nil
}

// EnsureKeyFile generates a new X25519 private key and writes it to path if
// the file does not already exist. Returns the hex-encoded private key
// regardless of whether it was generated or loaded from disk.
//
// The file is created with mode 0600 so it is readable only by the owner.
func EnsureKeyFile(path string) (privKeyHex string, generated bool, err error) {
	data, err := os.ReadFile(path)
	if err == nil {
		// File exists — return as-is after basic sanity check.
		privKeyHex = string(data)
		if _, decErr := hex.DecodeString(privKeyHex); decErr != nil {
			return "", false, fmt.Errorf("config: key file %s contains invalid hex: %w", path, decErr)
		}
		return privKeyHex, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("config: read key file %s: %w", path, err)
	}

	// Generate a new 32-byte random private key.
	// Caller is responsible for applying X25519 RFC 7748 clamping if needed.
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return "", false, fmt.Errorf("config: generate key: %w", err)
	}

	// Apply RFC 7748 clamping for X25519 compatibility.
	rawKey[0] &= 248
	rawKey[31] &= 127
	rawKey[31] |= 64

	privKeyHex = hex.EncodeToString(rawKey)

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", false, fmt.Errorf("config: mkdir for key file: %w", err)
	}
	if err := os.WriteFile(path, []byte(privKeyHex), 0600); err != nil {
		return "", false, fmt.Errorf("config: write key file %s: %w", path, err)
	}

	return privKeyHex, true, nil
}
