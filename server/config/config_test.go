package config_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavad93/vpn/server/config"
)

// ---------------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------------

func TestDefault_Values(t *testing.T) {
	t.Parallel()
	cfg := config.Default()

	if cfg.Listen == "" {
		t.Error("Default: Listen must not be empty")
	}
	if cfg.TunCIDR == "" {
		t.Error("Default: TunCIDR must not be empty")
	}
	if cfg.PrivateKeyFile == "" {
		t.Error("Default: PrivateKeyFile must not be empty")
	}
	if cfg.Log.Level == "" {
		t.Error("Default: Log.Level must not be empty")
	}
	if cfg.Log.Format == "" {
		t.Error("Default: Log.Format must not be empty")
	}
}

func TestDefault_Valid(t *testing.T) {
	t.Parallel()
	if err := config.Default().Validate(); err != nil {
		t.Errorf("Default config must be valid, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate_EmptyListen(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Listen = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty listen address")
	}
}

func TestValidate_EmptyTunCIDR(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.TunCIDR = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty tun_cidr")
	}
}

func TestValidate_EmptyPrivKeyFile(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.PrivateKeyFile = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty private_key_file")
	}
}

func TestValidate_BadLogLevel(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Log.Level = "verbose"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid log level")
	}
}

func TestValidate_BadLogFormat(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Log.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid log format")
	}
}

func TestValidate_InvalidAllowedKey_TooShort(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.AllowedKeys = []string{"deadbeef"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for short allowed key")
	}
}

func TestValidate_InvalidAllowedKey_NotHex(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.AllowedKeys = []string{strings.Repeat("zz", 32)}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for non-hex allowed key")
	}
}

func TestValidate_ValidAllowedKey(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.AllowedKeys = []string{strings.Repeat("ab", 32)}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid 64-char hex key must be accepted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Save / Load round-trip
// ---------------------------------------------------------------------------

func TestSaveLoad_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn.yaml")

	original := config.Default()
	original.Listen = "0.0.0.0:1194"
	original.API.Token = "super-secret"
	original.AllowedKeys = []string{strings.Repeat("cd", 32)}

	if err := config.Save(path, original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Listen != original.Listen {
		t.Errorf("Listen mismatch: got %q, want %q", loaded.Listen, original.Listen)
	}
	if loaded.API.Token != original.API.Token {
		t.Errorf("API.Token mismatch: got %q, want %q", loaded.API.Token, original.API.Token)
	}
	if len(loaded.AllowedKeys) != 1 || loaded.AllowedKeys[0] != original.AllowedKeys[0] {
		t.Errorf("AllowedKeys mismatch: got %v, want %v", loaded.AllowedKeys, original.AllowedKeys)
	}
}

func TestLoad_MissingFile_CreatesDefault(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn.yaml")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}

	// Should return defaults.
	def := config.Default()
	if cfg.Listen != def.Listen {
		t.Errorf("Listen: got %q, want %q", cfg.Listen, def.Listen)
	}

	// File should have been created.
	if _, statErr := os.Stat(path); statErr != nil {
		t.Errorf("default config file not created: %v", statErr)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("listen: [not: a: string"), 0600) //nolint:errcheck

	if _, err := config.Load(path); err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoad_InvalidConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.yaml")
	os.WriteFile(path, []byte("listen: \"\"\ntun_cidr: 10.8.0.1/24\nprivate_key_file: key.hex\n"), 0600) //nolint:errcheck

	if _, err := config.Load(path); err == nil {
		t.Error("expected validation error for empty listen address")
	}
}

func TestSave_CreatesParentDirectories(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "vpn.yaml")

	if err := config.Save(path, config.Default()); err != nil {
		t.Fatalf("Save with nested directories: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestSave_FilePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn.yaml")

	if err := config.Save(path, config.Default()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions: got %04o, want 0600", perm)
	}
}

// ---------------------------------------------------------------------------
// ParseAllowedKeys
// ---------------------------------------------------------------------------

func TestParseAllowedKeys_Empty(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	keys, err := cfg.ParseAllowedKeys()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty slice, got %d keys", len(keys))
	}
}

func TestParseAllowedKeys_Valid(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	raw := strings.Repeat("ab", 32)
	cfg.AllowedKeys = []string{raw}

	keys, err := cfg.ParseAllowedKeys()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	expected, _ := hex.DecodeString(raw)
	var want [32]byte
	copy(want[:], expected)
	if keys[0] != want {
		t.Errorf("key mismatch")
	}
}

func TestParseAllowedKeys_Invalid(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.AllowedKeys = []string{"not-hex"}
	if _, err := cfg.ParseAllowedKeys(); err == nil {
		t.Error("expected error for invalid hex key")
	}
}

// ---------------------------------------------------------------------------
// EnsureKeyFile
// ---------------------------------------------------------------------------

func TestEnsureKeyFile_GeneratesOnMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "privkey.hex")

	privHex, generated, err := config.EnsureKeyFile(path)
	if err != nil {
		t.Fatalf("EnsureKeyFile: %v", err)
	}
	if !generated {
		t.Error("expected generated=true on first call")
	}

	b, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("returned hex is invalid: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("key length: got %d bytes, want 32", len(b))
	}

	// File must exist on disk.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if string(data) != privHex {
		t.Error("file content does not match returned key")
	}
}

func TestEnsureKeyFile_LoadsExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "privkey.hex")

	// Pre-create a key file.
	expectedHex := strings.Repeat("aa", 32)
	os.WriteFile(path, []byte(expectedHex), 0600) //nolint:errcheck

	privHex, generated, err := config.EnsureKeyFile(path)
	if err != nil {
		t.Fatalf("EnsureKeyFile: %v", err)
	}
	if generated {
		t.Error("expected generated=false when file already exists")
	}
	if privHex != expectedHex {
		t.Errorf("got %q, want %q", privHex, expectedHex)
	}
}

func TestEnsureKeyFile_FilePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "privkey.hex")

	if _, _, err := config.EnsureKeyFile(path); err != nil {
		t.Fatalf("EnsureKeyFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file permissions: got %04o, want 0600", perm)
	}
}

func TestEnsureKeyFile_KeyIsClamped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "privkey.hex")

	privHex, _, err := config.EnsureKeyFile(path)
	if err != nil {
		t.Fatalf("EnsureKeyFile: %v", err)
	}

	b, _ := hex.DecodeString(privHex)
	if b[0]&7 != 0 {
		t.Error("X25519 clamp: lowest 3 bits of byte[0] must be 0")
	}
	if b[31]&128 != 0 {
		t.Error("X25519 clamp: bit 255 must be 0")
	}
	if b[31]&64 == 0 {
		t.Error("X25519 clamp: bit 254 must be 1")
	}
}

func TestEnsureKeyFile_CreatesParentDirectories(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "server", "privkey.hex")

	if _, _, err := config.EnsureKeyFile(path); err != nil {
		t.Fatalf("EnsureKeyFile with nested path: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("key file not created: %v", err)
	}
}
