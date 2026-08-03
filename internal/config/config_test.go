package config

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestLoadRequiresSigningKey(t *testing.T) {
	t.Setenv("SIGNOZ_ENDPOINT", "http://localhost:4318")
	t.Setenv("SESSION_SIGNING_KEY", "")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when SESSION_SIGNING_KEY is empty")
	}
	if !strings.Contains(err.Error(), "SESSION_SIGNING_KEY") {
		t.Fatalf("expected error to mention SESSION_SIGNING_KEY, got: %v", err)
	}
}

func TestLoadRejectsInvalidHex(t *testing.T) {
	t.Setenv("SIGNOZ_ENDPOINT", "http://localhost:4318")
	t.Setenv("SESSION_SIGNING_KEY", "not-hex-zzzz")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for non-hex key")
	}
}

func TestLoadRejectsShortKey(t *testing.T) {
	t.Setenv("SIGNOZ_ENDPOINT", "http://localhost:4318")
	t.Setenv("SESSION_SIGNING_KEY", "abcd") // 2 bytes < 32
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestLoadAcceptsValidKey(t *testing.T) {
	t.Setenv("SIGNOZ_ENDPOINT", "http://localhost:4318")
	keyHex := strings.Repeat("ab", 32) // 32 bytes
	t.Setenv("SESSION_SIGNING_KEY", keyHex)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want, _ := hex.DecodeString(keyHex)
	if string(cfg.SessionSigningKey) != string(want) {
		t.Fatal("signing key not decoded correctly")
	}
}

func TestCookieSecureDefaultTrue(t *testing.T) {
	t.Setenv("SIGNOZ_ENDPOINT", "http://localhost:4318")
	t.Setenv("SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	t.Setenv("ADMIN_COOKIE_SECURE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.AdminCookieSecure {
		t.Fatal("expected cookie secure to default to true")
	}
}

func TestCookieSecureFalse(t *testing.T) {
	t.Setenv("SIGNOZ_ENDPOINT", "http://localhost:4318")
	t.Setenv("SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	t.Setenv("ADMIN_COOKIE_SECURE", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AdminCookieSecure {
		t.Fatal("expected cookie secure to be false")
	}
}

func TestAdminListenAddrPriority(t *testing.T) {
	t.Setenv("SIGNOZ_ENDPOINT", "http://localhost:4318")
	t.Setenv("SESSION_SIGNING_KEY", strings.Repeat("ab", 32))

	// Explicit ADMIN_LISTEN_ADDR wins
	t.Setenv("ADMIN_LISTEN_ADDR", "0.0.0.0:9999")
	t.Setenv("ADMIN_PORT", "8080")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AdminListenAddr != "0.0.0.0:9999" {
		t.Fatalf("expected 0.0.0.0:9999, got %q", cfg.AdminListenAddr)
	}

	// Only ADMIN_PORT set → :<port> (backward compat)
	t.Setenv("ADMIN_LISTEN_ADDR", "")
	t.Setenv("ADMIN_PORT", "7070")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AdminListenAddr != ":7070" {
		t.Fatalf("expected :7070, got %q", cfg.AdminListenAddr)
	}

	// Neither set → localhost default
	t.Setenv("ADMIN_LISTEN_ADDR", "")
	t.Setenv("ADMIN_PORT", "")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AdminListenAddr != "127.0.0.1:8080" {
		t.Fatalf("expected 127.0.0.1:8080, got %q", cfg.AdminListenAddr)
	}
}

func TestMaxBodyBytes(t *testing.T) {
	t.Setenv("SIGNOZ_ENDPOINT", "http://localhost:4318")
	t.Setenv("SESSION_SIGNING_KEY", strings.Repeat("ab", 32))

	t.Setenv("MAX_BODY_BYTES", "")
	cfg, _ := Load()
	if cfg.MaxBodyBytes != 4194304 {
		t.Fatalf("expected default 4194304, got %d", cfg.MaxBodyBytes)
	}

	t.Setenv("MAX_BODY_BYTES", "1000000")
	cfg, _ = Load()
	if cfg.MaxBodyBytes != 1000000 {
		t.Fatalf("expected 1000000, got %d", cfg.MaxBodyBytes)
	}

	// Invalid → fallback
	t.Setenv("MAX_BODY_BYTES", "bogus")
	cfg, _ = Load()
	if cfg.MaxBodyBytes != 4194304 {
		t.Fatalf("expected fallback 4194304, got %d", cfg.MaxBodyBytes)
	}
}
