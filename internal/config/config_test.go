package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setenv sets an env var for the test and registers cleanup to restore it.
func setenv(t *testing.T, key, value string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("setenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// clearEnv removes all config-relevant env vars for a clean test baseline.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range os.Environ() {
		name := k[:strings.IndexByte(k, '=')]
		if strings.HasPrefix(name, "SIGNOZ_") || strings.HasPrefix(name, "PROXY_") ||
			strings.HasPrefix(name, "ADMIN_") || strings.HasPrefix(name, "SESSION_") ||
			strings.HasPrefix(name, "MAX_BODY") || strings.HasPrefix(name, "USAGE_") ||
			strings.HasPrefix(name, "SYSLOG_") || strings.HasPrefix(name, "CA_") ||
			strings.HasPrefix(name, "DB_") {
			setenv(t, name, "")
			_ = os.Unsetenv(name)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ProxyPort != "4318" {
		t.Errorf("ProxyPort = %q, want 4318", c.ProxyPort)
	}
	if c.AdminPort != "8080" {
		t.Errorf("AdminPort = %q, want 8080", c.AdminPort)
	}
	if c.AdminListenAddr != "127.0.0.1:8080" {
		t.Errorf("AdminListenAddr = %q, want 127.0.0.1:8080", c.AdminListenAddr)
	}
	if c.DBPath != "./tenants.db" {
		t.Errorf("DBPath = %q, want ./tenants.db", c.DBPath)
	}
	if c.MaxBodyBytes != 4194304 {
		t.Errorf("MaxBodyBytes = %d, want 4194304", c.MaxBodyBytes)
	}
	if c.UsageRetentionDays != 90 {
		t.Errorf("UsageRetentionDays = %d, want 90", c.UsageRetentionDays)
	}
	if !c.AdminCookieSecure {
		t.Errorf("AdminCookieSecure = false, want true (default)")
	}
	if c.SyslogMaxFrameBytes != 65536 {
		t.Errorf("SyslogMaxFrameBytes = %d, want 65536", c.SyslogMaxFrameBytes)
	}
	if c.SyslogMaxConnections != 1000 {
		t.Errorf("SyslogMaxConnections = %d, want 1000", c.SyslogMaxConnections)
	}
	if c.SyslogMaxConnsPerTenant != 50 {
		t.Errorf("SyslogMaxConnsPerTenant = %d, want 50", c.SyslogMaxConnsPerTenant)
	}
	if c.SyslogConnIdleTimeout.Seconds() != 300 {
		t.Errorf("SyslogConnIdleTimeout = %v, want 300s", c.SyslogConnIdleTimeout)
	}
}

func TestLoadRequiresEndpoint(t *testing.T) {
	clearEnv(t)
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SIGNOZ_ENDPOINT") {
		t.Fatalf("expected SIGNOZ_ENDPOINT error, got %v", err)
	}
}

func TestLoadRequiresSigningKey(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SESSION_SIGNING_KEY") {
		t.Fatalf("expected SESSION_SIGNING_KEY error, got %v", err)
	}
}

func TestLoadSigningKeyValidation(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")

	t.Run("not hex", func(t *testing.T) {
		setenv(t, "SESSION_SIGNING_KEY", "zz"+strings.Repeat("a", 62))
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "hex") {
			t.Fatalf("expected hex error, got %v", err)
		}
	})
	t.Run("too short", func(t *testing.T) {
		setenv(t, "SESSION_SIGNING_KEY", "deadbeef")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 32") {
			t.Fatalf("expected length error, got %v", err)
		}
	})
	t.Run("valid 32 bytes", func(t *testing.T) {
		setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("cd", 32))
		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(c.SessionSigningKey) != 32 {
			t.Errorf("SessionSigningKey length = %d, want 32", len(c.SessionSigningKey))
		}
	})
}

func TestLoadCookieSecureFalse(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	setenv(t, "ADMIN_COOKIE_SECURE", "false")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AdminCookieSecure {
		t.Errorf("AdminCookieSecure = true, want false")
	}
}

func TestLoadAdminListenPriority(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))

	t.Run("explicit listen addr wins", func(t *testing.T) {
		setenv(t, "ADMIN_LISTEN_ADDR", "0.0.0.0:9000")
		setenv(t, "ADMIN_PORT", "8080")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if c.AdminListenAddr != "0.0.0.0:9000" {
			t.Errorf("AdminListenAddr = %q, want 0.0.0.0:9000", c.AdminListenAddr)
		}
	})

	t.Run("port only builds addr", func(t *testing.T) {
		setenv(t, "ADMIN_LISTEN_ADDR", "")
		setenv(t, "ADMIN_PORT", "9090")
		c, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if c.AdminListenAddr != ":9090" {
			t.Errorf("AdminListenAddr = %q, want :9090", c.AdminListenAddr)
		}
	})
}

func TestLoadMaxBodyBytes(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	setenv(t, "MAX_BODY_BYTES", "1048576")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.MaxBodyBytes != 1048576 {
		t.Errorf("MaxBodyBytes = %d, want 1048576", c.MaxBodyBytes)
	}
}

func TestLoadSyslogRequiresCerts(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	setenv(t, "SYSLOG_ENABLED", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SYSLOG_SERVER_CERT_FILE") {
		t.Fatalf("expected syslog cert error, got %v", err)
	}
}

func TestLoadSyslogValid(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	setenv(t, "SYSLOG_ENABLED", "true")

	dir := t.TempDir()
	for _, f := range []string{"server.crt", "server.key", "client-ca.crt"} {
		p := filepath.Join(dir, f)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		setenv(t, "SYSLOG_"+strings.ToUpper(strings.ReplaceAll(strings.TrimSuffix(f, ".crt"), ".", "_"))+"_FILE", p)
	}
	setenv(t, "SYSLOG_SERVER_CERT_FILE", filepath.Join(dir, "server.crt"))
	setenv(t, "SYSLOG_SERVER_KEY_FILE", filepath.Join(dir, "server.key"))
	setenv(t, "SYSLOG_CLIENT_CA_FILE", filepath.Join(dir, "client-ca.crt"))

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.SyslogEnabled {
		t.Errorf("SyslogEnabled = false, want true")
	}
}

func TestLoadCARequiresVars(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	setenv(t, "CA_ENABLED", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CA_ENDPOINT") {
		t.Fatalf("expected CA_ENDPOINT error, got %v", err)
	}
}

func TestLoadCAValid(t *testing.T) {
	clearEnv(t)
	setenv(t, "SIGNOZ_ENDPOINT", "http://localhost:4318")
	setenv(t, "SESSION_SIGNING_KEY", strings.Repeat("ab", 32))
	setenv(t, "CA_ENABLED", "true")
	setenv(t, "CA_ENDPOINT", "https://step-ca:9000")
	setenv(t, "CA_PROVISIONER_NAME", "otlp-proxy")
	setenv(t, "CA_PROVISIONER_KEY", `{"use":"sig","kty":"EC","kid":"k","crv":"P-256","alg":"ES256","x":"x","y":"y","d":"d"}`)

	dir := t.TempDir()
	root := filepath.Join(dir, "root.crt")
	if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setenv(t, "CA_ROOT_CERT_FILE", root)
	setenv(t, "CA_EXTERNAL_HOSTNAME", "relay.example.com")
	setenv(t, "SYSLOG_SERVER_CERT_FILE", filepath.Join(dir, "s.crt"))
	setenv(t, "SYSLOG_SERVER_KEY_FILE", filepath.Join(dir, "s.key"))
	setenv(t, "SYSLOG_CLIENT_CA_FILE", filepath.Join(dir, "c.crt"))
	for _, f := range []string{"s.crt", "s.key", "c.crt"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.CAEnabled {
		t.Errorf("CAEnabled = false, want true")
	}
	if c.CACertLifetime != "2160h" {
		t.Errorf("CACertLifetime = %q, want 2160h", c.CACertLifetime)
	}
	if c.CASyslogRelayPort != 6514 {
		t.Errorf("CASyslogRelayPort = %d, want 6514", c.CASyslogRelayPort)
	}
}
