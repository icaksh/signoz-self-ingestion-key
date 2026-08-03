package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultDBPath       = "./tenants.db"
	defaultProxyPort    = "4318"
	defaultAdminPort    = "8080"
	defaultAdminListen  = "127.0.0.1:8080"
	defaultMaxBodyBytes = 4194304
)

type Config struct {
	SigNozEndpoint     string
	SigNozIngestKey    string
	ProxyPort          string
	AdminPort          string
	AdminListenAddr    string
	DBPath             string
	SessionSigningKey  []byte
	AdminCookieSecure  bool
	MaxBodyBytes       int64
	UsageRetentionDays int

	SyslogEnabled         bool
	SyslogListenAddr      string
	SyslogServerCertFile  string
	SyslogServerKeyFile   string
	SyslogClientCAFile    string
	SyslogMaxFrameBytes   int
	SyslogMaxConnections  int
	SyslogConnIdleTimeout time.Duration
	SyslogCollectorAddr   string
}

func Load() (*Config, error) {
	c := &Config{
		SigNozEndpoint:     os.Getenv("SIGNOZ_ENDPOINT"),
		SigNozIngestKey:    os.Getenv("SIGNOZ_INGESTION_KEY"),
		ProxyPort:          envOrDefault("PROXY_PORT", defaultProxyPort),
		AdminPort:          envOrDefault("ADMIN_PORT", defaultAdminPort),
		DBPath:             envOrDefault("DB_PATH", defaultDBPath),
		UsageRetentionDays: envOrDefaultInt("USAGE_RETENTION_DAYS", 90),
		MaxBodyBytes:       envOrDefaultInt64("MAX_BODY_BYTES", defaultMaxBodyBytes),
	}

	// Admin listen address: ADMIN_LISTEN_ADDR takes priority.
	// Backward compat: if only ADMIN_PORT is set explicitly (ADMIN_LISTEN_ADDR
	// unset or default), build the addr from ADMIN_PORT.
	listenAddr := os.Getenv("ADMIN_LISTEN_ADDR")
	switch {
	case listenAddr != "" && listenAddr != defaultAdminListen:
		c.AdminListenAddr = listenAddr
	case os.Getenv("ADMIN_PORT") != "":
		c.AdminListenAddr = ":" + c.AdminPort
	default:
		c.AdminListenAddr = defaultAdminListen
	}

	// Session signing key
	keyHex := os.Getenv("SESSION_SIGNING_KEY")
	if keyHex == "" {
		return nil, fmt.Errorf("SESSION_SIGNING_KEY is required (generate: openssl rand -hex 32)")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("SESSION_SIGNING_KEY must be valid hex: %w", err)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("SESSION_SIGNING_KEY must be at least 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	c.SessionSigningKey = key

	// Admin cookie secure flag
	secure := strings.ToLower(os.Getenv("ADMIN_COOKIE_SECURE"))
	c.AdminCookieSecure = secure != "false"

	if c.SigNozEndpoint == "" {
		return nil, fmt.Errorf("SIGNOZ_ENDPOINT is required")
	}

	// Syslog-over-TLS (mTLS) — optional
	c.SyslogEnabled = os.Getenv("SYSLOG_ENABLED") == "true"
	c.SyslogListenAddr = envOrDefault("SYSLOG_LISTEN_ADDR", ":6514")
	c.SyslogCollectorAddr = envOrDefault("SYSLOG_COLLECTOR_ADDR", "127.0.0.1:5140")
	c.SyslogMaxFrameBytes = envOrDefaultInt("SYSLOG_MAX_FRAME_BYTES", 65536)
	c.SyslogMaxConnections = envOrDefaultInt("SYSLOG_MAX_CONNECTIONS", 1000)

	timeoutStr := envOrDefault("SYSLOG_CONN_IDLE_TIMEOUT", "300s")
	c.SyslogConnIdleTimeout, err = time.ParseDuration(timeoutStr)
	if err != nil {
		return nil, fmt.Errorf("SYSLOG_CONN_IDLE_TIMEOUT: %w", err)
	}

	if c.SyslogEnabled {
		c.SyslogServerCertFile = os.Getenv("SYSLOG_SERVER_CERT_FILE")
		c.SyslogServerKeyFile = os.Getenv("SYSLOG_SERVER_KEY_FILE")
		c.SyslogClientCAFile = os.Getenv("SYSLOG_CLIENT_CA_FILE")
		if c.SyslogServerCertFile == "" || c.SyslogServerKeyFile == "" || c.SyslogClientCAFile == "" {
			return nil, fmt.Errorf("SYSLOG_ENABLED=true requires SYSLOG_SERVER_CERT_FILE, SYSLOG_SERVER_KEY_FILE, SYSLOG_CLIENT_CA_FILE")
		}
		for _, f := range []string{c.SyslogServerCertFile, c.SyslogServerKeyFile, c.SyslogClientCAFile} {
			if _, err := os.Stat(f); err != nil {
				return nil, fmt.Errorf("cannot access %s: %w", f, err)
			}
		}
	}

	return c, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrDefaultInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var n int
	fmt.Sscanf(v, "%d", &n)
	if n <= 0 {
		return fallback
	}
	return n
}

func envOrDefaultInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
