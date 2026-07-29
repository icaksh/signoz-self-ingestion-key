package config

import (
	"fmt"
	"os"
)

const (
	defaultDBPath    = "./tenants.db"
	defaultProxyPort = "4318"
	defaultAdminPort = "8080"
)

type Config struct {
	SigNozEndpoint     string
	SigNozIngestKey    string
	ProxyPort          string
	AdminPort          string
	DBPath             string
	UsageRetentionDays int
}

func Load() (*Config, error) {
	c := &Config{
		SigNozEndpoint:     os.Getenv("SIGNOZ_ENDPOINT"),
		SigNozIngestKey:    os.Getenv("SIGNOZ_INGESTION_KEY"),
		ProxyPort:          envOrDefault("PROXY_PORT", defaultProxyPort),
		AdminPort:          envOrDefault("ADMIN_PORT", defaultAdminPort),
		DBPath:             envOrDefault("DB_PATH", defaultDBPath),
		UsageRetentionDays: envOrDefaultInt("USAGE_RETENTION_DAYS", 90),
	}

	if c.SigNozEndpoint == "" {
		return nil, fmt.Errorf("SIGNOZ_ENDPOINT is required")
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
