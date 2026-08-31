-- 0001_init.sql — baseline schema, idempotent.
-- Recreates the exact production schema (with rate-limit columns inlined on
-- tenants, matching the post-rebuild shape) using IF NOT EXISTS so it is safe
-- on both a fresh database and a pre-existing legacy database.

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tenants (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    api_key          TEXT NOT NULL DEFAULT '',
    active           INTEGER NOT NULL DEFAULT 1,
    description      TEXT NOT NULL DEFAULT '',
    rate_limit_rps   INTEGER,
    burst_bytes      INTEGER,
    daily_byte_quota INTEGER,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tenants_api_key ON tenants(api_key);

CREATE TABLE IF NOT EXISTS usage_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    signal_type  TEXT    NOT NULL,
    byte_count   INTEGER NOT NULL,
    status_code  INTEGER NOT NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_usage_tenant_time ON usage_logs(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_logs(created_at);

CREATE TABLE IF NOT EXISTS certificates (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id          INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    serial_number      TEXT    NOT NULL,
    fingerprint_sha256 TEXT    NOT NULL UNIQUE,
    subject_cn         TEXT    NOT NULL,
    not_before         DATETIME,
    not_after          DATETIME,
    revoked_at         DATETIME,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at       DATETIME
);

CREATE INDEX IF NOT EXISTS idx_certificates_fingerprint ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_certificates_tenant ON certificates(tenant_id);

CREATE TABLE IF NOT EXISTS usage_counters (
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    signal_type TEXT    NOT NULL,
    hour_bucket TEXT    NOT NULL,
    requests    INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    errors      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, signal_type, hour_bucket)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash     TEXT NOT NULL,
    key_prefix   TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    revoked_at   DATETIME
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
