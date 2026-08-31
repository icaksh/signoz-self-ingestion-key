package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestOpenFreshMigrates(t *testing.T) {
	st := openTestStore(t)

	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Errorf("schema_migrations rows = %d, want >= 2", n)
	}

	// The retention index from 0002 must exist.
	var idx int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_usage_counters_hour'`).Scan(&idx); err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Errorf("idx_usage_counters_hour missing")
	}
}

// legacySchemaDDL reproduces the pre-migration legacy shape: tenants carries a
// UNIQUE constraint on api_key, plaintext keys live in tenants.api_key, and
// there is no schema_migrations table.
const legacySchemaDDL = `
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL DEFAULT 1,
    description TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    signal_type TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    status_code INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    serial_number TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    subject_cn TEXT NOT NULL,
    not_before DATETIME,
    not_after DATETIME,
    revoked_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME
);
CREATE TABLE usage_counters (
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    signal_type TEXT NOT NULL,
    hour_bucket TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, signal_type, hour_bucket)
);
`

// TestLegacyBaselineAdoption seeds a legacy DB (UNIQUE api_key + plaintext key,
// no schema_migrations) and verifies the new store adopts it in place with zero
// data loss.
func TestLegacyBaselineAdoption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Seed a legacy DB using the raw driver, bypassing the migration runner.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(legacySchemaDDL); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	legacyKey := "0123456789abcdef0123456789abcdef" // 32 lowercase hex
	if _, err := raw.Exec(`INSERT INTO tenants (id, name, api_key) VALUES (1, 'legacy-tenant', ?)`, legacyKey); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy DB: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// Migrations recorded.
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Errorf("schema_migrations = %d, want >= 2 after baseline", n)
	}

	// The UNIQUE constraint on api_key must be gone (rebuild ran).
	var sqlText string
	if err := st.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='tenants'`).Scan(&sqlText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sqlText, "UNIQUE") {
		t.Errorf("tenants still carries UNIQUE constraint: %s", sqlText)
	}

	// Plaintext key migrated into api_keys (hashed), tenants.api_key blanked.
	tenant, err := st.LookupTenantByKey(ctx, legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	if tenant == nil || tenant.Name != "legacy-tenant" {
		t.Fatalf("legacy key lookup failed: %+v", tenant)
	}
	var apiKeyBlank string
	_ = st.db.QueryRow(`SELECT api_key FROM tenants WHERE id = 1`).Scan(&apiKeyBlank)
	if apiKeyBlank != "" {
		t.Errorf("tenants.api_key = %q, want blank after migration", apiKeyBlank)
	}
	var keyHash string
	_ = st.db.QueryRow(`SELECT key_hash FROM api_keys WHERE tenant_id = 1`).Scan(&keyHash)
	if keyHash != HashKey(legacyKey) {
		t.Errorf("api_keys.key_hash mismatch")
	}
	// No plaintext key persists anywhere.
	var plaintextCount int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE key_hash = ?`, legacyKey).Scan(&plaintextCount)
	if plaintextCount != 0 {
		t.Errorf("plaintext key persisted in api_keys")
	}

	// Multiple tenants may hold empty api_key (the legacy UNIQUE bug is fixed).
	if _, err := st.db.Exec(`INSERT INTO tenants (name, api_key) VALUES ('t2', ''), ('t3', '')`); err != nil {
		t.Errorf("insert multiple empty api_key tenants failed: %v", err)
	}
}

func TestKeyLifecycle(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	tenant, err := st.CreateTenant(ctx, "acme", "desc", nil)
	if err != nil {
		t.Fatal(err)
	}
	key := tenant.APIKey
	if !strings.HasPrefix(key, "ing_"+itoa64(tenant.ID)+"_") {
		t.Fatalf("key format = %q, want ing_<id>_<48hex>", key)
	}
	rest := key[len("ing_"+itoa64(tenant.ID)+"_"):]
	if len(rest) != 48 {
		t.Errorf("secret length = %d, want 48", len(rest))
	}

	// The full key is not persisted in plaintext.
	var plaintextCount int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE key_hash = ? OR key_prefix = ?`, key, key).Scan(&plaintextCount)
	if plaintextCount != 0 {
		t.Errorf("plaintext key persisted")
	}

	// Lookup by full key works.
	got, err := st.LookupTenantByKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != tenant.ID {
		t.Fatalf("lookup failed: %+v", got)
	}

	// Regenerate revokes the old key and issues a new one.
	newKey, err := st.RegenerateKey(ctx, tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newKey == key {
		t.Fatalf("regenerate returned the same key")
	}
	if got, _ := st.LookupTenantByKey(ctx, key); got != nil {
		t.Errorf("old key still valid after regenerate")
	}
	if got, _ := st.LookupTenantByKey(ctx, newKey); got == nil {
		t.Errorf("new key not valid")
	}
}

func TestLegacyHexKeyAccepted(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	tenant, err := st.CreateTenant(ctx, "legacy", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	legacyKey := "abcdefabcdefabcdefabcdefabcdefab" // 32 lowercase hex
	if err := st.CreateAPIKey(ctx, tenant.ID, HashKey(legacyKey), legacyKey[:12]); err != nil {
		t.Fatal(err)
	}

	got, err := st.LookupTenantByKey(ctx, legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != tenant.ID {
		t.Fatalf("legacy key rejected: %+v", got)
	}

	// Non-hex / wrong-format keys are rejected before any DB query.
	for _, bad := range []string{"", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "ing_1_nothex"} {
		if got, _ := st.LookupTenantByKey(ctx, bad); got != nil {
			t.Errorf("bad key %q resolved to a tenant", bad)
		}
	}
}

func TestUsageFlushAndRetention(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	tenant, err := st.CreateTenant(ctx, "usage", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	st.RecordUsage(tenant.ID, "traces", 200, 1024)
	st.RecordUsage(tenant.ID, "traces", 500, 2048)
	st.FlushCounters()

	requests, bytes, errors, err := st.CounterTotals(ctx, tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || bytes != 3072 || errors != 1 {
		t.Errorf("totals = %d/%d/%d, want 2/3072/1", requests, bytes, errors)
	}

	// Seed an old counter row and verify retention purges usage_counters.
	oldBucket := time.Now().UTC().AddDate(0, 0, -120).Format("2006-01-02T15")
	if _, err := st.db.Exec(`INSERT INTO usage_counters (tenant_id, signal_type, hour_bucket, requests, bytes, errors)
		VALUES (?, 'logs', ?, 1, 1, 0)`, tenant.ID, oldBucket); err != nil {
		t.Fatal(err)
	}
	if err := st.CleanupOldCounters(ctx, 90); err != nil {
		t.Fatal(err)
	}
	var oldCount int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM usage_counters WHERE hour_bucket = ?`, oldBucket).Scan(&oldCount)
	if oldCount != 0 {
		t.Errorf("old usage_counters row not purged by retention")
	}
}

func TestCertLifecycle(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	tenant, err := st.CreateTenant(ctx, "cert", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	fingerprint := "aabbccdd"
	cert, err := st.AddCertificate(ctx, tenant.ID, "01", fingerprint, "device-1", time.Now(), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if cert.ID == 0 {
		t.Fatal("cert ID zero")
	}

	got, err := st.LookupTenantByFingerprint(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != tenant.ID {
		t.Fatalf("fingerprint lookup failed: %+v", got)
	}

	// Revoked certs no longer resolve a tenant.
	if err := st.RevokeCertificate(ctx, fingerprint); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.LookupTenantByFingerprint(ctx, fingerprint); got != nil {
		t.Errorf("revoked cert still resolves tenant")
	}
}

func TestTenantCascade(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	tenant, err := st.CreateTenant(ctx, "cascade", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTenant(ctx, tenant.ID); err != nil {
		t.Fatal(err)
	}
	var keys int
	_ = st.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE tenant_id = ?`, tenant.ID).Scan(&keys)
	if keys != 0 {
		t.Errorf("api_keys not cascaded on tenant delete")
	}
}

func itoa64(n int64) string {
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
