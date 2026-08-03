package store

import (
	"context"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

func testDB(t *testing.T) *Store {
	t.Helper()
	path := t.TempDir() + "/test.db"
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close(); os.Remove(path) })
	return s
}

func TestCreateAndLookupTenant(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, err := s.CreateTenant(ctx, "test-app", "test tenant")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tenant.ID == 0 {
		t.Fatal("expected non-zero ID")
	}
	if tenant.APIKey == "" {
		t.Fatal("expected API key")
	}
	if len(tenant.APIKey) != 54 {
		t.Fatalf("expected 54-char v2 key (ing_<id>_<48 hex>), got %d: %q", len(tenant.APIKey), tenant.APIKey)
	}
	if !strings.HasPrefix(tenant.APIKey, "ing_") {
		t.Fatalf("expected key to start with ing_, got %q", tenant.APIKey)
	}
	if !tenant.Active {
		t.Fatal("expected active tenant")
	}

	found, err := s.LookupTenantByKey(ctx, tenant.APIKey)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find tenant")
	}
	if found.Name != "test-app" {
		t.Fatalf("expected name 'test-app', got %q", found.Name)
	}
}

func TestLookupTenantNotFound(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	found, err := s.LookupTenant(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found != nil {
		t.Fatal("expected nil for unknown key")
	}
}

func TestLookupInactiveTenant(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "app", "")
	s.UpdateTenant(ctx, tenant.ID, "app", "", false)

	found, _ := s.LookupTenant(ctx, tenant.APIKey)
	if found != nil {
		t.Fatal("expected nil for inactive tenant")
	}
}

func TestListTenants(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	s.CreateTenant(ctx, "a", "")
	s.CreateTenant(ctx, "b", "")

	list, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(list))
	}
}

func TestRegenerateKey(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "app", "")
	oldKey := tenant.APIKey

	newKey, err := s.RegenerateKey(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if newKey == oldKey {
		t.Fatal("expected different key")
	}

	found, _ := s.LookupTenantByKey(ctx, newKey)
	if found == nil {
		t.Fatal("expected to find tenant by new key")
	}

	foundOld, _ := s.LookupTenantByKey(ctx, oldKey)
	if foundOld != nil {
		t.Fatal("expected old key to no longer work")
	}
}

func TestDeleteTenant(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "app", "")
	s.LogUsage(ctx, tenant.ID, "traces", 100, 200)
	s.LogUsage(ctx, tenant.ID, "metrics", 200, 200)

	s.DeleteTenant(ctx, tenant.ID)

	found, _ := s.LookupTenantByID(ctx, tenant.ID)
	if found != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestUsageData(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "app", "")
	s.LogUsage(ctx, tenant.ID, "traces", 1000, 200)
	s.LogUsage(ctx, tenant.ID, "traces", 2000, 200)
	s.LogUsage(ctx, tenant.ID, "metrics", 500, 200)
	s.LogUsage(ctx, tenant.ID, "logs", 100, 200)

	data, err := s.GetUsageData(ctx, tenant.ID, "7d")
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if len(data.SignalTypes) != 3 {
		t.Fatalf("expected 3 signal types, got %d", len(data.SignalTypes))
	}
}

func TestCleanupOldLogs(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "app", "")
	// Insert usage then verify cleanup with 90-day retention does NOT delete recent data
	s.LogUsage(ctx, tenant.ID, "traces", 100, 200)

	err := s.CleanupOldLogs(ctx, 90)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	data, _ := s.GetUsageData(ctx, tenant.ID, "7d")
	if len(data.SignalTypes) == 0 {
		t.Fatal("expected data preserved with 90-day retention")
	}

	// Cleanup with 36500 days (~100 years) also preserves data
	err = s.CleanupOldLogs(ctx, 36500)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	data, _ = s.GetUsageData(ctx, tenant.ID, "7d")
	if len(data.SignalTypes) == 0 {
		t.Fatal("expected data preserved")
	}
}

func TestOnDeleteCascade(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "cascade-test", "")
	s.LogUsage(ctx, tenant.ID, "traces", 100, 200)
	s.LogUsage(ctx, tenant.ID, "metrics", 200, 200)

	// Verify usage exists before delete
	var beforeCount int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_logs WHERE tenant_id = ?`, tenant.ID).Scan(&beforeCount)
	if beforeCount != 2 {
		t.Fatalf("expected 2 usage rows before delete, got %d", beforeCount)
	}

	s.DeleteTenant(ctx, tenant.ID)

	var afterCount int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_logs WHERE tenant_id = ?`, tenant.ID).Scan(&afterCount)
	if afterCount != 0 {
		t.Fatalf("ON DELETE CASCADE failed: expected 0 usage rows after delete, got %d", afterCount)
	}
}

func TestAPIKeyFormat(t *testing.T) {
	key := GenerateAPIKeyV2(42)
	if !strings.HasPrefix(key, "ing_42_") {
		t.Fatalf("expected prefix ing_42_, got %q", key)
	}
	secret := key[7:] // "ing_42_" is 7 chars
	if len(secret) != 48 {
		t.Fatalf("expected 48 hex chars, got %d", len(secret))
	}
	if _, err := hex.DecodeString(secret); err != nil {
		t.Fatalf("secret part must be hex: %v", err)
	}
}

func TestAPIKeyHashAndLookup(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "hash-app", "")

	// Wrong key fails
	wrong, err := s.LookupTenantByKey(ctx, "ing_"+strconv.FormatInt(tenant.ID, 10)+"_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if err != nil {
		t.Fatalf("lookup wrong: %v", err)
	}
	if wrong != nil {
		t.Fatal("expected nil for wrong key")
	}

	// Correct key succeeds
	good, err := s.LookupTenantByKey(ctx, tenant.APIKey)
	if err != nil {
		t.Fatalf("lookup good: %v", err)
	}
	if good == nil || good.ID != tenant.ID {
		t.Fatal("expected to find tenant by correct key")
	}
}

func TestAPIKeyRevoked(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "revoke-app", "")
	oldKey := tenant.APIKey

	if _, err := s.RegenerateKey(ctx, tenant.ID); err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	found, _ := s.LookupTenantByKey(ctx, oldKey)
	if found != nil {
		t.Fatal("expected old key to be revoked")
	}

	// New key still works after regenerate
	newFound, _ := s.LookupTenantByKey(ctx, tenant.APIKey)
	if newFound != nil {
		t.Fatal("expected OLD tenant.APIKey (pre-regenerate) to fail")
	}
}

func TestAPIKeyMigration(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	// Seed a tenant the old way: direct INSERT with plaintext api_key
	oldKey := "deadbeefdeadbeefdeadbeefdeadbeef"
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (name, api_key, active, description, created_at, updated_at)
		 VALUES ('migration-test', ?, 1, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		oldKey)
	if err != nil {
		t.Fatalf("insert old-style tenant: %v", err)
	}

	// Run migration manually
	if err := migratePlaintextKeys(s.db); err != nil {
		t.Fatalf("migration: %v", err)
	}

	// Verify old key still authenticates
	tenant, err := s.LookupTenantByKey(ctx, oldKey)
	if err != nil {
		t.Fatalf("lookup after migration: %v", err)
	}
	if tenant == nil {
		t.Fatal("expected old key to work after migration")
	}
	if tenant.Name != "migration-test" {
		t.Fatalf("expected 'migration-test', got %q", tenant.Name)
	}

	// Verify tenants.api_key is now empty/NULL
	var apiKey string
	s.db.QueryRowContext(ctx, `SELECT COALESCE(api_key, '') FROM tenants WHERE id = ?`, tenant.ID).Scan(&apiKey)
	if apiKey != "" {
		t.Fatalf("expected empty api_key after migration, got %q", apiKey)
	}
}

func TestMalformedKeyNoQuery(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	malformed := []string{
		"not-a-key",
		"",
		"ing_",
		"ing_abc_1234",
		"ing_1_short",
		"ing_1_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // non-hex
		"ING_1_000000000000000000000000000000000000000000000000", // uppercase prefix
	}
	for _, k := range malformed {
		found, err := s.LookupTenantByKey(ctx, k)
		if err != nil {
			t.Fatalf("lookup %q: %v", k, err)
		}
		if found != nil {
			t.Fatalf("expected nil for malformed key %q", k)
		}
	}
}

func TestAPIKeyNoPlaintextInDB(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "no-plaintext", "")
	var apiKey string
	s.db.QueryRowContext(ctx, `SELECT COALESCE(api_key, '') FROM tenants WHERE id = ?`, tenant.ID).Scan(&apiKey)
	if apiKey != "" {
		t.Fatalf("expected empty tenants.api_key after create, got %q", apiKey)
	}

	if _, err := s.RegenerateKey(ctx, tenant.ID); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	s.db.QueryRowContext(ctx, `SELECT COALESCE(api_key, '') FROM tenants WHERE id = ?`, tenant.ID).Scan(&apiKey)
	if apiKey != "" {
		t.Fatalf("expected empty tenants.api_key after regenerate, got %q", apiKey)
	}

	// Also verify no plaintext hash stored in api_keys.key_hash
	var hash string
	s.db.QueryRowContext(ctx, `SELECT key_hash FROM api_keys WHERE tenant_id = ? LIMIT 1`, tenant.ID).Scan(&hash)
	if strings.Contains(hash, tenant.APIKey) {
		t.Fatal("key_hash must not contain plaintext key")
	}
}
