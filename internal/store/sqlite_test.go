package store

import (
	"context"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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
	s.RecordUsage(tenant.ID, "traces", 200, 1000)
	s.RecordUsage(tenant.ID, "traces", 200, 2000)
	s.RecordUsage(tenant.ID, "metrics", 200, 500)
	s.RecordUsage(tenant.ID, "logs", 200, 100)
	s.FlushCounters()

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
	// usage_counters are the source of truth now; usage_logs keeps legacy rows.
	// Insert a legacy row directly and verify CleanupOldLogs only touches usage_logs.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO usage_logs (tenant_id, signal_type, byte_count, status_code) VALUES (?, 'traces', 100, 200)`,
		tenant.ID); err != nil {
		t.Fatalf("insert legacy usage: %v", err)
	}

	err := s.CleanupOldLogs(ctx, 90)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	var legacyCount int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_logs WHERE tenant_id = ?`, tenant.ID).Scan(&legacyCount)
	if legacyCount != 1 {
		t.Fatalf("expected legacy usage_logs row preserved, got %d", legacyCount)
	}

	// Cleanup with 36500 days (~100 years) also preserves data
	err = s.CleanupOldLogs(ctx, 36500)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_logs WHERE tenant_id = ?`, tenant.ID).Scan(&legacyCount)
	if legacyCount != 1 {
		t.Fatalf("expected legacy usage_logs row preserved, got %d", legacyCount)
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

func TestUsageWriterBasic(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "writer-test", "")

	// Record 5 samples: 3 traces (1 error), 2 metrics (0 errors)
	s.RecordUsage(tenant.ID, "traces", 200, 100)
	s.RecordUsage(tenant.ID, "traces", 500, 200) // error
	s.RecordUsage(tenant.ID, "traces", 200, 300)
	s.RecordUsage(tenant.ID, "metrics", 200, 50)
	s.RecordUsage(tenant.ID, "metrics", 200, 75)

	s.FlushCounters()

	req, bytes, errs, err := s.CounterTotals(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if req != 5 {
		t.Fatalf("expected 5 requests, got %d", req)
	}
	if bytes != 725 {
		t.Fatalf("expected 725 bytes (100+200+300+50+75), got %d", bytes)
	}
	if errs != 1 {
		t.Fatalf("expected 1 error, got %d", errs)
	}

	// Verify GetUsageData still works
	data, err := s.GetUsageData(ctx, tenant.ID, "7d")
	if err != nil {
		t.Fatalf("get usage: %v", err)
	}
	if len(data.SignalTypes) != 2 {
		t.Fatalf("expected 2 signal types, got %d", len(data.SignalTypes))
	}
}

func TestUsageWriterBulk(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "bulk-test", "")

	const n = 10000
	var expectBytes int64
	for i := 0; i < n; i++ {
		signalType := "traces"
		if i%3 == 0 {
			signalType = "metrics"
		} else if i%5 == 0 {
			signalType = "logs"
		}
		sc := 200
		if i%10 == 0 {
			sc = 500
		}
		bc := int64(100 + i%900)
		expectBytes += bc
		s.RecordUsage(tenant.ID, signalType, sc, bc)
	}

	s.FlushCounters()

	req, bytes, errs, err := s.CounterTotals(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if req != n {
		t.Fatalf("expected %d requests, got %d", n, req)
	}
	if bytes != expectBytes {
		t.Fatalf("expected %d bytes, got %d", expectBytes, bytes)
	}
	if errs != n/10 {
		t.Fatalf("expected %d errors (i%%10==0), got %d", n/10, errs)
	}
}

func TestUsageWriterChannelFull(t *testing.T) {
	// Bare writer with no consumer goroutine: the channel fills and excess
	// samples must be dropped instead of blocking.
	w := &UsageWriter{ch: make(chan counterSample, 4096)}

	const over = 100
	for i := 0; i < 4096+over; i++ {
		w.record(counterSample{tenantID: 1, signalType: "traces", hourBucket: "h", requests: 1, bytes: 1})
	}

	dropped := atomic.LoadInt64(&w.dropped)
	if dropped == 0 {
		t.Fatal("expected some dropped samples when channel overflows")
	}
	if dropped < over {
		t.Fatalf("expected >= %d dropped, got %d", over, dropped)
	}
}

func TestUsageWriterGoroutineExit(t *testing.T) {
	path := t.TempDir() + "/goroutine-test.db"
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	tenant, _ := s.CreateTenant(t.Context(), "goroutine-test", "")
	s.RecordUsage(tenant.ID, "traces", 200, 100)

	// Close should block until writer flushes and exits
	s.Close()
	// Reaching here means the writer goroutine stopped cleanly.
}

func TestUsageWriterShutdownFlush(t *testing.T) {
	path := t.TempDir() + "/shutdown-flush.db"
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	tenant, _ := s.CreateTenant(t.Context(), "shutdown-flush", "")
	const n = 5000
	for i := 0; i < n; i++ {
		s.RecordUsage(tenant.ID, "traces", 200, 10)
	}

	// Close flushes everything (Stop drains + flushes)
	s.Close()

	// Reopen and verify all samples flushed
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	req, _, _, err := s2.CounterTotals(t.Context(), tenant.ID)
	if err != nil {
		t.Fatalf("counter totals: %v", err)
	}
	if req != n {
		t.Fatalf("expected %d requests after shutdown flush, got %d", n, req)
	}
}

func TestOnDeleteCascadeCounters(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "cascade-counter", "")
	s.RecordUsage(tenant.ID, "traces", 200, 100)
	s.FlushCounters()

	var cnt int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_counters WHERE tenant_id = ?`, tenant.ID).Scan(&cnt)
	if cnt == 0 {
		t.Fatal("expected counter rows before delete")
	}

	s.DeleteTenant(ctx, tenant.ID)

	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_counters WHERE tenant_id = ?`, tenant.ID).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("ON DELETE CASCADE failed: expected 0 counter rows, got %d", cnt)
	}
}

func TestGetUsageDataFromCounters(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	tenant, _ := s.CreateTenant(ctx, "counters-usage", "")
	// Insert counter rows directly across multiple hour buckets
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO usage_counters (tenant_id, signal_type, hour_bucket, requests, bytes, errors) VALUES
		(?, 'traces', strftime('%Y-%m-%dT%H','now','-2 hours'), 10, 1000, 1),
		(?, 'traces', strftime('%Y-%m-%dT%H','now','-1 hours'), 5, 500, 0),
		(?, 'metrics', strftime('%Y-%m-%dT%H','now','-1 hours'), 3, 300, 0),
		(?, 'logs',    strftime('%Y-%m-%dT%H','now','-3 hours'), 7, 700, 2)`,
		tenant.ID, tenant.ID, tenant.ID, tenant.ID)
	if err != nil {
		t.Fatalf("insert counters: %v", err)
	}

	data, err := s.GetUsageData(ctx, tenant.ID, "24h")
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if len(data.SignalTypes) != 3 {
		t.Fatalf("expected 3 signal types, got %d", len(data.SignalTypes))
	}
	var totalRequests int64
	for _, b := range data.Requests {
		totalRequests += b.Count
	}
	if totalRequests != 25 {
		t.Fatalf("expected 25 total requests, got %d", totalRequests)
	}
}
