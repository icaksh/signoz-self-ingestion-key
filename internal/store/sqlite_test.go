package store

import (
	"context"
	"os"
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
	if len(tenant.APIKey) != 32 {
		t.Fatalf("expected 32-char hex key, got %d", len(tenant.APIKey))
	}
	if !tenant.Active {
		t.Fatal("expected active tenant")
	}

	found, err := s.LookupTenant(ctx, tenant.APIKey)
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

	found, _ := s.LookupTenant(ctx, newKey)
	if found == nil {
		t.Fatal("expected to find tenant by new key")
	}

	foundOld, _ := s.LookupTenant(ctx, oldKey)
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
