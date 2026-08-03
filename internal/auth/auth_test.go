package auth

import (
	"context"
	"testing"
	"time"

	"github.com/sismedika/otlp-proxy/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestResolveAPIKey(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	tenant, _ := st.CreateTenant(ctx, "app", "", nil)

	g := NewGateway(st)

	found, err := g.ResolveTenant(ctx, NewAPIKeyCredential(tenant.APIKey))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if found == nil || found.ID != tenant.ID {
		t.Fatalf("expected tenant %d, got %+v", tenant.ID, found)
	}
}

func TestResolveAPIKeyUnknown(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	g := NewGateway(st)

	found, err := g.ResolveTenant(ctx, NewAPIKeyCredential("ing_1_000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if found != nil {
		t.Fatal("expected nil for unknown key")
	}
}

func TestResolveCertFingerprint(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	tenant, _ := st.CreateTenant(ctx, "cert-app", "", nil)

	fp := "abcdef1234567890"
	_, err := st.AddCertificate(ctx, tenant.ID, "12345", fp, "client-1", time.Now(), time.Now().Add(24*3600e9))
	if err != nil {
		t.Fatalf("add cert: %v", err)
	}

	g := NewGateway(st)
	found, err := g.ResolveTenant(ctx, NewCertCredential(fp))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if found == nil || found.ID != tenant.ID {
		t.Fatalf("expected tenant %d via fingerprint, got %+v", tenant.ID, found)
	}
}

func TestResolveRevokedCert(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	tenant, _ := st.CreateTenant(ctx, "revoked-app", "", nil)

	fp := "feedbeef12345678"
	_, err := st.AddCertificate(ctx, tenant.ID, "99", fp, "client-1", time.Now(), time.Now().Add(24*3600e9))
	if err != nil {
		t.Fatalf("add cert: %v", err)
	}
	if err := st.RevokeCertificate(ctx, fp); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	g := NewGateway(st)
	found, _ := g.ResolveTenant(ctx, NewCertCredential(fp))
	if found != nil {
		t.Fatal("expected nil for revoked cert")
	}
}

func TestUnknownCredentialType(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	g := NewGateway(st)

	found, err := g.ResolveTenant(ctx, Credential{Type: 99, Value: "x"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if found != nil {
		t.Fatal("expected nil for unknown credential type")
	}
}
