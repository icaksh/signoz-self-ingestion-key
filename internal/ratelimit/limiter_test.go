package ratelimit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sismedika/otlp-proxy/internal/store"
)

func newTestLimiter(t *testing.T) (*Limiter, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	l := NewLimiter(st)
	t.Cleanup(l.Stop)
	return l, st
}

func TestUnlimitedByDefault(t *testing.T) {
	l, st := newTestLimiter(t)
	ctx := context.Background()
	tenant, err := st.CreateTenant(ctx, "unlimited", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// No limits configured: RPS and bytes always allowed.
	for i := 0; i < 1000; i++ {
		if d := l.AllowRPS(ctx, tenant.ID); !d.Allowed {
			t.Fatalf("RPS denied for unlimited tenant: %v", d.Reason)
		}
	}
	if d := l.AllowBytes(ctx, tenant.ID, 1<<30); !d.Allowed {
		t.Fatalf("bytes denied for unlimited tenant: %v", d.Reason)
	}
}

func TestRPSLimit(t *testing.T) {
	l, st := newTestLimiter(t)
	ctx := context.Background()
	rps := int64(5)
	tenant, err := st.CreateTenant(ctx, "rps", "", &store.RateLimitParams{RateLimitRPS: &rps})
	if err != nil {
		t.Fatal(err)
	}
	// Burst equals RPS, so the first N are allowed then rejected.
	for i := 0; i < int(rps); i++ {
		if d := l.AllowRPS(ctx, tenant.ID); !d.Allowed {
			t.Fatalf("request %d denied: %v", i, d.Reason)
		}
	}
	if d := l.AllowRPS(ctx, tenant.ID); d.Allowed || d.Reason != "rps" {
		t.Fatalf("expected rps rejection, got %+v", d)
	}
}

func TestBurstBytesLimit(t *testing.T) {
	l, st := newTestLimiter(t)
	ctx := context.Background()
	burst := int64(1024)
	tenant, err := st.CreateTenant(ctx, "burst", "", &store.RateLimitParams{BurstBytes: &burst})
	if err != nil {
		t.Fatal(err)
	}
	if d := l.AllowBytes(ctx, tenant.ID, 2048); d.Allowed || d.Reason != "burst_bytes" {
		t.Fatalf("expected burst_bytes rejection, got %+v", d)
	}
	if d := l.AllowBytes(ctx, tenant.ID, 512); !d.Allowed {
		t.Fatalf("small request denied: %v", d.Reason)
	}
}

func TestDailyQuotaLimit(t *testing.T) {
	l, st := newTestLimiter(t)
	ctx := context.Background()
	quota := int64(2048)
	tenant, err := st.CreateTenant(ctx, "quota", "", &store.RateLimitParams{DailyByteQuota: &quota})
	if err != nil {
		t.Fatal(err)
	}
	// First request consumes quota in the DB via RecordUsage.
	st.RecordUsage(tenant.ID, "traces", 200, 1500)
	st.FlushCounters()
	if d := l.AllowBytes(ctx, tenant.ID, 1000); d.Allowed || d.Reason != "daily_quota" {
		t.Fatalf("expected daily_quota rejection, got %+v", d)
	}
}

func TestLookupFailed(t *testing.T) {
	l, _ := newTestLimiter(t)
	ctx := context.Background()
	if d := l.AllowRPS(ctx, 999999); d.Allowed || d.Reason != "lookup_failed" {
		t.Fatalf("expected lookup_failed, got %+v", d)
	}
}
