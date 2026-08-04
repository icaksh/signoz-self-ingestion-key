package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/sismedika/otlp-proxy/internal/store"
)

func testDB(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func int64p(v int64) *int64 { return &v }

func TestRateLimitRPS(t *testing.T) {
	st := testDB(t)
	tenant, _ := st.CreateTenant(context.Background(), "rps-test", "", &store.RateLimitParams{RateLimitRPS: int64p(10)})

	lim := NewLimiter(st)
	lim.Start()
	defer lim.Stop()

	for i := 0; i < 10; i++ {
		dec := lim.AllowRPS(tenant.ID)
		if !dec.Allowed {
			t.Fatalf("request %d unexpectedly rejected: %s", i+1, dec.Reason)
		}
	}
	dec := lim.AllowRPS(tenant.ID)
	if dec.Allowed {
		t.Fatal("11th request should be rejected")
	}
	if dec.Reason != "rps" {
		t.Fatalf("expected reason=rps, got %s", dec.Reason)
	}
}

func TestRateLimitBurstBytes(t *testing.T) {
	st := testDB(t)
	tenant, _ := st.CreateTenant(context.Background(), "burst-test", "", &store.RateLimitParams{BurstBytes: int64p(100)})

	lim := NewLimiter(st)

	// 100 bytes allowed (burst = 100)
	if dec := lim.AllowBytes(tenant.ID, 100); !dec.Allowed {
		t.Fatalf("expected 100 bytes allowed: %s", dec.Reason)
	}
	// Next byte beyond burst rejected
	dec := lim.AllowBytes(tenant.ID, 1)
	if dec.Allowed {
		t.Fatal("expected rejection after burst exhausted")
	}
	if dec.Reason != "burst_bytes" {
		t.Fatalf("expected reason=burst_bytes, got %s", dec.Reason)
	}
}

func TestUnlimitedTenant(t *testing.T) {
	st := testDB(t)
	tenant, _ := st.CreateTenant(context.Background(), "unlimited", "", nil)

	lim := NewLimiter(st)

	for i := 0; i < 1000; i++ {
		if dec := lim.AllowRPS(tenant.ID); !dec.Allowed {
			t.Fatalf("request %d should be allowed: %s", i+1, dec.Reason)
		}
		if dec := lim.AllowBytes(tenant.ID, 1_000_000); !dec.Allowed {
			t.Fatalf("bytes request %d should be allowed: %s", i+1, dec.Reason)
		}
	}
}

func TestQuotaExhaustion(t *testing.T) {
	ctx := context.Background()
	st := testDB(t)
	tenant, _ := st.CreateTenant(ctx, "quota-test", "", &store.RateLimitParams{DailyByteQuota: int64p(1000)})

	// Seed usage: 900 bytes today
	st.RecordUsage(tenant.ID, "traces", 200, 900)
	st.FlushCounters()

	lim := NewLimiter(st)

	// 900 used + 100 requested = 1000 = at limit, allowed
	if dec := lim.AllowBytes(tenant.ID, 100); !dec.Allowed {
		t.Fatalf("expected at-limit request allowed: %s", dec.Reason)
	}
	// 900 used + 101 requested > 1000 → rejected
	dec := lim.AllowBytes(tenant.ID, 101)
	if dec.Allowed {
		t.Fatal("expected quota rejection")
	}
	if dec.Reason != "daily_quota" {
		t.Fatalf("expected reason=daily_quota, got %s", dec.Reason)
	}
}

func TestAllowOrder(t *testing.T) {
	st := testDB(t)
	tenant, _ := st.CreateTenant(context.Background(), "order-test", "", &store.RateLimitParams{
		RateLimitRPS:   int64p(1),
		BurstBytes:     int64p(1000),
		DailyByteQuota: int64p(100000),
	})

	lim := NewLimiter(st)

	// Exhaust RPS first
	if dec := lim.AllowRPS(tenant.ID); !dec.Allowed {
		t.Fatal("first RPS should be allowed")
	}
	dec := lim.AllowRPS(tenant.ID)
	if dec.Allowed || dec.Reason != "rps" {
		t.Fatalf("expected rps rejection, got %+v", dec)
	}

	// RPS exhausted but bytes still allowed (checks are independent)
	if dec := lim.AllowBytes(tenant.ID, 10); !dec.Allowed {
		t.Fatalf("bytes should still be allowed: %s", dec.Reason)
	}
}

func TestQuotaFailuresCounter(t *testing.T) {
	st := testDB(t)
	tenant, _ := st.CreateTenant(context.Background(), "qf-test", "", nil)

	lim := NewLimiter(st)

	// Initial count should be 0
	if qf := lim.QuotaFailures(); qf != 0 {
		t.Fatalf("expected 0 quota failures, got %d", qf)
	}

	// Successful lookup resets to 0
	st.RecordUsage(tenant.ID, "traces", 200, 100)
	st.FlushCounters()

	lim.AllowBytes(tenant.ID, 10)
	if qf := lim.QuotaFailures(); qf != 0 {
		t.Fatalf("expected 0 quota failures after successful lookup, got %d", qf)
	}
}

func TestBucketEviction(t *testing.T) {
	st := testDB(t)
	tenant, _ := st.CreateTenant(context.Background(), "evict-test", "", &store.RateLimitParams{RateLimitRPS: int64p(1)})

	lim := NewLimiter(st)

	lim.AllowRPS(tenant.ID)

	lim.mu.Lock()
	b, ok := lim.buckets[tenant.ID]
	if !ok {
		t.Fatal("expected bucket to exist")
	}
	lim.mu.Unlock()

	// Mark last access as 2h ago → eviction should remove it
	lim.mu.Lock()
	b.lastAccess = time.Now().Add(-2 * time.Hour)
	lim.mu.Unlock()

	lim.evictBuckets()

	lim.mu.Lock()
	_, ok = lim.buckets[tenant.ID]
	lim.mu.Unlock()
	if ok {
		t.Fatal("expected bucket to be evicted after idle")
	}

	// Recreate on access
	if dec := lim.AllowRPS(tenant.ID); !dec.Allowed {
		t.Fatal("expected allowed after re-creation")
	}
}
