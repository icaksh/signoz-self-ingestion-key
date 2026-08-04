package ratelimit

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/sismedika/otlp-proxy/internal/store"
)

// Decision is the outcome of a rate-limit check.
type Decision struct {
	Allowed bool
	Reason  string // "rps", "burst_bytes", "daily_quota", "lookup_failed", "" when allowed
}

type tenantBucket struct {
	rpsLimiter   *rate.Limiter
	burstLimiter *rate.Limiter
	lastAccess   time.Time
}

type quotaEntry struct {
	used      int64
	expiresAt time.Time
}

// Limiter enforces per-tenant rate limits: requests/sec, burst bytes, and a
// daily byte quota. Tenant limits are read from the store on each check;
// buckets are lazily created and evicted after 1h idle.
type Limiter struct {
	store         *store.Store
	mu            sync.Mutex
	buckets       map[int64]*tenantBucket
	quotaCache    map[int64]*quotaEntry
	quotaFailures atomic.Int64
	done          chan struct{}
}

func NewLimiter(st *store.Store) *Limiter {
	return &Limiter{
		store:      st,
		buckets:    make(map[int64]*tenantBucket),
		quotaCache: make(map[int64]*quotaEntry),
		done:       make(chan struct{}),
	}
}

// QuotaFailures returns the number of times the daily usage query failed.
func (l *Limiter) QuotaFailures() int64 {
	return l.quotaFailures.Load()
}

func (l *Limiter) Start() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				l.evictBuckets()
				l.refreshQuotaCache()
			case <-l.done:
				return
			}
		}
	}()
}

func (l *Limiter) Stop() {
	close(l.done)
}

// AllowRPS consumes one RPS token for the tenant. Called before the body is
// read so over-rate tenants are rejected without consuming bandwidth.
func (l *Limiter) AllowRPS(tenantID int64) Decision {
	tenant, err := l.store.LookupTenantByID(context.Background(), tenantID)
	if err != nil || tenant == nil {
		return Decision{Allowed: false, Reason: "lookup_failed"}
	}
	if tenant.RateLimitRPS == nil || *tenant.RateLimitRPS <= 0 {
		return Decision{Allowed: true}
	}

	l.mu.Lock()
	b := l.getOrCreateBucket(tenant)
	b.lastAccess = time.Now()
	l.mu.Unlock()

	if !b.rpsLimiter.Allow() {
		log.Printf("[ratelimit] tenant=%d reason=rps rps_tokens=%.1f", tenantID, b.rpsLimiter.Tokens())
		return Decision{Allowed: false, Reason: "rps"}
	}
	return Decision{Allowed: true}
}

// AllowBytes checks burst bytes and daily quota for a request of byteCount
// bytes. Called after the body size is known. Does not consume RPS tokens.
func (l *Limiter) AllowBytes(tenantID int64, byteCount int64) Decision {
	tenant, err := l.store.LookupTenantByID(context.Background(), tenantID)
	if err != nil || tenant == nil {
		return Decision{Allowed: false, Reason: "lookup_failed"}
	}
	if tenant.BurstBytes == nil && tenant.DailyByteQuota == nil {
		return Decision{Allowed: true}
	}

	l.mu.Lock()
	b := l.getOrCreateBucket(tenant)
	b.lastAccess = time.Now()
	l.mu.Unlock()

	if tenant.BurstBytes != nil && *tenant.BurstBytes > 0 {
		if !b.burstLimiter.AllowN(time.Now(), int(byteCount)) {
			log.Printf("[ratelimit] tenant=%d reason=burst_bytes burst_tokens=%.1f", tenantID, b.burstLimiter.Tokens())
			return Decision{Allowed: false, Reason: "burst_bytes"}
		}
	}

	if tenant.DailyByteQuota != nil && *tenant.DailyByteQuota > 0 {
		used := l.getDailyUsage(tenantID)
		if used+byteCount > *tenant.DailyByteQuota {
			log.Printf("[ratelimit] tenant=%d reason=daily_quota quota=%d/%d",
				tenantID, used, *tenant.DailyByteQuota)
			return Decision{Allowed: false, Reason: "daily_quota"}
		}
	}

	return Decision{Allowed: true}
}
