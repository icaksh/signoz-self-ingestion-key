package ratelimit

import (
	"time"

	"golang.org/x/time/rate"

	"github.com/sismedika/otlp-proxy/internal/store"
)

// getOrCreateBucket lazily creates the token buckets for a tenant. Must be
// called with l.mu held.
func (l *Limiter) getOrCreateBucket(t *store.Tenant) *tenantBucket {
	b, ok := l.buckets[t.ID]
	if !ok {
		rpsRate := 100.0
		rpsBurst := 200
		byteRate := 10_000_000.0 // 10 MB/s default
		byteBurst := 10_000_000

		if t.RateLimitRPS != nil && *t.RateLimitRPS > 0 {
			rpsRate = float64(*t.RateLimitRPS)
			rpsBurst = int(*t.RateLimitRPS) // burst = RPS
		}
		if t.BurstBytes != nil && *t.BurstBytes > 0 {
			byteRate = float64(*t.BurstBytes)
			byteBurst = int(*t.BurstBytes)
		}

		b = &tenantBucket{
			rpsLimiter:   rate.NewLimiter(rate.Limit(rpsRate), rpsBurst),
			burstLimiter: rate.NewLimiter(rate.Limit(byteRate), byteBurst),
			lastAccess:   time.Now(),
		}
		l.buckets[t.ID] = b
	}
	return b
}

// evictBuckets removes buckets idle for more than 1 hour.
func (l *Limiter) evictBuckets() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for id, b := range l.buckets {
		if b.lastAccess.Before(cutoff) {
			delete(l.buckets, id)
		}
	}
}
