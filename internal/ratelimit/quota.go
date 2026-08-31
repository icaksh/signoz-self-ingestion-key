package ratelimit

import (
	"context"
	"log"
	"time"
)

// getDailyUsage returns the bytes used today by the tenant, cached for 60s.
// Fail-open on DB errors: returns 0 so a transient store failure does not
// block legitimate traffic, but increments the failure counter (exposed via
// healthz).
func (l *Limiter) getDailyUsage(ctx context.Context, tenantID int64) int64 {
	l.mu.Lock()
	entry, ok := l.quotaCache[tenantID]
	l.mu.Unlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.used
	}

	used, err := l.store.GetDailyByteUsage(ctx, tenantID)
	if err != nil {
		l.quotaFailures.Add(1)
		log.Printf("[ratelimit] daily usage query error tenant=%d: %v", tenantID, err)
		return 0
	}

	l.mu.Lock()
	l.quotaCache[tenantID] = &quotaEntry{
		used:      used,
		expiresAt: time.Now().Add(60 * time.Second),
	}
	l.mu.Unlock()

	return used
}

// refreshQuotaCache clears the cache so the next AllowBytes re-fetches from
// the DB. Called every 60s by the background goroutine.
func (l *Limiter) refreshQuotaCache() {
	l.mu.Lock()
	l.quotaCache = make(map[int64]*quotaEntry)
	l.mu.Unlock()
}
