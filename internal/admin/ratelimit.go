package admin

import (
	"sync"
	"time"
)

type windowCount struct {
	count   int
	resetAt time.Time
}

// LoginLimiter rate-limits login attempts per username and per client IP.
// Window: 15 minutes, max 5 failures.
type LoginLimiter struct {
	mu      sync.Mutex
	entries map[string]*windowCount
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		entries: make(map[string]*windowCount),
	}
}

// Allow returns true if the attempt for key is allowed, false if rate limited.
// It also records the failure (incrementing the counter) when allowed.
func (l *LoginLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	entry, ok := l.entries[key]
	if !ok || now.After(entry.resetAt) {
		l.entries[key] = &windowCount{count: 1, resetAt: now.Add(15 * time.Minute)}
		return true
	}
	if entry.count >= 5 {
		return false
	}
	entry.count++
	return true
}
