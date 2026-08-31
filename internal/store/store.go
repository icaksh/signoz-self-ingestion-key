// Package store owns SQLite persistence: connection setup, ordered
// migrations, and the tenant/user/api-key/certificate/usage repositories.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps a single-writer SQLite database plus the background usage
// writer.
type Store struct {
	db     *sql.DB
	writer *UsageWriter
}

// Open opens (or creates) the SQLite database at path, applies migrations,
// verifies critical pragmas, and starts the usage writer. The returned Store
// must be closed with Close.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Single writer avoids SQLITE_BUSY and simplifies the usage writer.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	var journalMode, foreignKeys string
	_ = db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	_ = db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys)
	log.Printf("[store] sqlite pragmas: journal_mode=%s foreign_keys=%s", journalMode, foreignKeys)

	writer := NewUsageWriter(db)
	writer.Start()

	return &Store{db: db, writer: writer}, nil
}

// Close stops the usage writer (flushing buffered counters) and closes the
// database.
func (s *Store) Close() error {
	if s.writer != nil {
		s.writer.Stop()
	}
	return s.db.Close()
}

// Ping reports whether the database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Tenant is the tenant record, with optional rate-limit fields (nil =
// unlimited).
type Tenant struct {
	ID             int64
	Name           string
	APIKey         string // populated only transiently at create/regenerate
	KeyPrefix      string
	Active         bool
	Description    string
	RateLimitRPS   *int64
	BurstBytes     *int64
	DailyByteQuota *int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RateLimitParams carries optional per-tenant rate limits; nil fields are
// unlimited.
type RateLimitParams struct {
	RateLimitRPS   *int64
	BurstBytes     *int64
	DailyByteQuota *int64
}

// User is an admin user.
type User struct {
	ID        int64
	Username  string
	CreatedAt time.Time
}

// RequestBucket is one bar in the requests-over-time chart.
type RequestBucket struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// VolumeBucket is one point in the volume-over-time chart.
type VolumeBucket struct {
	Label string `json:"label"`
	Bytes int64  `json:"bytes"`
}

// SignalBucket is one slice of the signal-type breakdown.
type SignalBucket struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}
