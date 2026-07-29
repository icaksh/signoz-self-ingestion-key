package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Tenant struct {
	ID          int64
	Name        string
	APIKey      string
	Active      bool
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type User struct {
	ID        int64
	Username  string
	CreatedAt time.Time
}

type RequestBucket struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

type VolumeBucket struct {
	Label string `json:"label"`
	Bytes int64  `json:"bytes"`
}

type SignalBucket struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func migrate(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
	    id          INTEGER PRIMARY KEY AUTOINCREMENT,
	    username    TEXT NOT NULL UNIQUE,
	    password    TEXT NOT NULL,
	    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS tenants (
	    id          INTEGER PRIMARY KEY AUTOINCREMENT,
	    name        TEXT NOT NULL,
	    api_key     TEXT NOT NULL UNIQUE,
	    active      INTEGER NOT NULL DEFAULT 1,
	    description TEXT NOT NULL DEFAULT '',
	    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_tenants_api_key ON tenants(api_key);

	CREATE TABLE IF NOT EXISTS usage_logs (
	    id           INTEGER PRIMARY KEY AUTOINCREMENT,
	    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	    signal_type  TEXT    NOT NULL,
	    byte_count   INTEGER NOT NULL,
	    status_code  INTEGER NOT NULL,
	    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_usage_tenant_time ON usage_logs(tenant_id, created_at);
	CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_logs(created_at);
	`
	_, err := db.Exec(schema)
	return err
}

func (s *Store) LookupTenant(ctx context.Context, apiKey string) (*Tenant, error) {
	t := &Tenant{}
	var active int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, api_key, active, description, created_at, updated_at
		 FROM tenants WHERE api_key = ? AND active = 1`, apiKey,
	).Scan(&t.ID, &t.Name, &t.APIKey, &active, &t.Description, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Active = active == 1
	return t, nil
}

func (s *Store) LookupTenantByID(ctx context.Context, id int64) (*Tenant, error) {
	t := &Tenant{}
	var active int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, api_key, active, description, created_at, updated_at
		 FROM tenants WHERE id = ?`, id,
	).Scan(&t.ID, &t.Name, &t.APIKey, &active, &t.Description, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Active = active == 1
	return t, nil
}

func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, api_key, active, description, created_at, updated_at
		 FROM tenants ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		var t Tenant
		var active int
		if err := rows.Scan(&t.ID, &t.Name, &t.APIKey, &active, &t.Description, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.Active = active == 1
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}

func GenerateAPIKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (s *Store) CreateTenant(ctx context.Context, name, description string) (*Tenant, error) {
	apiKey := GenerateAPIKey()
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (name, api_key, active, description, created_at, updated_at)
		 VALUES (?, ?, 1, ?, ?, ?)`,
		name, apiKey, description, now, now)
	if err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Tenant{
		ID:          id,
		Name:        name,
		APIKey:      apiKey,
		Active:      true,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func (s *Store) UpdateTenant(ctx context.Context, id int64, name, description string, active bool) error {
	activeInt := 0
	if active {
		activeInt = 1
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE tenants SET name = ?, active = ?, description = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		name, activeInt, description, id)
	return err
}

func (s *Store) DeleteTenant(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, id)
	return err
}

func (s *Store) RegenerateKey(ctx context.Context, id int64) (string, error) {
	apiKey := GenerateAPIKey()
	_, err := s.db.ExecContext(ctx,
		`UPDATE tenants SET api_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		apiKey, id)
	if err != nil {
		return "", err
	}
	return apiKey, nil
}

func (s *Store) LogUsage(ctx context.Context, tenantID int64, signalType string, byteCount int64, statusCode int) {
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO usage_logs (tenant_id, signal_type, byte_count, status_code)
		 VALUES (?, ?, ?, ?)`,
		tenantID, signalType, byteCount, statusCode)
}

func (s *Store) GetUsageData(ctx context.Context, tenantID int64, rng string) (*UsageData, error) {
	var hours int
	switch rng {
	case "24h":
		hours = 24
	case "7d":
		hours = 168
	case "30d":
		hours = 720
	default:
		hours = 168
	}

	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	requests, err := s.getUsageRequests(ctx, tenantID, since, hours)
	if err != nil {
		return nil, err
	}
	volumes, err := s.getUsageVolumes(ctx, tenantID, since)
	if err != nil {
		return nil, err
	}
	signalTypes, err := s.getUsageSignalTypes(ctx, tenantID, since)
	if err != nil {
		return nil, err
	}

	return &UsageData{
		Requests:    requests,
		Volumes:     volumes,
		SignalTypes: signalTypes,
	}, nil
}

type UsageData struct {
	Requests    []RequestBucket `json:"requests"`
	Volumes     []VolumeBucket  `json:"volumes"`
	SignalTypes []SignalBucket  `json:"signal_types"`
}

func (s *Store) getUsageRequests(ctx context.Context, tenantID int64, since time.Time, hours int) ([]RequestBucket, error) {
	groupBy := "%Y-%m-%d %H:00"
	if hours > 168 {
		groupBy = "%Y-%m-%d"
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT strftime(?, created_at) AS label, COUNT(*) AS cnt
		 FROM usage_logs
		 WHERE tenant_id = ? AND created_at >= ?
		 GROUP BY label ORDER BY label`,
		groupBy, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buckets []RequestBucket
	for rows.Next() {
		var b RequestBucket
		if err := rows.Scan(&b.Label, &b.Count); err != nil {
			return nil, err
		}
		buckets = append(buckets, b)
	}
	return buckets, rows.Err()
}

func (s *Store) getUsageVolumes(ctx context.Context, tenantID int64, since time.Time) ([]VolumeBucket, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT strftime('%Y-%m-%d', created_at) AS label, SUM(byte_count) AS total
		 FROM usage_logs
		 WHERE tenant_id = ? AND created_at >= ?
		 GROUP BY label ORDER BY label`,
		tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buckets []VolumeBucket
	for rows.Next() {
		var b VolumeBucket
		if err := rows.Scan(&b.Label, &b.Bytes); err != nil {
			return nil, err
		}
		buckets = append(buckets, b)
	}
	return buckets, rows.Err()
}

func (s *Store) getUsageSignalTypes(ctx context.Context, tenantID int64, since time.Time) ([]SignalBucket, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT signal_type, COUNT(*) AS cnt
		 FROM usage_logs
		 WHERE tenant_id = ? AND created_at >= ?
		 GROUP BY signal_type ORDER BY cnt DESC`,
		tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buckets []SignalBucket
	for rows.Next() {
		var b SignalBucket
		if err := rows.Scan(&b.Type, &b.Count); err != nil {
			return nil, err
		}
		buckets = append(buckets, b)
	}
	return buckets, rows.Err()
}

// --- user auth ---

func (s *Store) GetUserByUsername(ctx context.Context, username string) (id int64, passwordHash string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT id, password FROM users WHERE username = ?`, username,
	).Scan(&id, &passwordHash)
	if err == sql.ErrNoRows {
		return 0, "", nil
	}
	return
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password) VALUES (?, ?)`, username, passwordHash)
	return err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// --- usage cleanup ---

func (s *Store) CleanupOldLogs(ctx context.Context, retentionDays int) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM usage_logs WHERE created_at < datetime('now', ? || ' days')`,
		fmt.Sprintf("-%d", retentionDays))
	return err
}
