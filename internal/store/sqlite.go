package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

type Tenant struct {
	ID          int64
	Name        string
	APIKey      string
	KeyPrefix   string
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
	db     *sql.DB
	writer *UsageWriter
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	// Verify critical pragmas
	var journalMode, foreignKeys string
	_ = db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	_ = db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys)
	log.Printf("[store] sqlite pragmas: journal_mode=%s foreign_keys=%s", journalMode, foreignKeys)

	writer := NewUsageWriter(db)
	writer.Start()

	return &Store{db: db, writer: writer}, nil
}

func (s *Store) Close() error {
	if s.writer != nil {
		s.writer.Stop()
	}
	return s.db.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// counterKey is the composite key for hourly usage aggregation.
type counterKey struct {
	tenantID   int64
	signalType string
	hourBucket string
}

// counterSample is a single usage event sent through the channel.
type counterSample struct {
	tenantID   int64
	signalType string
	hourBucket string
	requests   int64
	bytes      int64
	isError    bool
}

// counterAccum holds in-memory aggregates before flush.
type counterAccum struct {
	requests int64
	bytes    int64
	errors   int64
}

// UsageWriter aggregates per-request usage samples and flushes them to
// usage_counters every 10s or on shutdown. The channel is bounded so a slow
// DB can never unboundedly grow memory — excess samples are dropped and
// counted in DroppedSamples. All channel reads happen on the single writer
// goroutine; flushNow coordinates a synchronous flush through it so a
// concurrent flush can never race an in-flight sample handoff.
type UsageWriter struct {
	db       *sql.DB
	ch       chan counterSample
	flushReq chan chan struct{}
	mu       sync.Mutex
	accum    map[counterKey]*counterAccum
	dropped  int64
	done     chan struct{}
	flushed  chan struct{}
	stopOnce sync.Once
}

func NewUsageWriter(db *sql.DB) *UsageWriter {
	return &UsageWriter{
		db:       db,
		ch:       make(chan counterSample, 4096),
		flushReq: make(chan chan struct{}),
		accum:    make(map[counterKey]*counterAccum),
	}
}

func (w *UsageWriter) Start() {
	w.done = make(chan struct{})
	w.flushed = make(chan struct{})
	go func() {
		defer close(w.flushed)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case s := <-w.ch:
				w.accumulate(s)
			case done := <-w.flushReq:
				w.drain()
				w.flush()
				close(done)
			case <-ticker.C:
				w.flush()
			case <-w.done:
				w.drain()
				w.flush()
				return
			}
		}
	}()
}

func (w *UsageWriter) Stop() {
	w.stopOnce.Do(func() {
		close(w.done)
		<-w.flushed
	})
}

func (w *UsageWriter) accumulate(s counterSample) {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := counterKey{tenantID: s.tenantID, signalType: s.signalType, hourBucket: s.hourBucket}
	acc, ok := w.accum[key]
	if !ok {
		acc = &counterAccum{}
		w.accum[key] = acc
	}
	acc.requests += s.requests
	acc.bytes += s.bytes
	if s.isError {
		acc.errors++
	}
}

func (w *UsageWriter) drain() {
	for {
		select {
		case s := <-w.ch:
			w.accumulate(s)
		default:
			return
		}
	}
}

func (w *UsageWriter) flush() {
	w.mu.Lock()
	snapshot := w.accum
	w.accum = make(map[counterKey]*counterAccum)
	w.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	// On any failure after the snapshot is taken, merge it back so no
	// samples are lost; a later flush will retry.
	restore := func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		for k, v := range snapshot {
			acc := w.accum[k]
			if acc == nil {
				acc = &counterAccum{}
				w.accum[k] = acc
			}
			acc.requests += v.requests
			acc.bytes += v.bytes
			acc.errors += v.errors
		}
	}

	tx, err := w.db.Begin()
	if err != nil {
		log.Printf("[store] flush begin tx: %v", err)
		restore()
		return
	}

	stmt, err := tx.Prepare(`
		INSERT INTO usage_counters (tenant_id, signal_type, hour_bucket, requests, bytes, errors)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, signal_type, hour_bucket) DO UPDATE SET
			requests = requests + excluded.requests,
			bytes    = bytes    + excluded.bytes,
			errors   = errors   + excluded.errors
	`)
	if err != nil {
		tx.Rollback()
		log.Printf("[store] flush prepare: %v", err)
		restore()
		return
	}

	for key, acc := range snapshot {
		if _, err := stmt.Exec(key.tenantID, key.signalType, key.hourBucket, acc.requests, acc.bytes, acc.errors); err != nil {
			stmt.Close()
			tx.Rollback()
			log.Printf("[store] flush exec: %v", err)
			restore()
			return
		}
	}
	stmt.Close()

	if err := tx.Commit(); err != nil {
		log.Printf("[store] flush commit: %v", err)
		restore()
		return
	}
}

// record enqueues one sample. Never blocks: if the bounded channel is full
// the sample is dropped (counted in DroppedSamples).
func (w *UsageWriter) record(s counterSample) {
	select {
	case w.ch <- s:
	default:
		atomic.AddInt64(&w.dropped, 1)
	}
}

// RecordUsage enqueues one usage sample. Never blocks: if the bounded channel
// is full the sample is dropped (counted in DroppedSamples).
func (s *Store) RecordUsage(tenantID int64, signalType string, statusCode int, byteCount int64) {
	hourBucket := time.Now().UTC().Format("2006-01-02T15")
	isErr := statusCode >= 400
	sample := counterSample{
		tenantID:   tenantID,
		signalType: signalType,
		hourBucket: hourBucket,
		requests:   1,
		bytes:      byteCount,
		isError:    isErr,
	}
	s.writer.record(sample)
}

func (s *Store) DroppedSamples() int64 {
	return atomic.LoadInt64(&s.writer.dropped)
}

// FlushCounters triggers an immediate synchronous flush of in-memory usage
// counters via the writer goroutine. Exposed for testing.
func (s *Store) FlushCounters() {
	select {
	case <-s.writer.done:
		return // already stopped — Stop() drained and flushed
	default:
	}
	done := make(chan struct{})
	s.writer.flushReq <- done
	<-done
}

// CounterTotals returns aggregate totals across all counter rows for a tenant.
func (s *Store) CounterTotals(ctx context.Context, tenantID int64) (requests, bytes, errors int64, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests),0), COALESCE(SUM(bytes),0), COALESCE(SUM(errors),0)
		 FROM usage_counters WHERE tenant_id = ?`,
		tenantID).Scan(&requests, &bytes, &errors)
	return
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
	    api_key     TEXT NOT NULL DEFAULT '',
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

	CREATE TABLE IF NOT EXISTS usage_counters (
	    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	    signal_type TEXT    NOT NULL,
	    hour_bucket TEXT    NOT NULL,
	    requests    INTEGER NOT NULL DEFAULT 0,
	    bytes       INTEGER NOT NULL DEFAULT 0,
	    errors      INTEGER NOT NULL DEFAULT 0,
	    PRIMARY KEY (tenant_id, signal_type, hour_bucket)
	);

	CREATE TABLE IF NOT EXISTS api_keys (
	    id           INTEGER PRIMARY KEY AUTOINCREMENT,
	    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	    key_hash     TEXT NOT NULL,
	    key_prefix   TEXT NOT NULL,
	    enabled      INTEGER NOT NULL DEFAULT 1,
	    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	    last_used_at DATETIME,
	    revoked_at   DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	if err := ensureTenantSchema(db); err != nil {
		return err
	}
	return migratePlaintextKeys(db)
}

// ensureTenantSchema rebuilds the tenants table if it still carries the legacy
// UNIQUE constraint on api_key. Multiple tenants must be able to store the
// empty placeholder string (real keys live in the api_keys table now).
func ensureTenantSchema(db *sql.DB) error {
	var sqlText string
	err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='tenants'`).Scan(&sqlText)
	if err == sql.ErrNoRows {
		return nil // fresh DB — created by the new schema above
	}
	if err != nil {
		return fmt.Errorf("read tenants schema: %w", err)
	}
	if !strings.Contains(sqlText, "UNIQUE") {
		return nil // already rebuilt
	}

	// Rebuild without UNIQUE on api_key (standard SQLite 12-step-style rewrite).
	// foreign_keys must be off while the referenced table is dropped.
	if _, err := db.Exec(`PRAGMA foreign_keys=off`); err != nil {
		return err
	}
	steps := []string{
		`CREATE TABLE tenants_rebuild (
		    id          INTEGER PRIMARY KEY AUTOINCREMENT,
		    name        TEXT NOT NULL,
		    api_key     TEXT NOT NULL DEFAULT '',
		    active      INTEGER NOT NULL DEFAULT 1,
		    description TEXT NOT NULL DEFAULT '',
		    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO tenants_rebuild (id, name, api_key, active, description, created_at, updated_at)
		 SELECT id, name, api_key, active, description, created_at, updated_at FROM tenants`,
		`DROP TABLE tenants`,
		`ALTER TABLE tenants_rebuild RENAME TO tenants`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_api_key ON tenants(api_key)`,
	}
	for _, stmt := range steps {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("rebuild tenants table: %w", err)
		}
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=on`); err != nil {
		return err
	}
	log.Printf("[store] rebuilt tenants table (dropped legacy UNIQUE on api_key)")
	return nil
}

// migratePlaintextKeys moves any remaining plaintext tenants.api_key values
// into the api_keys table (hashed), then blanks tenants.api_key. Idempotent:
// rows with empty api_key are skipped.
func migratePlaintextKeys(db *sql.DB) error {
	rows, err := db.Query(`SELECT id, api_key FROM tenants WHERE api_key != ''`)
	if err != nil {
		return fmt.Errorf("migrate api_keys: %w", err)
	}
	defer rows.Close()

	type row struct {
		id     int64
		apiKey string
	}
	var toMigrate []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.apiKey); err != nil {
			return err
		}
		toMigrate = append(toMigrate, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, r := range toMigrate {
		hash := sha256Hex(r.apiKey)
		prefix := r.apiKey
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		_, err := db.Exec(
			`INSERT OR IGNORE INTO api_keys (tenant_id, key_hash, key_prefix, enabled, created_at)
			 VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)`,
			r.id, hash, prefix,
		)
		if err != nil {
			return fmt.Errorf("migrate api_key for tenant %d: %w", r.id, err)
		}
		_, err = db.Exec(`UPDATE tenants SET api_key = '' WHERE id = ?`, r.id)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateAPIKeyV2 returns a key of the form ing_<tenantID>_<48 hex chars>.
func GenerateAPIKeyV2(tenantID int64) string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return "ing_" + strconv.FormatInt(tenantID, 10) + "_" + hex.EncodeToString(b)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// HashKey returns the hex-encoded SHA256 of a full key.
func HashKey(fullKey string) string {
	return sha256Hex(fullKey)
}

// LookupTenant (by plaintext api_key) is deprecated — kept for migration
// compatibility. New code should use LookupTenantByKey.
func (s *Store) LookupTenant(ctx context.Context, apiKey string) (*Tenant, error) {
	t := &Tenant{}
	var active int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, COALESCE(api_key, ''), active, description, created_at, updated_at
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

// LookupTenantByKey authenticates a full API key against the api_keys table.
// Returns (nil, nil) for not-found, invalid, or rejected keys.
func (s *Store) LookupTenantByKey(ctx context.Context, fullKey string) (*Tenant, error) {
	if strings.HasPrefix(fullKey, "ing_") {
		rest := fullKey[4:]
		underscoreIdx := strings.IndexByte(rest, '_')
		if underscoreIdx < 0 {
			return nil, nil
		}
		tenantID, err := strconv.ParseInt(rest[:underscoreIdx], 10, 64)
		if err != nil || tenantID <= 0 {
			return nil, nil
		}
		secret := rest[underscoreIdx+1:]
		if len(secret) != 48 || !isHex(secret) {
			return nil, nil
		}

		keyHash := sha256Hex(fullKey)

		rows, err := s.db.QueryContext(ctx,
			`SELECT ak.key_hash, t.id, t.name, COALESCE(t.api_key, ''), t.active, t.description, t.created_at, t.updated_at
			 FROM api_keys ak JOIN tenants t ON ak.tenant_id = t.id
			 WHERE ak.tenant_id = ? AND ak.enabled = 1 AND ak.revoked_at IS NULL AND t.active = 1`,
			tenantID)
		if err != nil {
			return nil, err
		}
		return s.matchCandidates(ctx, rows, keyHash)
	}

	// Legacy path: pre-migration plaintext keys were 32 lowercase hex chars.
	// After migration their SHA-256 lives in api_keys.key_hash — authenticate by
	// exact hash (indexed, constant-time compare). Keys that don't match either
	// format are rejected before any DB query.
	if len(fullKey) != 32 || !isHex(fullKey) {
		return nil, nil
	}
	keyHash := sha256Hex(fullKey)
	rows, err := s.db.QueryContext(ctx,
		`SELECT ak.key_hash, t.id, t.name, COALESCE(t.api_key, ''), t.active, t.description, t.created_at, t.updated_at
		 FROM api_keys ak JOIN tenants t ON ak.tenant_id = t.id
		 WHERE ak.key_hash = ? AND ak.enabled = 1 AND ak.revoked_at IS NULL AND t.active = 1`,
		keyHash)
	if err != nil {
		return nil, err
	}
	return s.matchCandidates(ctx, rows, keyHash)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// matchCandidates compares the hashed key against candidate rows and returns
// the matching tenant. Collects all rows before any follow-up query to avoid
// deadlock under MaxOpenConns(1).
func (s *Store) matchCandidates(ctx context.Context, rows *sql.Rows, keyHash string) (*Tenant, error) {
	type candidate struct {
		hash string
		ten  Tenant
		act  bool
	}
	var candidates []candidate
	for rows.Next() {
		var hash string
		var t Tenant
		var active int
		if err := rows.Scan(&hash, &t.ID, &t.Name, &t.APIKey, &active, &t.Description, &t.CreatedAt, &t.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, candidate{hash: hash, ten: t, act: active == 1})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	for _, c := range candidates {
		if subtle.ConstantTimeCompare([]byte(c.hash), []byte(keyHash)) == 1 {
			c.ten.Active = c.act
			// Update last_used_at (best-effort, don't fail on error)
			_, _ = s.db.ExecContext(ctx,
				`UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_hash = ?`, c.hash)
			return &c.ten, nil
		}
	}
	return nil, nil
}

// CreateAPIKey inserts a new API key row for a tenant.
func (s *Store) CreateAPIKey(ctx context.Context, tenantID int64, fullKey string, keyHash string, keyPrefix string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (tenant_id, key_hash, key_prefix) VALUES (?, ?, ?)`,
		tenantID, keyHash, keyPrefix)
	return err
}

// tenantSelect returns the column list plus the latest active key prefix.
const tenantSelect = `
	SELECT t.id, t.name, COALESCE(t.api_key, ''), t.active, t.description, t.created_at, t.updated_at,
	       COALESCE((SELECT ak.key_prefix FROM api_keys ak
	                 WHERE ak.tenant_id = t.id AND ak.enabled = 1 AND ak.revoked_at IS NULL
	                 ORDER BY ak.created_at DESC LIMIT 1), '') AS key_prefix`

func scanTenant(scanner interface{ Scan(...any) error }) (*Tenant, error) {
	t := &Tenant{}
	var active int
	err := scanner.Scan(&t.ID, &t.Name, &t.APIKey, &active, &t.Description, &t.CreatedAt, &t.UpdatedAt, &t.KeyPrefix)
	if err != nil {
		return nil, err
	}
	t.Active = active == 1
	return t, nil
}

func (s *Store) LookupTenantByID(ctx context.Context, id int64) (*Tenant, error) {
	t, err := scanTenant(s.db.QueryRowContext(ctx,
		tenantSelect+` FROM tenants t WHERE t.id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx,
		tenantSelect+` FROM tenants t ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, *t)
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
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (name, api_key, active, description, created_at, updated_at)
		 VALUES (?, '', 1, ?, ?, ?)`,
		name, description, now, now)
	if err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	id, _ := res.LastInsertId()

	apiKey := GenerateAPIKeyV2(id)
	keyHash := sha256Hex(apiKey)
	keyPrefix := apiKey[:12]
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO api_keys (tenant_id, key_hash, key_prefix) VALUES (?, ?, ?)`,
		id, keyHash, keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("create api_key: %w", err)
	}

	return &Tenant{
		ID:          id,
		Name:        name,
		APIKey:      apiKey, // full plaintext — returned once for display
		KeyPrefix:   keyPrefix,
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
	// Revoke all active keys for this tenant
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND revoked_at IS NULL`, id)
	if err != nil {
		return "", err
	}

	apiKey := GenerateAPIKeyV2(id)
	keyHash := sha256Hex(apiKey)
	keyPrefix := apiKey[:12]
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO api_keys (tenant_id, key_hash, key_prefix) VALUES (?, ?, ?)`,
		id, keyHash, keyPrefix)
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

	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02T15")

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

func (s *Store) getUsageRequests(ctx context.Context, tenantID int64, since string, hours int) ([]RequestBucket, error) {
	var query string
	if hours > 168 {
		// 30d: group by day
		query = `SELECT substr(hour_bucket, 1, 10) AS label, SUM(requests) AS cnt
			 FROM usage_counters
			 WHERE tenant_id = ? AND hour_bucket >= ?
			 GROUP BY label ORDER BY label`
	} else {
		// 24h/7d: group by hour
		query = `SELECT hour_bucket AS label, SUM(requests) AS cnt
			 FROM usage_counters
			 WHERE tenant_id = ? AND hour_bucket >= ?
			 GROUP BY label ORDER BY label`
	}
	rows, err := s.db.QueryContext(ctx, query, tenantID, since)
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

func (s *Store) getUsageVolumes(ctx context.Context, tenantID int64, since string) ([]VolumeBucket, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT substr(hour_bucket, 1, 10) AS label, SUM(bytes) AS total
		 FROM usage_counters
		 WHERE tenant_id = ? AND hour_bucket >= ?
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

func (s *Store) getUsageSignalTypes(ctx context.Context, tenantID int64, since string) ([]SignalBucket, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT signal_type, SUM(requests) AS cnt
		 FROM usage_counters
		 WHERE tenant_id = ? AND hour_bucket >= ?
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
