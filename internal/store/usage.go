package store

import (
	"context"
	"database/sql"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

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

const usageWriterBufferSize = 65536

// UsageWriter aggregates per-request usage samples and flushes them to
// usage_counters every 10s or on shutdown. The channel is bounded so a slow
// DB can never unboundedly grow memory — excess samples are dropped and
// counted in DroppedSamples.
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
		ch:       make(chan counterSample, usageWriterBufferSize),
		flushReq: make(chan chan struct{}),
		accum:    make(map[counterKey]*counterAccum),
	}
}

// Start launches the single writer goroutine.
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

// Stop drains and flushes buffered counters, then joins the goroutine.
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

	// On any failure after the snapshot is taken, merge it back so no samples
	// are lost; a later flush will retry.
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

func (w *UsageWriter) record(s counterSample) {
	select {
	case w.ch <- s:
	default:
		atomic.AddInt64(&w.dropped, 1)
	}
}

// RecordUsage enqueues one usage sample. Never blocks.
func (s *Store) RecordUsage(tenantID int64, signalType string, statusCode int, byteCount int64) {
	hourBucket := time.Now().UTC().Format("2006-01-02T15")
	isErr := statusCode >= 400
	s.writer.record(counterSample{
		tenantID:   tenantID,
		signalType: signalType,
		hourBucket: hourBucket,
		requests:   1,
		bytes:      byteCount,
		isError:    isErr,
	})
}

// DroppedSamples returns the number of usage samples dropped due to a full
// channel.
func (s *Store) DroppedSamples() int64 {
	return atomic.LoadInt64(&s.writer.dropped)
}

// FlushCounters triggers an immediate synchronous flush of in-memory counters.
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

// GetDailyByteUsage returns total bytes recorded for the tenant in the current
// UTC day.
func (s *Store) GetDailyByteUsage(ctx context.Context, tenantID int64) (int64, error) {
	todayPrefix := time.Now().UTC().Format("2006-01-02")
	var total sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT SUM(bytes) FROM usage_counters
		 WHERE tenant_id = ? AND hour_bucket >= ?`,
		tenantID, todayPrefix+"T00",
	).Scan(&total)
	if err != nil {
		return 0, err
	}
	if total.Valid {
		return total.Int64, nil
	}
	return 0, nil
}

// UsageData is the JSON payload for the usage chart endpoints.
type UsageData struct {
	Requests    []RequestBucket `json:"requests"`
	Volumes     []VolumeBucket  `json:"volumes"`
	SignalTypes []SignalBucket  `json:"signal_types"`
}

// GetUsageData aggregates usage_counters for the requested range ("24h",
// "7d", or "30d").
func (s *Store) GetUsageData(ctx context.Context, tenantID int64, rng string) (*UsageData, error) {
	hours := 168
	switch rng {
	case "24h":
		hours = 24
	case "7d":
		hours = 168
	case "30d":
		hours = 720
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

	return &UsageData{Requests: requests, Volumes: volumes, SignalTypes: signalTypes}, nil
}

func (s *Store) getUsageRequests(ctx context.Context, tenantID int64, since string, hours int) ([]RequestBucket, error) {
	query := `SELECT hour_bucket AS label, SUM(requests) AS cnt
		 FROM usage_counters
		 WHERE tenant_id = ? AND hour_bucket >= ?
		 GROUP BY label ORDER BY label`
	if hours > 168 {
		query = `SELECT substr(hour_bucket, 1, 10) AS label, SUM(requests) AS cnt
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

// CleanupOldCounters purges usage_counters older than retentionDays, plus the
// legacy usage_logs table. This fixes the legacy bug where retention only
// touched the dead usage_logs table and never the real usage_counters.
func (s *Store) CleanupOldCounters(ctx context.Context, retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 90
	}
	threshold := time.Now().UTC().AddDate(0, 0, -retentionDays).Format("2006-01-02T15")

	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM usage_counters WHERE hour_bucket < ?`, threshold); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM usage_logs WHERE created_at < datetime('now', ? || ' days')`,
		"-"+strconv.Itoa(retentionDays)); err != nil {
		return err
	}
	return nil
}
