package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"strconv"
	"strings"
)

// GenerateAPIKeyV2 returns a key of the form ing_<tenantID>_<48 hex chars>.
// The secret is 24 random bytes. Full plaintext is returned only to the caller
// for one-time display; only its SHA-256 hash is persisted.
func GenerateAPIKeyV2(tenantID int64) string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return "ing_" + strconv.FormatInt(tenantID, 10) + "_" + hex.EncodeToString(b)
}

// HashKey returns the hex-encoded SHA-256 of a full key.
func HashKey(fullKey string) string {
	h := sha256.Sum256([]byte(fullKey))
	return hex.EncodeToString(h[:])
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// LookupTenantByKey authenticates a full API key against the api_keys table.
// Returns (nil, nil) for not-found, malformed, revoked, disabled, or inactive.
// Legacy 32-hex keys are matched exactly (constant-time) against key_hash.
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

		keyHash := HashKey(fullKey)
		rows, err := s.db.QueryContext(ctx,
			`SELECT ak.key_hash, t.id, t.name, COALESCE(t.api_key, ''), t.active, t.description,
			        t.rate_limit_rps, t.burst_bytes, t.daily_byte_quota, t.created_at, t.updated_at
			 FROM api_keys ak JOIN tenants t ON ak.tenant_id = t.id
			 WHERE ak.tenant_id = ? AND ak.enabled = 1 AND ak.revoked_at IS NULL AND t.active = 1`,
			tenantID)
		if err != nil {
			return nil, err
		}
		return s.matchCandidates(ctx, rows, keyHash)
	}

	// Legacy path: pre-migration plaintext keys were 32 lowercase hex chars.
	if len(fullKey) != 32 || !isHex(fullKey) {
		return nil, nil
	}
	keyHash := HashKey(fullKey)
	rows, err := s.db.QueryContext(ctx,
		`SELECT ak.key_hash, t.id, t.name, COALESCE(t.api_key, ''), t.active, t.description,
		        t.rate_limit_rps, t.burst_bytes, t.daily_byte_quota, t.created_at, t.updated_at
		 FROM api_keys ak JOIN tenants t ON ak.tenant_id = t.id
		 WHERE ak.key_hash = ? AND ak.enabled = 1 AND ak.revoked_at IS NULL AND t.active = 1`,
		keyHash)
	if err != nil {
		return nil, err
	}
	return s.matchCandidates(ctx, rows, keyHash)
}

type keyCandidate struct {
	hash string
	ten  Tenant
}

// matchCandidates compares the hashed key against candidate rows using a
// constant-time compare. All rows are collected before any follow-up query to
// avoid deadlock under MaxOpenConns(1).
func (s *Store) matchCandidates(ctx context.Context, rows *sql.Rows, keyHash string) (*Tenant, error) {
	var candidates []keyCandidate
	for rows.Next() {
		var hash string
		var t Tenant
		var active int
		var rps, burst, quota sql.NullInt64
		if err := rows.Scan(&hash, &t.ID, &t.Name, &t.APIKey, &active, &t.Description,
			&rps, &burst, &quota, &t.CreatedAt, &t.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		t.Active = active == 1
		if rps.Valid {
			t.RateLimitRPS = &rps.Int64
		}
		if burst.Valid {
			t.BurstBytes = &burst.Int64
		}
		if quota.Valid {
			t.DailyByteQuota = &quota.Int64
		}
		candidates = append(candidates, keyCandidate{hash: hash, ten: t})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	for _, c := range candidates {
		if subtle.ConstantTimeCompare([]byte(c.hash), []byte(keyHash)) == 1 {
			// Best-effort last_used_at update; never fail auth on error.
			_, _ = s.db.ExecContext(ctx,
				`UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_hash = ?`, c.hash)
			return &c.ten, nil
		}
	}
	return nil, nil
}

// CreateAPIKey inserts a new API key row for a tenant.
func (s *Store) CreateAPIKey(ctx context.Context, tenantID int64, keyHash, keyPrefix string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (tenant_id, key_hash, key_prefix) VALUES (?, ?, ?)`,
		tenantID, keyHash, keyPrefix)
	return err
}

// RevokeAllKeysForTenant revokes every active key for a tenant.
func (s *Store) RevokeAllKeysForTenant(ctx context.Context, tenantID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND revoked_at IS NULL`,
		tenantID)
	return err
}
