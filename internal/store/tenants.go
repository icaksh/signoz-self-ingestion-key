package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// tenantSelect returns the tenant columns plus the latest active key prefix.
const tenantSelect = `
	SELECT t.id, t.name, COALESCE(t.api_key, ''), t.active, t.description,
	       t.rate_limit_rps, t.burst_bytes, t.daily_byte_quota, t.created_at, t.updated_at,
	       COALESCE((SELECT ak.key_prefix FROM api_keys ak
	                 WHERE ak.tenant_id = t.id AND ak.enabled = 1 AND ak.revoked_at IS NULL
	                 ORDER BY ak.created_at DESC LIMIT 1), '') AS key_prefix`

func scanTenant(scanner interface{ Scan(...any) error }) (*Tenant, error) {
	t := &Tenant{}
	var active int
	var rps, burst, quota sql.NullInt64
	if err := scanner.Scan(&t.ID, &t.Name, &t.APIKey, &active, &t.Description,
		&rps, &burst, &quota, &t.CreatedAt, &t.UpdatedAt, &t.KeyPrefix); err != nil {
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
	return t, nil
}

// LookupTenantByID returns a tenant by ID, or (nil, nil) when absent.
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

// ListTenants returns all tenants, newest first.
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

// CreateTenant creates a tenant and its first API key. The returned Tenant
// carries the full plaintext key for one-time display; only the hash is
// persisted.
func (s *Store) CreateTenant(ctx context.Context, name, description string, limits *RateLimitParams) (*Tenant, error) {
	if limits == nil {
		limits = &RateLimitParams{}
	}
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (name, api_key, active, description, rate_limit_rps, burst_bytes, daily_byte_quota, created_at, updated_at)
		 VALUES (?, '', 1, ?, ?, ?, ?, ?, ?)`,
		name, description, limits.RateLimitRPS, limits.BurstBytes, limits.DailyByteQuota, now, now)
	if err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	id, _ := res.LastInsertId()

	apiKey := GenerateAPIKeyV2(id)
	keyHash := HashKey(apiKey)
	keyPrefix := apiKey[:12]
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (tenant_id, key_hash, key_prefix) VALUES (?, ?, ?)`,
		id, keyHash, keyPrefix); err != nil {
		return nil, fmt.Errorf("create api_key: %w", err)
	}

	return &Tenant{
		ID:             id,
		Name:           name,
		APIKey:         apiKey,
		KeyPrefix:      keyPrefix,
		Active:         true,
		Description:    description,
		RateLimitRPS:   limits.RateLimitRPS,
		BurstBytes:     limits.BurstBytes,
		DailyByteQuota: limits.DailyByteQuota,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

// UpdateTenant updates editable tenant fields.
func (s *Store) UpdateTenant(ctx context.Context, id int64, name, description string, active bool, limits *RateLimitParams) error {
	if limits == nil {
		limits = &RateLimitParams{}
	}
	activeInt := 0
	if active {
		activeInt = 1
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE tenants SET name = ?, active = ?, description = ?, rate_limit_rps = ?, burst_bytes = ?, daily_byte_quota = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		name, activeInt, description, limits.RateLimitRPS, limits.BurstBytes, limits.DailyByteQuota, id)
	return err
}

// DeleteTenant removes a tenant (cascading to keys/certs/usage).
func (s *Store) DeleteTenant(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, id)
	return err
}

// RegenerateKey revokes all active keys for a tenant and issues a new one.
// Returns the full plaintext key for one-time display.
func (s *Store) RegenerateKey(ctx context.Context, id int64) (string, error) {
	if err := s.RevokeAllKeysForTenant(ctx, id); err != nil {
		return "", err
	}
	apiKey := GenerateAPIKeyV2(id)
	keyHash := HashKey(apiKey)
	keyPrefix := apiKey[:12]
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (tenant_id, key_hash, key_prefix) VALUES (?, ?, ?)`,
		id, keyHash, keyPrefix); err != nil {
		return "", err
	}
	return apiKey, nil
}
