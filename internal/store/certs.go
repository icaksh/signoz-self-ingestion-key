package store

import (
	"context"
	"database/sql"
	"time"
)

// Certificate is a client certificate enrolled for a tenant.
type Certificate struct {
	ID                int64
	TenantID          int64
	SerialNumber      string
	FingerprintSHA256 string
	SubjectCN         string
	NotBefore         time.Time
	NotAfter          time.Time
	RevokedAt         sql.NullTime
	CreatedAt         time.Time
	LastSeenAt        sql.NullTime
}

const certColumns = `id, tenant_id, serial_number, fingerprint_sha256, subject_cn,
       not_before, not_after, revoked_at, created_at, last_seen_at`

func scanCertificate(scanner interface{ Scan(...any) error }) (*Certificate, error) {
	c := &Certificate{}
	var notBefore, notAfter, revokedAt, lastSeenAt sql.NullTime
	if err := scanner.Scan(&c.ID, &c.TenantID, &c.SerialNumber, &c.FingerprintSHA256, &c.SubjectCN,
		&notBefore, &notAfter, &revokedAt, &c.CreatedAt, &lastSeenAt); err != nil {
		return nil, err
	}
	if notBefore.Valid {
		c.NotBefore = notBefore.Time
	}
	if notAfter.Valid {
		c.NotAfter = notAfter.Time
	}
	if revokedAt.Valid {
		c.RevokedAt = revokedAt
	}
	if lastSeenAt.Valid {
		c.LastSeenAt = lastSeenAt
	}
	return c, nil
}

// LookupTenantByFingerprint resolves the active tenant for a client-cert
// fingerprint. Returns (nil, nil) when unknown, revoked, or inactive.
func (s *Store) LookupTenantByFingerprint(ctx context.Context, fingerprint string) (*Tenant, error) {
	t, err := scanTenant(s.db.QueryRowContext(ctx,
		`SELECT t.id, t.name, COALESCE(t.api_key, ''), t.active, t.description,
		        t.rate_limit_rps, t.burst_bytes, t.daily_byte_quota, t.created_at, t.updated_at,
		        COALESCE((SELECT ak.key_prefix FROM api_keys ak
		                  WHERE ak.tenant_id = t.id AND ak.enabled = 1 AND ak.revoked_at IS NULL
		                  ORDER BY ak.created_at DESC LIMIT 1), '') AS key_prefix
		 FROM tenants t
		 JOIN certificates c ON c.tenant_id = t.id
		 WHERE c.fingerprint_sha256 = ? AND c.revoked_at IS NULL AND t.active = 1`,
		fingerprint))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// LookupCertificateByFingerprint returns the certificate metadata for a
// fingerprint, or (nil, nil) when unknown.
func (s *Store) LookupCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	c, err := scanCertificate(s.db.QueryRowContext(ctx,
		`SELECT `+certColumns+` FROM certificates WHERE fingerprint_sha256 = ?`, fingerprint))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// UpdateLastSeen stamps last_seen_at for a fingerprint.
func (s *Store) UpdateLastSeen(ctx context.Context, fingerprint string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE certificates SET last_seen_at = CURRENT_TIMESTAMP WHERE fingerprint_sha256 = ?`,
		fingerprint)
	return err
}

// AddCertificate records a newly issued certificate.
func (s *Store) AddCertificate(ctx context.Context, tenantID int64, serial, fingerprint, cn string, notBefore, notAfter time.Time) (*Certificate, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO certificates (tenant_id, serial_number, fingerprint_sha256, subject_cn, not_before, not_after)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		tenantID, serial, fingerprint, cn, notBefore, notAfter)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Certificate{
		ID:                id,
		TenantID:          tenantID,
		SerialNumber:      serial,
		FingerprintSHA256: fingerprint,
		SubjectCN:         cn,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
		CreatedAt:         time.Now(),
	}, nil
}

// RevokeCertificate marks a certificate revoked locally.
func (s *Store) RevokeCertificate(ctx context.Context, fingerprint string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE certificates SET revoked_at = CURRENT_TIMESTAMP WHERE fingerprint_sha256 = ?`,
		fingerprint)
	return err
}

// ListCertificates returns all certificates for a tenant, newest first.
func (s *Store) ListCertificates(ctx context.Context, tenantID int64) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+certColumns+` FROM certificates WHERE tenant_id = ? ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var certs []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *c)
	}
	return certs, rows.Err()
}

// LookupCertificateByID fetches a certificate by its database ID.
func (s *Store) LookupCertificateByID(ctx context.Context, id int64) (*Certificate, error) {
	c, err := scanCertificate(s.db.QueryRowContext(ctx,
		`SELECT `+certColumns+` FROM certificates WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ExpiringCertInfo is a lightweight view of a certificate expiring soon.
type ExpiringCertInfo struct {
	TenantName string
	CertID     int64
	TenantID   int64
	SubjectCN  string
	NotAfter   time.Time
}

// ListExpiringCertificates returns all non-revoked certificates expiring
// within the next withinHours hours, soonest first.
func (s *Store) ListExpiringCertificates(ctx context.Context, withinHours int) ([]ExpiringCertInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT t.name, c.id, c.tenant_id, c.subject_cn, c.not_after
		 FROM certificates c
		 JOIN tenants t ON t.id = c.tenant_id
		 WHERE c.revoked_at IS NULL
		   AND c.not_after <= datetime('now', '+' || ? || ' hours')
		   AND t.active = 1
		 ORDER BY c.not_after ASC`, withinHours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var certs []ExpiringCertInfo
	for rows.Next() {
		var c ExpiringCertInfo
		var notAfter sql.NullTime
		if err := rows.Scan(&c.TenantName, &c.CertID, &c.TenantID, &c.SubjectCN, &notAfter); err != nil {
			return nil, err
		}
		if notAfter.Valid {
			c.NotAfter = notAfter.Time
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// ExpiringCertsByTenant returns a count of expiring certificates per tenant
// within the next withinHours hours.
func (s *Store) ExpiringCertsByTenant(ctx context.Context, withinHours int) (map[int64]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT c.tenant_id, COUNT(*)
		 FROM certificates c
		 JOIN tenants t ON t.id = c.tenant_id
		 WHERE c.revoked_at IS NULL
		   AND c.not_after <= datetime('now', '+' || ? || ' hours')
		   AND t.active = 1
		 GROUP BY c.tenant_id`, withinHours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[int64]int)
	for rows.Next() {
		var tenantID int64
		var count int
		if err := rows.Scan(&tenantID, &count); err != nil {
			return nil, err
		}
		m[tenantID] = count
	}
	return m, rows.Err()
}
