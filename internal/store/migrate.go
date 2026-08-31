package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strconv"
	"strings"
)

// migrationsFS embeds the ordered SQL migration files. File names are
// NNNN_name.sql; NNNN is the integer migration version.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

type migration struct {
	version int
	sql     string
}

// loadMigrations reads all embedded SQL migrations and sorts them by version.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}
	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		underscore := strings.IndexByte(e.Name(), '_')
		if underscore < 0 {
			return nil, fmt.Errorf("migration filename missing version: %s", e.Name())
		}
		version, err := strconv.Atoi(e.Name()[:underscore])
		if err != nil {
			return nil, fmt.Errorf("migration version parse %q: %w", e.Name(), err)
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		out = append(out, migration{version: version, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// migrate runs the ordered migration framework against an open database.
// It is safe on a fresh DB, a legacy DB (adopted via baseline), and an
// already-migrated DB.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
	    version    INTEGER PRIMARY KEY,
	    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := loadAppliedVersions(db)
	if err != nil {
		return err
	}

	// Baseline adoption: a pre-existing legacy DB has the core tables but no
	// migration bookkeeping. Bring it to the "0001" shape in place (zero data
	// movement) and record version 1, then apply only newer migrations.
	legacy := len(applied) == 0 && tableExists(db, "users") && tableExists(db, "tenants")

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	if legacy {
		log.Printf("[store] adopting legacy database (no schema_migrations) in place")
		for _, m := range migrations {
			if m.version != 1 {
				continue
			}
			if err := applyMigration(db, m); err != nil {
				return fmt.Errorf("migration %04d (legacy baseline): %w", m.version, err)
			}
		}
		if err := normalizeLegacyTenants(db); err != nil {
			return err
		}
		if err := migratePlaintextKeys(db); err != nil {
			return err
		}
		if err := recordVersion(db, 1); err != nil {
			return err
		}
	}

	applied, err = loadAppliedVersions(db)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := applyMigration(db, m); err != nil {
			return fmt.Errorf("migration %04d: %w", m.version, err)
		}
		if err := recordVersion(db, m.version); err != nil {
			return err
		}
		log.Printf("[store] applied migration %04d", m.version)
	}
	return nil
}

// applyMigration executes one migration's SQL inside a transaction so a
// failure leaves no partial schema.
func applyMigration(db *sql.DB, m migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(m.sql); err != nil {
		return err
	}
	return tx.Commit()
}

func loadAppliedVersions(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func recordVersion(db *sql.DB, version int) error {
	_, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, version)
	return err
}

func tableExists(db *sql.DB, name string) bool {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?`, name,
	).Scan(&n)
	return err == nil && n > 0
}

// normalizeLegacyTenants performs the two additive/data-preserving steps the
// legacy ad-hoc migrate() did: add the rate-limit columns (best-effort) and
// rebuild the tenants table if it still carries the legacy UNIQUE constraint
// on api_key (multiple tenants must be able to store the empty placeholder).
func normalizeLegacyTenants(db *sql.DB) error {
	for _, s := range []string{
		"ALTER TABLE tenants ADD COLUMN rate_limit_rps INTEGER",
		"ALTER TABLE tenants ADD COLUMN burst_bytes INTEGER",
		"ALTER TABLE tenants ADD COLUMN daily_byte_quota INTEGER",
	} {
		_, _ = db.Exec(s) // best-effort — fails harmlessly if column exists
	}
	return ensureTenantSchema(db)
}

// ensureTenantSchema rebuilds the tenants table if it still carries the legacy
// UNIQUE constraint on api_key. The rebuild runs in a single transaction so a
// crash cannot drop the original table without committing the replacement.
// Rate-limit columns are preserved.
func ensureTenantSchema(db *sql.DB) error {
	var sqlText string
	err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='tenants'`).Scan(&sqlText)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read tenants schema: %w", err)
	}
	if !strings.Contains(sqlText, "UNIQUE") {
		return nil // already rebuilt
	}

	// SQLite forbids changing foreign_keys inside a transaction, so toggle it
	// before and after.
	if _, err := db.Exec(`PRAGMA foreign_keys=off`); err != nil {
		return err
	}
	restore := func() {
		_, _ = db.Exec(`PRAGMA foreign_keys=on`)
	}

	tx, err := db.Begin()
	if err != nil {
		restore()
		return fmt.Errorf("rebuild begin tx: %w", err)
	}
	defer tx.Rollback()

	steps := []string{
		`CREATE TABLE tenants_rebuild (
		    id               INTEGER PRIMARY KEY AUTOINCREMENT,
		    name             TEXT NOT NULL,
		    api_key          TEXT NOT NULL DEFAULT '',
		    active           INTEGER NOT NULL DEFAULT 1,
		    description      TEXT NOT NULL DEFAULT '',
		    rate_limit_rps   INTEGER,
		    burst_bytes      INTEGER,
		    daily_byte_quota INTEGER,
		    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO tenants_rebuild (id, name, api_key, active, description, rate_limit_rps, burst_bytes, daily_byte_quota, created_at, updated_at)
		 SELECT id, name, api_key, active, description, rate_limit_rps, burst_bytes, daily_byte_quota, created_at, updated_at FROM tenants`,
		`DROP TABLE tenants`,
		`ALTER TABLE tenants_rebuild RENAME TO tenants`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_api_key ON tenants(api_key)`,
	}
	for _, stmt := range steps {
		if _, err := tx.Exec(stmt); err != nil {
			restore()
			return fmt.Errorf("rebuild tenants table: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		restore()
		return fmt.Errorf("rebuild commit: %w", err)
	}
	restore()
	log.Printf("[store] rebuilt tenants table (dropped legacy UNIQUE on api_key)")
	return nil
}

// migratePlaintextKeys moves any remaining plaintext tenants.api_key values
// into api_keys (hashed), then blanks tenants.api_key. Idempotent.
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
		hash := HashKey(r.apiKey)
		prefix := r.apiKey
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		if _, err := db.Exec(
			`INSERT OR IGNORE INTO api_keys (tenant_id, key_hash, key_prefix, enabled, created_at)
			 VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)`,
			r.id, hash, prefix,
		); err != nil {
			return fmt.Errorf("migrate api_key for tenant %d: %w", r.id, err)
		}
		if _, err := db.Exec(`UPDATE tenants SET api_key = '' WHERE id = ?`, r.id); err != nil {
			return err
		}
	}
	return nil
}
