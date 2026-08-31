# OTLP Proxy — Greenfield Rewrite Specification

Legend used throughout:

- **[verified]** — confirmed by reading legacy source/tests/config directly.
- **[inference]** — reasonable conclusion from surrounding code/docs, not directly observed.
- **[decision]** — new design choice made for the rewrite; not constrained by legacy.

---

## 1. Verified legacy product inventory

The legacy product (`github.com/sismedika/otlp-proxy`) is a single Go binary
(module `go 1.25.0`) that is a **tenant-authenticating OTLP proxy** in front of
a SigNoz (or any OTLP) receiver, plus a **self-hosted admin dashboard**.

**[verified]** Subsystems:

| Subsystem | Package | Role |
|:---|:---|:---|
| Config | `internal/config` | Env-var loading + validation |
| Store | `internal/store` | SQLite (modernc.org/sqlite), tenants, users, API keys, certs, usage counters |
| Auth gateway | `internal/auth` | Resolve credential (API key / cert fingerprint) → tenant |
| OTLP proxy | `internal/proxy` | `:4318` reverse proxy; auth, rate-limit, tenant stamping, usage accounting |
| Rate limit | `internal/ratelimit` | Per-tenant RPS / burst bytes / daily byte quota |
| Admin | `internal/admin` | `:8080` (default `127.0.0.1:8080`) dashboard; HTMX + templates + CSS + Chart.js |
| Syslog | `internal/syslog` | Optional RFC 5425 mTLS syslog ingestion → collector |
| CA | `internal/ca` | Optional step-ca client, bundle download, mTLS renewal server |
| Main | `cmd/proxy` | Wiring + lifecycle |

**[verified]** Deployed artifacts: multi-stage `Dockerfile`
(`golang:1.25-alpine` → `alpine:3.21`, `CGO_ENABLED=0`, static binary),
`docker-compose.yml` (ports 4318/8080/6514/6543, `DB_PATH=/data/tenants.db`,
read-only `./certs:/certs`), `Makefile` (`build`/`run`/`test`/`clean`),
GitHub Actions CI (vet, `test -race`, `gofmt`, static build, docker push).

**[verified]** Legacy test suite: 200+ test functions across `config`, `store`,
`auth`, `proxy`, `ratelimit`, `syslog`, `ca`, `admin`; plus two benchmarks in
`proxy/otlp_bench_test.go`. Many `admin` tests are **implementation-coupled to
HTMX** (assert `/static/htmx.min.js` present, `hx-*` fragments, `data-confirm-name`
strings, swap containers `#tenant-list`/`#form-area`/`#download-link`).

---

## 2. External contracts (must be preserved)

These are the externally meaningful behaviors clients and operators rely on.

### 2.1 OTLP ingestion (`:4318`) [verified]

- `POST /v1/traces`, `POST /v1/metrics`, `POST /v1/logs` only. **Exact match** —
  any other path (including `/v1/traces/`) returns `404 {"error":"unknown OTLP path"}`.
- Auth: `X-Tenant-Key` header. Missing → `401 {"error":"missing X-Tenant-Key header"}`.
  Unknown/revoked/inactive → `401 {"error":"invalid tenant key"}`.
- `GET /healthz` (no auth) → `200 {"status":"ok",...}`; DB down → `503`.
- Body limit `MAX_BODY_BYTES` (default 4 MiB) via `http.MaxBytesReader`; over limit → `413`.
- Content types: `application/json` (proto-JSON) and protobuf binary; `application/json`
  variants with charset/params accepted. `Content-Encoding: gzip` bodies decompressed,
  re-stamped, re-compressed (header retained); any other encoding stripped.
- Upstream forwarding: `SIGNOZ_ENDPOINT` base URL; path rewritten to target host;
  `X-Tenant-Key` removed; if `SIGNOZ_INGESTION_KEY` set, `Authorization: Bearer <key>` added.
- Upstream failure → `502 {"error":"backend unreachable"}`; upstream status passthrough.
- Malformed OTLP/gzip → `400 {"error":"invalid request body"}`.
- **Tenant stamping**: client-supplied `tenant.id`, `tenant.name`, `service.namespace`
  resource attributes are removed; server injects `tenant.id` (numeric ID) and
  `tenant.name` (name) into every resource across all signals.

### 2.2 API key format and semantics [verified]

- New keys: `ing_<tenantID>_<48 lowercase hex>` (24 random bytes). Full key returned
  **once** after create/regenerate; afterwards only a 12-char prefix is displayed.
- Keys stored **SHA-256 hashed** only (`api_keys.key_hash`); plaintext never persisted.
- Regenerate revokes all active keys for the tenant and issues a new one.
- **Backward compat**: legacy 32-lowercase-hex keys (pre-`api_keys` migration) remain
  accepted; their hashes live in `api_keys.key_hash` and are matched exactly.
- Tenant "Active" flag: inactive tenants reject all requests (401 on proxy, rejected on
  syslog mTLS).

### 2.3 Admin surface (`:8080`) [verified]

- First-run `/setup` creates the first admin user; redirects to `/login` once any user
  exists. Min 12-char password.
- `/login`/`/logout`; bcrypt password hashing; HMAC-SHA256 signed session cookie
  (`session`, 24 h expiry, `HttpOnly`, `Secure` default on, `SameSite=Strict`).
- Login throttling: 5 failures / 15 min per username and per IP.
- Tenant CRUD, API-key regenerate/revoke, per-tenant usage (24h/7d/30d charts + quota),
  user CRUD, certificate management (when CA enabled).
- `GET /healthz` (no auth) → `200 {"status":"ok"}`.

### 2.4 Syslog mTLS (`:6514`, optional) [verified]

- RFC 5425 octet-counted framing with newline fallback; `SYSLOG_MAX_FRAME_BYTES` cap.
- mTLS: `tls.RequireAndVerifyClientCert`, client CA file; tenant resolved by cert
  SHA-256 fingerprint; revoked cert / inactive tenant / unknown fingerprint rejected
  (connection closed).
- Tenant stamped into RFC 5424 structured-data as
  `[tenant@<id> tenant-id="<id>"]`; any client-supplied `tenant@` SD-ID stripped first.
- Forwarded over plain TCP (newline-terminated) to `SYSLOG_COLLECTOR_ADDR`
  (default `127.0.0.1:5140`) via a small connection pool with backpressure.
- Per-frame RPS/burst/quotacounts applied; usage recorded as signal type `syslog`.

### 2.5 Certificate lifecycle / step-ca (optional) [verified]

- CA integration is **client-only**: proxy holds no CA keys, authenticates with
  short-lived (5 min) provisioner JWTs signed by a provided JWK provisioner key.
- Admin issue (CSR preferred, or server-side keygen with single-use 10-min download),
  renew (new key, single-use download), revoke (local `revoked_at` + step-ca revoke).
- Download bundle zip: `ca.crt`, `client.crt`, `client.key`, `60-signoz.conf`,
  `install.sh` (idempotent, validates rsyslog config, rolls back).
- Public single-use download: `GET /api/certificates/{token}/download` (no auth,
  token-scoped, 10-min expiry).
- mTLS renewal endpoint `POST /renew` on `:6543` (device presents valid cert).

---

## 3. Security invariants (must not be weakened)

**[verified]** invariants extracted from legacy code:

1. **API keys never stored in plaintext.** Only SHA-256 hashes + prefixes persisted.
   Full plaintext exists only transiently in memory for the one-time reveal.
2. **Tenant identity is server-stamped, never client-trusted.** Client-supplied
   `tenant.id`/`tenant.name`/`service.namespace` are stripped before stamping the
   authenticated tenant. (Same for syslog `tenant@` SD-ID.)
3. **Auth failures are constant-time or format-gated.** Legacy 32-hex path rejects
   malformed keys before any DB query; candidate hashes compared with
   `crypto/subtle.ConstantTimeCompare`; unknown-username login runs bcrypt against a
   dummy hash.
4. **Passwords bcrypt-hashed; min 12 chars.** Session cookie `HttpOnly` + `Secure`
   (default) + `SameSite=Strict` + HMAC-signed with 24 h expiry.
5. **Login throttled** 5/15 min per username and per IP.
6. **Rate/quota enforced server-side** before body is forwarded; byte accounting uses
   the *original client byte count*, not the re-stamped size.
7. **Generated private keys live only in memory**, delivered once via single-use
   download token; zeroed on consumption/expiry; never persisted.
8. **Admin binds `127.0.0.1:8080` by default**; exposing it is explicit and documented
   as requiring a trusted reverse proxy with TLS.
9. **mTLS requires client certs** (`RequireAndVerifyClientCert`, min TLS 1.2); revoked
   certs rejected on every new connection (no CRL/OCSP delay).
10. **Per-tenant syslog connection cap** (default 50) and global cap (default 1000)
    bound resource usage; oversized frames rejected before allocation.
11. **Request/body/header sizes bounded** (MaxBodyBytes, MaxHeaderBytes, timeouts on
    all servers).

**[decision]** The rewrite **adds** (gaps found in legacy):

- CSRF protection on all state-changing admin routes (legacy has **none**).
- Security headers middleware (e.g. `X-Content-Type-Options`, `X-Frame-Options`,
  referrer policy, frame-ancestors) — legacy has none.
- Session validation re-checks the user still exists (legacy only checks HMAC + expiry;
  deleting a user does not revoke their session).
- Logout cookie clears with full attribute parity.
- Trust of `X-Forwarded-For`/`X-Real-IP` is made explicit/config-gated (legacy trusts
  `X-Forwarded-For` unconditionally for IP-based throttling/logging).

---

## 4. Data / schema invariants (production data must survive)

**[verified]** Current SQLite schema (the "production" shape to stay compatible with):

- `users(id, username UNIQUE, password, created_at)`
- `tenants(id, name, api_key DEFAULT '', active, description, rate_limit_rps,
  burst_bytes, daily_byte_quota, created_at, updated_at)` — no UNIQUE on api_key
  (multiple tenants may hold empty placeholder).
- `api_keys(id, tenant_id→tenants ON DELETE CASCADE, key_hash UNIQUE, key_prefix,
  enabled, created_at, last_used_at, revoked_at)`
- `certificates(id, tenant_id→tenants CASCADE, serial_number, fingerprint_sha256 UNIQUE,
  subject_cn, not_before, not_after, revoked_at, created_at, last_seen_at)`
- `usage_counters(tenant_id→tenants CASCADE, signal_type, hour_bucket,
  requests, bytes, errors, PK(tenant_id, signal_type, hour_bucket))` — **source of truth
  for usage.**
- `usage_logs(...)` — **legacy/dead table** (see §6).
- Indexes on `tenants.api_key`, `api_keys.key_hash` (unique), `api_keys.tenant_id`,
  `certificates.fingerprint_sha256`, `certificates.tenant_id`, `usage_logs` time.

**[verified]** Migration history already embedded in legacy code (must remain
compatible): additive rate-limit columns, tenants-table rebuild (dropping the legacy
UNIQUE on `api_key`), plaintext-key → `api_keys` migration. The new app must open an
existing DB produced by *any* of these stages without data loss.

**[decision]** New app introduces an **ordered, versioned migration framework**
(see §10). Migration V1 recreates the exact current schema idempotently; a baseline
step adopts pre-existing legacy DBs. A V2 adds an index supporting the fixed usage
retention cleanup. No production column is dropped or renamed.

---

## 5. Operational / config contracts

**[verified]** Environment variables and secure defaults (from `internal/config`,
`.env.example`, `README`, `docker-compose.yml`):

| Variable | Default | Notes |
|:---|:---|:---|
| `SIGNOZ_ENDPOINT` | *(required)* | Upstream OTLP base URL |
| `SIGNOZ_INGESTION_KEY` | *(empty)* | Optional upstream bearer |
| `PROXY_PORT` | `4318` | |
| `ADMIN_PORT` | `8080` | backward-compat alias |
| `ADMIN_LISTEN_ADDR` | `127.0.0.1:8080` | priority over `ADMIN_PORT` |
| `SESSION_SIGNING_KEY` | *(required)* | hex, ≥32 bytes |
| `ADMIN_COOKIE_SECURE` | `true` | |
| `MAX_BODY_BYTES` | `4194304` | |
| `DB_PATH` | `./tenants.db` | |
| `USAGE_RETENTION_DAYS` | `90` | |
| `SYSLOG_ENABLED` | `false` | |
| `SYSLOG_LISTEN_ADDR` | `:6514` | |
| `SYSLOG_SERVER_CERT_FILE` / `_KEY_FILE` / `_CLIENT_CA_FILE` | *(required when enabled)* | |
| `SYSLOG_MAX_FRAME_BYTES` | `65536` | |
| `SYSLOG_MAX_CONNECTIONS` | `1000` | |
| `SYSLOG_MAX_CONNS_PER_TENANT` | `50` | |
| `SYSLOG_CONN_IDLE_TIMEOUT` | `300s` | |
| `SYSLOG_COLLECTOR_ADDR` | `127.0.0.1:5140` | |
| `CA_ENABLED` | `false` | |
| `CA_ENDPOINT` / `CA_PROVISIONER_NAME` / `CA_PROVISIONER_KEY[_FILE]` / `CA_ROOT_CERT_FILE` / `CA_EXTERNAL_HOSTNAME` | *(required when enabled)* | |
| `CA_CERT_LIFETIME` | `2160h` | |
| `CA_RENEWAL_LISTEN_ADDR` | `:6543` | |
| `CA_SYSLOG_RELAY_PORT` | `6514` | |

**[verified]** Startup validation: config errors are fatal with specific messages;
CA root/leaf files existence-checked; syslog/CA cert files must exist. `ADMIN_LISTEN_ADDR`
priority over `ADMIN_PORT` with a documented backward-compat fallback.

**[verified]** Docker: `DB_PATH=/data/tenants.db`, volume `proxy-data:/data`, certs
read-only at `/certs`, ports 4318/8080 (localhost)/6514/6543 exposed.

**[decision]** Keep the exact env-var names and defaults (operational compatibility);
do not rename. Keep `CGO_ENABLED=0` static build and `alpine` runtime.

---

## 6. Confirmed legacy bugs / debt (explicitly NOT carried forward)

1. **[verified] `USAGE_RETENTION_DAYS` is a no-op for real usage data.**
   `CleanupOldLogs` deletes from `usage_logs`, but ingestion writes only
   `usage_counters` (via `RecordUsage`). `LogUsage`/`usage_logs` are dead code
   (only referenced by tests). Actual usage counters are never purged. **Fix:** retention
   deletes old `usage_counters` (and legacy `usage_logs` for completeness).
2. **[verified] No CSRF protection** on any admin mutation route.
3. **[verified] Sessions not revoked on user deletion** — `requireAuth` validates only
   HMAC + expiry, never that the user still exists.
4. **[verified] Trusted forwarded headers** — `X-Forwarded-For` is trusted
   unconditionally for login throttling and proxy 401 logging (spoofable behind a
   non-terminating proxy).
5. **[verified] HTMX everywhere** in admin — forbidden in the rewrite (see §8).
6. **[verified] Vendored 205 KB Chart.js UMD + 51 KB HTMX** pulled into every page;
   Chart.js sourced from a CDN minifier (jsDelivr) then vendored. Replaced with a small
   vanilla chart module (no runtime dependency).
7. **[verified] `lookup_failed` rate-limit decision is returned as HTTP 429** to the
   client (mislabeled as "rate limit exceeded" when it is an internal store error).
8. **[inference] Cleanup ticker and limiter eviction goroutines have no stop signal**
   (run until process exit); shutdown does not wait for them. `lim.Stop()` closes a
   channel but does not join.
9. **[verified] `contentLength`/spoofing handled but chunked body accounting re-reads
   whole body into memory** — acceptable for the 4 MiB cap, but noted as hot-path debt.
10. **[verified] Logout cookie omits `Secure`/`SameSite`** on the clearing cookie.
11. **[verified] Docs contain typos** (`SIGNNOZ_ENDPOINT` in getting-started.md) and a
    stale `docs/phase8-design.md` palette that diverges from the shipped `app.css`.

---

## 7. Deliberate behavior changes

| # | Change | Rationale |
|:---|:---|:---|
| 1 | Replace HTMX with PRG + small vanilla ES modules | Forbidden tech; simpler, more robust |
| 2 | Replace Chart.js with ~small vanilla SVG/canvas charts | No CDN/vendored 205 KB lib |
| 3 | Fix usage retention to purge `usage_counters` | Bug fix (data-integrity hygiene) |
| 4 | Add CSRF + security headers | Security gap |
| 5 | Validate session user still exists | Security gap |
| 6 | Return 500 (not 429) on store lookup failure in ingestion | Correctness |
| 7 | Explicit/gated forwarded-header trust | Security/operational clarity |
| 8 | Ordered versioned migrations replacing ad-hoc `migrate()` | Maintainability + safety |
| 9 | Full graceful shutdown joining all goroutines | Lifecycle correctness |
| 10 | Accessible chart fallback (HTML table/list) | A11y requirement |
| 11 | Light **and** dark mode (legacy shipped both; keep, formalize) | Parity (legacy already had both) |

No externally meaningful protocol, key format, credential semantics, rate-limit
semantics, syslog framing, or CA behavior changes.

---

## 8. New architecture

**[decision]** One production Go binary (module `go 1.25`), pure-Go SQLite, embedded
templates/static, server-rendered HTML + small vanilla ES modules, `fetch()` only for
async usage-chart loading. No HTMX, no runtime Node, no CDN, no remote fonts, minimal
dependencies.

Dependency budget (same minimal set, no additions beyond maybe `argon2`):

- `modernc.org/sqlite` (pure-Go, keeps `CGO_ENABLED=0`)
- `go.opentelemetry.io/proto/otlp` + `google.golang.org/protobuf`
- `golang.org/x/crypto` (bcrypt)
- `golang.org/x/time/rate`
- `github.com/go-jose/go-jose/v4` (step-ca provisioner JWTs)

**[decision]** Explicit package responsibilities (fresh naming; do not treat old
package layout as a contract):

```
cmd/proxy/main.go              entrypoint + wiring + lifecycle
internal/config/               env loading + validation
internal/store/                sqlite open, ordered migrations, repos (tenants/users/usage/certs/keys)
internal/auth/                 credential gateway, session token, CSRF, login limiter
internal/ingest/               OTLP proxy handler + tenant stamping
internal/ratelimit/            per-tenant limiter + quota cache
internal/syslog/               mTLS server, framing, stamping, collector pool
internal/pki/                  step-ca client, provisioner, bundle, download tokens, renewal server
internal/web/                  admin HTTP server, handlers, middleware, templates/, static/
```

This is a **new** design; it happens to map to product domains because those domains
are real, not because the old packages are preserved.

---

## 9. Proposed Go package tree (detail)

```
cmd/proxy/main.go
internal/config/config.go, config_test.go
internal/store/
    store.go            (*Store, Open/Close/Ping, pragma setup)
    migrate.go          (ordered migration runner + baseline)
    migrations/0001_init.sql
    migrations/0002_usage_retention_index.sql
    tenants.go users.go usage.go certs.go apikeys.go
internal/auth/
    gateway.go session.go csrf.go loginlimiter.go
internal/ingest/
    handler.go stamp.go
internal/ratelimit/
    limiter.go
internal/syslog/
    server.go conn.go frame.go pool.go stamp.go
internal/pki/
    client.go provisioner.go bundle.go download.go renewal.go templates/
internal/web/
    server.go handlers.go handlers_certs.go handlers_usage.go middleware.go
    templates/*.html  static/app.css  static/app.js (ES modules)
```

Conventions (from `golang-design-patterns`): functional-options constructors; explicit
error returns; `defer Close()` after open; timeouts on external calls; `crypto/rand`
for tokens; compile-time interface checks; no `init()` for wiring.

---

## 10. Persistence / migration design

**[decision]**

- Ordered migrations in `internal/store/migrations/NNNN_name.sql`, embedded via
  `//go:embed`, applied inside a transaction, tracked in `schema_migrations(version,
  applied_at)`.
- `0001_init.sql` recreates the exact current legacy schema idempotently
  (`CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF NOT EXISTS`) so it is safe on both a
  fresh DB and a pre-existing legacy DB.
- **Baseline adoption**: on open, if `schema_migrations` is missing but core tables
  (`users`, `tenants`) already exist, the runner records the current `0001` version
  without re-executing destructive steps — i.e. legacy DBs are adopted in place with
  zero data movement.
- `0002_usage_retention_index.sql` adds `idx_usage_counters_hour` on
  `usage_counters(hour_bucket)` to support the fixed retention cleanup.
- Migration failure is fatal and observable (no silent partial schema).
- `PRAGMA journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`; `SetMaxOpenConns(1)`
  preserved (single-writer SQLite, avoids SQLITE_BUSY and simplifies the usage writer).
- Usage aggregation stays an in-memory, bounded-channel, single-writer model that
  flushes to `usage_counters` every 10 s and on shutdown (see §12).

---

## 11. Auth / session / CSRF design

**[decision]**

- **Credentials** (unchanged semantics): API key (`ing_*` and legacy 32-hex) and cert
  fingerprint resolve through one gateway; `(nil, nil)` on unknown/revoked/inactive.
- **API keys** (unchanged): `ing_<id>_<48hex>`, SHA-256 hashed, prefix display,
  one-time reveal, regenerate revokes prior active keys, legacy 32-hex accepted.
- **Admin session**: HMAC-SHA256 signed cookie (`session`), 24 h expiry, `HttpOnly`,
  `Secure` (default), `SameSite=Strict`. Login re-validates the user exists;
  logout clears cookie with identical flags.
- **CSRF** (new): synchronizer token bound to the session (HMAC of session secret +
  per-session random), delivered as a hidden form field and a `SameSite=Strict` cookie;
  verified on every `POST`/`PUT`/`DELETE` admin route. Rejected → 403.
- **Login throttling** (unchanged): 5 failures / 15 min per username and per IP,
  constant-time for unknown users (bcrypt dummy hash).
- **Authorization**: all admin routes require a valid session (single-role admin, as
  legacy). Public: `/healthz`, `/login`, `/setup`, `/api/certificates/{token}/download`.

---

## 12. Ingestion / hot-path design

**[decision]** Preserve the exact hot-path contract, restructured for clarity:

1. Route match (`/v1/{traces,metrics,logs}`) → 404 otherwise.
2. `MaxBytesReader` bound.
3. Resolve tenant via `X-Tenant-Key`; missing/unknown → 401 (with masked key logging).
4. RPS pre-check (reject before reading body).
5. Read full body (bounded); byte-aware check (burst bytes + daily quota).
6. Decode (gzip if present), unmarshal OTLP (proto or proto-JSON), stamp tenant
   attributes (strip `tenant.id`/`tenant.name`/`service.namespace`, inject authenticated
   values), re-encode (proto or JSON), re-compress if gzip.
7. Forward via reverse proxy; capture real upstream status; account **original** byte
   count against the tenant; record usage (non-blocking).
8. Upstream errors → 502; malformed body → 400.

Hot-path notes: single shared reverse proxy with tuned transport (connection reuse,
timeouts); avoid global locks (limiter uses per-tenant buckets under a short mutex);
usage accounting is lock-light and non-blocking (bounded channel, drop+count on full).

---

## 13. Rate / quota / usage design

**[decision]** Preserve semantics; fix the store-failure classification:

- Per-tenant optional `rate_limit_rps`, `burst_bytes`, `daily_byte_quota` (nil = unlimited).
- Token-bucket RPS + burst-bytes (defaults when unset: unlimited), daily byte quota
  read from `usage_counters` (current UTC day), cached 60 s, fail-open on DB error with
  a failure counter (exposed in healthz) but **fail-closed returns 500, not 429**.
- Buckets lazily created, evicted after 1 h idle; quota cache refreshed every 60 s.
- Usage data (`GetUsageData`) aggregated from `usage_counters` for 24h/7d (hourly
  buckets) and 30d (daily buckets): requests bar, volume line, signal-type breakdown.
- **Retention** (fixed): background + startup cleanup deletes `usage_counters` older
  than `USAGE_RETENTION_DAYS`, and legacy `usage_logs` too.

---

## 14. Optional syslog design

**[decision]** Preserve protocol and security semantics; refactor only:

- RFC 5425 octet-counted framing + newline fallback; `MaxFrameBytes` enforced before
  allocation.
- mTLS (require + verify client cert, min TLS 1.2), tenant by cert fingerprint.
- Strip client `tenant@` SD-ID; inject `[tenant@<id> tenant-id="<id>"]`.
- Per-frame rate/quota checks; usage recorded as `syslog`.
- Bounded collector connection pool (plain TCP) with backpressure (refuse new conns
  when collector unhealthy), graceful FIN close, single retry.
- Global + per-tenant connection caps; idle timeout via read deadlines.
- Owned goroutine per connection with context cancellation and WaitGroup join on
  shutdown.

---

## 15. Optional CA / certificate design

**[decision]** Preserve as optional, client-only:

- step-ca REST client (sign/renew/revoke) authenticated by 5-min provisioner JWTs
  (go-jose). Root CA pinned for the HTTPS client.
- Provisioner JWK via inline env or file (file preferred; chmod 600, read-only mount).
- Issue (CSR or keygen), renew (new key), revoke (local + step-ca).
- Single-use 10-min download tokens, keys in memory only, zeroed on consume/expiry.
- Bundle zip (ca.crt, client.crt, client.key, 60-signoz.conf, install.sh).
- mTLS renewal server `POST /renew` on `:6543`.
- All CA endpoints/behavior gated by `CA_ENABLED`; disabled → UI shows a notice, actions
  hidden, operations return 503.

---

## 16. Lifecycle / shutdown design

**[decision]** Structured concurrency; every goroutine owned and joinable.

- Single root `context` + `errgroup` (or explicit `WaitGroup`) owning: proxy HTTP
  server, admin HTTP server, syslog listener, renewal listener, usage writer, limiter
  eviction/refresh ticker, retention ticker, download-token cleanup.
- On SIGINT/SIGTERM: cancel context → stop accepting connections (close listeners) →
  `Shutdown(ctx)` HTTP servers with a bounded timeout (10 s) → flush usage writer →
  close DB.
- All long-lived loops select on `ctx.Done()`; no fire-and-forget goroutines.
- Fail-fast startup: config/store/TLS/CA errors are fatal before any listener binds.

---

## 17. Test architecture

**[decision]** Behavioral, not implementation-coupled:

- **Unit tests** (fast, table-driven, named subtests): config validation; OTLP
  stamping (proto/json/gzip/tenant-strip/no-resource/malformed); API-key generation/
  hashing/legacy-32-hex/revoke/no-plaintext; rate limiter (RPS/burst/quota/eviction/
  fail-open); syslog framing + stamping (octet-counted, newline, oversized, tenant
  strip, multiple SD-IDs); session/CSRF tokens; login limiter window.
- **Store integration tests** (build-tag `//go:build integration` or in-memory SQLite):
  migrations fresh + legacy-baseline, CRUD, cascades, usage flush, retention cleanup,
  cert lifecycle, expiring-certs queries.
- **HTTP tests** (`httptest`): full admin flows via PRG (no HTMX assertions), CSRF
  enforcement, auth redirects, login throttle, key one-time reveal, cert download
  single-use, healthz.
- **Concurrency**: `go.uber.org/goleak` in `TestMain`; `-race` in CI.
- **Benchmarks**: stamp protobuf + JSON (ported from legacy).
- Replace HTMX-coupled tests with equivalent behavioral assertions (no
  `/static/htmx.min.js`, no `hx-*`, no swap-container IDs).

---

## 18. Rollout / migration strategy

1. Ship the new binary as a drop-in replacement: same env vars, same ports, same
   `DB_PATH`, same `docker-compose` shape.
2. On first start against an existing `tenants.db`, the migration runner **baselines**
   the legacy schema (no data movement) and applies only additive migrations.
3. Keep the legacy 32-hex API-key acceptance and `usage_logs` table (as a legacy
   table) so nothing existing breaks during the transition.
4. Provide a documented "brownfield upgrade" check: start new binary against a copy of
   the production DB in a staging container; verify tenant/key/cert/usage reads before
   cutover.
5. No dual-run, no data export/import step required.

---

## 19. Legacy components NOT copied

- `htmx.min.js` and all `hx-*` attributes/targets/swaps/fragment endpoints.
- `chart.umd.min.js` (vendored CDN build).
- HTMX-specific handlers/tests (`CancelForm`, empty-body `Delete`, `QuotaFragment`
  fragment, swap-container DOM IDs).
- Ad-hoc `migrate()`/`ensureTenantSchema()`/`migratePlaintextKeys()` functions
  (replaced by ordered migrations with baseline).
- Tailwind-utility leftovers and the `phase8-design.md` palette (superseded by the
  formalized token system in `design-system.md`).
- `usage_logs` write path (`LogUsage`) — dead code.
- Old template `define` names, DOM IDs, and CSS class names.

---

## 20. Risks & mitigations

| Risk | Mitigation |
|:---|:---|
| Breaking an existing production DB on upgrade | Baseline migration + integration test that seeds a legacy-schema DB and opens it with the new store |
| Losing client keys during transition | Preserve `api_keys` + legacy 32-hex lookup; no schema column dropped |
| Frontend regressions | HIG/accessibility spec + behavioral HTTP tests; no-HTMX CI gate |
| Chart accessibility regression | Accessible HTML table/list fallback alongside charts |
| Goroutine leaks / unclean shutdown | goleak + structured concurrency + `-race` |
| Rate-limit regression | Ported behavioral tests + fail-closed classification fix |
| CA/syslog drift | Optional subsystems preserved by ported behavioral tests (framing, stamping, cert fingerprint auth) |
| Hot-path perf | Keep single shared transport, avoid global locks, benchmark stamping |
| Scope loss | Final reconciliation against every §2–§6 invariant (rewrite-orchestrator quality gate) |

---

## 21. Deliberate behavior changes (summary)

See §7. The only intentionally *changed* observable behaviors are the bug fixes and
the HTMX→PRG/vanilla frontend replacement. All protocols, credentials, rate limits,
syslog framing, and CA semantics are preserved.
