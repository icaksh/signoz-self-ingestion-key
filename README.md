# OTLP Proxy

A tenant-authenticating **OTLP proxy** in front of a SigNoz (or any OTLP)
receiver, plus a self-hosted admin dashboard for managing tenants, API keys,
usage quotas, and (optionally) mTLS client certificates.

A single static Go binary. No runtime Node, no CDN, no remote fonts.

## All-in-one installation (recommended)

The repository includes a terminal UI that installs the application, a bundled private step-ca, and an internal OpenTelemetry syslog conversion collector automatically. Certificate lifecycle support is enabled during the same flow.

```bash
chmod +x install.sh scripts/install-tui.sh
./install.sh
```

Use **Quick install / reconfigure everything**. The wizard generates secrets, initializes step-ca, exports its trust root and JWK provisioner credential, issues the proxy listener certificate, builds the Go service, and starts the full Docker Compose stack.

See `docs/AIO_INSTALL.md` for ports, trust distribution, backups, and security notes.


## Features

- **OTLP ingestion** (`:4318`) — `POST /v1/{traces,metrics,logs}` with
  `X-Tenant-Key` authentication, per-tenant rate limits (RPS / burst bytes /
  daily byte quota), and server-side tenant stamping (`tenant.id`,
  `tenant.name`) onto every resource.
- **Admin dashboard** (`127.0.0.1:8080`) — tenant/user CRUD, API-key
  management (one-time reveal, hashed at rest), usage charts (24h/7d/30d), and
  certificate management when CA is enabled.
- **Syslog over mTLS** (`:6514`, optional) — RFC 5425 framing, client-cert
  fingerprint authentication, per-tenant stamping.
- **step-ca certificate lifecycle** (optional) — client-only CA integration,
  bundle downloads, and an mTLS renewal endpoint (`:6543`).

## Quick start

```bash
# Required configuration
export SIGNOZ_ENDPOINT=http://localhost:4318
export SESSION_SIGNING_KEY=$(openssl rand -hex 32)

go run ./cmd/proxy
```

Open `http://127.0.0.1:8080` and complete the one-time setup to create the
first admin user. Then create a tenant, copy the one-time API key, and point
your OTLP clients at `:4318`.

## Configuration

All configuration is via environment variables. See `.env.example` for the
complete list and defaults. The most important:

| Variable | Default | Notes |
|:---|:---|:---|
| `SIGNOZ_ENDPOINT` | *(required)* | Upstream OTLP base URL |
| `SIGNOZ_INGESTION_KEY` | *(empty)* | Optional upstream bearer token |
| `PROXY_PORT` | `4318` | |
| `ADMIN_LISTEN_ADDR` | `127.0.0.1:8080` | Overrides `ADMIN_PORT` |
| `SESSION_SIGNING_KEY` | *(required)* | hex, ≥32 bytes |
| `DB_PATH` | `./tenants.db` | SQLite database |
| `USAGE_RETENTION_DAYS` | `90` | Usage counter retention |
| `MAX_BODY_BYTES` | `4194304` | Ingest body limit |

Optional subsystems are documented in:

- [`docs/getting-started.md`](docs/getting-started.md)
- [`docs/syslog-local-setup.md`](docs/syslog-local-setup.md)
- [`docs/CA_ENABLEMENT.md`](docs/CA_ENABLEMENT.md)

## Security model

- API keys are stored **SHA-256 hashed** only; the full key is shown once.
- Tenant identity is **server-stamped**; client-claimed `tenant.id`,
  `tenant.name`, and `service.namespace` are always stripped.
- Passwords are bcrypt-hashed; sessions are HMAC-signed cookies (`HttpOnly`,
  `Secure` default, `SameSite=Strict`, 24 h).
- All state-changing admin routes are **CSRF-protected**; security headers are
  applied to every response.
- Admin binds to loopback by default; expose it only behind a trusted reverse
  proxy with TLS.

## Building

```bash
make build          # CGO_ENABLED=0 static binary at bin/proxy
make test           # go test ./...
make test-race      # go test -race ./...
bash scripts/verify-rewrite.sh   # full build/test/vet + no-HTMX gate
```

## Docker

```bash
docker compose up --build
```

The proxy listens on `4318` (ingest) and `8080` (admin, localhost-only), with
the SQLite database in the `proxy-data` volume and certificates read-only from
`./certs`.

## Brownfield upgrade

The migration runner adopts an existing `tenants.db` in place: it baselines the
legacy schema (no data movement) and applies only additive migrations. Existing
tenants, users, API keys (including legacy 32-hex keys), certificates, and
usage counters are preserved. Validate by starting the new binary against a
copy of the production database in a staging container before cutover.


Syslog AIO path: `rsyslog client --mTLS/octet-counted--> proxy:6514 --RFC5424/TCP--> syslog-collector:5140 --OTLP/HTTP--> SigNoz`.
