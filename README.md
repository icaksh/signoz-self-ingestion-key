# OTLP Proxy

A lightweight Go proxy for SigNoz OTLP ingestion with custom tenant-based authentication, an admin dashboard, and usage analytics.

## Architecture

```
Clients → Proxy (:4318) → SigNoz (:4318/v1/*)
              ↓
         SQLite (usage logs + tenants)
              ↑
Admin (:8080) — HTMX + Tailwind + Chart.js
```

## Quick Start

> **Step-by-step guide:** [`docs/getting-started.md`](docs/getting-started.md) —
> covers minimal setup, creating a tenant, sending test telemetry, and
> checking the usage dashboard.

```bash
# 1. Generate a signing key
openssl rand -hex 32

# 2. Run (minimal — no syslog, no CA)
SESSION_SIGNING_KEY=<hex-key> \
SIGNOZ_ENDPOINT=http://localhost:4318 \
go run ./cmd/proxy
# → Admin: http://localhost:8080  |  Proxy: http://localhost:4318
```

```bash
# docker
docker compose up -d
```

## Environment

| Variable | Default | Description |
|:---|:---|:---|
| `SIGNOZ_ENDPOINT` | `http://localhost:4318` | SigNoz OTLP endpoint |
| `SIGNOZ_INGESTION_KEY` | *(empty)* | SigNoz ingestion key (optional) |
| `PROXY_PORT` | `4318` | OTLP proxy listen port |
| `ADMIN_PORT` | `8080` | Admin dashboard port (backward compat) |
| `ADMIN_LISTEN_ADDR` | `127.0.0.1:8080` | Admin listen address — localhost only by default |
| `SESSION_SIGNING_KEY` | *(required)* | Hex key (>= 32 bytes) for session cookies — `openssl rand -hex 32` |
| `ADMIN_COOKIE_SECURE` | `true` | Set `Secure` on session cookies |
| `MAX_BODY_BYTES` | `4194304` | Max request body size (4 MiB) |
| `DB_PATH` | `./tenants.db` | SQLite database path |
| `USAGE_RETENTION_DAYS` | `90` | Days to retain usage logs |

## Auth Flow

1. First visit to admin → `/setup` creates the initial admin user
2. Login with username/password → HMAC-signed session cookie
3. Create tenants in admin → each gets a v2 API key (`ing_<id>_<48 hex>`)
4. API keys are stored **hashed** (SHA-256) — never in plaintext
5. The full key is shown **once** inline in the response body after creation/regeneration, then only the prefix is displayed

## Sending Telemetry

```bash
curl -X POST http://localhost:4318/v1/traces \
  -H "X-Tenant-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"resourceSpans":[]}'
```

Endpoints: `/v1/traces`, `/v1/metrics`, `/v1/logs` (exact match — near paths return 404)

Tenant identity is stamped server-side: on every forwarded OTLP request the
proxy removes any client-claimed `tenant.id` / `tenant.name` /
`service.namespace` resource attributes and injects the authenticated
`tenant.id` + `tenant.name`. JSON and gzip `Content-Encoding` bodies are
supported.

Health: `GET /healthz` on both the proxy and admin returns `{"status":"ok"}`.

## Syslog-over-TLS (mTLS)

Optional RFC 5425 syslog ingestion with mutual TLS. Clients (rsyslog,
syslog-ng) connect with a client certificate signed by your private CA; the
proxy authenticates each connection by cert SHA-256 fingerprint and stamps
the authenticated tenant into the RFC 5424 structured-data:

```
[tenant@<id> tenant-id="<id>"]
```

Any client-supplied `tenant@` SD-ID is stripped before the fresh one is
injected. Framed messages are forwarded over plain TCP to a local OTel
Collector syslog receiver.

Enable with `SYSLOG_ENABLED=true` and set `SYSLOG_SERVER_CERT_FILE`,
`SYSLOG_SERVER_KEY_FILE`, `SYSLOG_CLIENT_CA_FILE`. The OTel Collector syslog
receiver must bind to `127.0.0.1` only:

```yaml
receivers:
  syslog:
    tcp:
      listen_address: "127.0.0.1:5140"
    protocol: rfc5424
```

> The OTel Collector syslog receiver must bind to 127.0.0.1 only. It must
> never be exposed to the internet.

| Variable | Default | Description |
|:---|:---|:---|
| `SYSLOG_ENABLED` | `false` | Enable the syslog listener (requires certs) |
| `SYSLOG_LISTEN_ADDR` | `:6514` | Syslog mTLS listen address |
| `SYSLOG_SERVER_CERT_FILE` | — | Server TLS cert (publicly trusted) |
| `SYSLOG_SERVER_KEY_FILE` | — | Server TLS key |
| `SYSLOG_CLIENT_CA_FILE` | — | Private CA verifying client certs |
| `SYSLOG_MAX_FRAME_BYTES` | `65536` | Max RFC 5425 frame size |
| `SYSLOG_MAX_CONNECTIONS` | `1000` | Max concurrent connections |
| `SYSLOG_CONN_IDLE_TIMEOUT` | `300s` | Idle connection timeout |
| `SYSLOG_COLLECTOR_ADDR` | `127.0.0.1:5140` | OTel Collector syslog receiver |

## Admin Dashboard

- Tenant CRUD with key management (show prefix, revoke/regenerate)
- User management (add/remove admin accounts, min 12-char passwords)
- Usage dashboard per tenant: request counts (bar), data volume (line), signal type breakdown (doughnut) — 24h / 7d / 30d selectors
- Login is rate-limited (5 failures / 15 min per username and IP)

> The admin dashboard binds to `127.0.0.1:8080` by default. To expose it, set
> `ADMIN_LISTEN_ADDR=:8080` (or `:0.0.0.0:8080`) explicitly — recommended only
> behind a trusted reverse proxy with TLS.

## Build

```bash
make build    # CGO_ENABLED=0 → static binary in bin/proxy
make test     # go test ./...
```

## Docker

```bash
docker build -t otlp-proxy .
docker run -e SIGNOZ_ENDPOINT=http://localhost:4318 -p 4318:4318 -p 8080:8080 otlp-proxy
```

Image ~10 MB. Multi-stage build: `golang:1.25-alpine` → `alpine:3.21`.

## Certificate Lifecycle (step-ca)

> Full enablement guide: **[CA_ENABLEMENT.md](CA_ENABLEMENT.md)** — provisioner
> setup, config, verification, device installation, and troubleshooting.

Optional integration with [step-ca](https://smallstep.com/docs/step-ca/) for
automated client-certificate issuance, renewal, and revocation. The proxy is
**only an API client** — it holds no CA keys and never stores private keys.
It authenticates with short-lived provisioner JWTs.

Enable with `CA_ENABLED=true` and set `CA_ENDPOINT`, `CA_PROVISIONER_NAME`,
and either `CA_PROVISIONER_KEY` (inline JWK JSON) or
`CA_PROVISIONER_KEY_FILE` (path). `CA_ROOT_CERT_FILE` and
`CA_EXTERNAL_HOSTNAME` are required.

- **Admin UI** (`/tenants/{id}/certificates`): issue via CSR upload (preferred)
  or server-side keypair generation (single-use download link, 10-min expiry,
  key held only in memory), plus renew and revoke actions.
- **Revocation is immediate**: revoking sets `revoked_at` locally, so the
  Phase 5 mTLS listener rejects new connections from that cert right away.
- **mTLS renewal endpoint** (`:6543/renew`): a device holding a valid client
  cert can renew it with a new key via `POST /renew` over mTLS.
- **Client bundle**: the download is a zip with `ca.crt`, `client.crt`,
  `client.key`, `60-signoz.conf` (rsyslog), and an idempotent `install.sh`
  that validates the rsyslog config and rolls back on failure.

| Variable | Default | Description |
|:---|:---|:---|
| `CA_ENABLED` | `false` | Enable step-ca integration | 
| `CA_ENDPOINT` | — | step-ca base URL, e.g. `https://step-ca:9000` |
| `CA_PROVISIONER_NAME` | — | Provisioner name for JWT auth |
| `CA_PROVISIONER_KEY` | — | Inline provisioner JWK JSON |
| `CA_PROVISIONER_KEY_FILE` | — | Path to JWK file (alternative) |
| `CA_ROOT_CERT_FILE` | — | Root CA PEM (for client bundles) |
| `CA_CERT_LIFETIME` | `2160h` | Issued certificate lifetime (90d) |
| `CA_RENEWAL_LISTEN_ADDR` | `:6543` | mTLS renewal endpoint |
| `CA_EXTERNAL_HOSTNAME` | — | Public hostname for install.sh/rsyslog |
| `CA_SYSLOG_RELAY_PORT` | `6514` | Syslog relay port in rsyslog conf |
