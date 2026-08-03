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

```bash
# required: session signing key (openssl rand -hex 32)
SESSION_SIGNING_KEY=<hex> \
SIGNOZ_ENDPOINT=http://localhost:4318 \
ADMIN_LISTEN_ADDR=127.0.0.1:8080 \
go run ./cmd/proxy
# → Admin: http://localhost:8080  |  Proxy: http://localhost:4318
```
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
