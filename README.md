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
# local
SIGNOZ_ENDPOINT=http://your-signoz:4318 go run ./cmd/proxy
# → Admin: http://localhost:8080  |  Proxy: http://localhost:4318

# docker
docker compose up -d
```

## Environment

| Variable | Default | Description |
|:---|:---|:---|
| `SIGNOZ_ENDPOINT` | `http://localhost:4318` | SigNoz OTLP endpoint |
| `SIGNOZ_INGESTION_KEY` | *(empty)* | SigNoz ingestion key (optional) |
| `PROXY_PORT` | `4318` | OTLP proxy listen port |
| `ADMIN_PORT` | `8080` | Admin dashboard listen port |
| `DB_PATH` | `./tenants.db` | SQLite database path |
| `USAGE_RETENTION_DAYS` | `90` | Days to retain usage logs |

## Auth Flow

1. First visit to admin → `/setup` creates the initial admin user
2. Login with username/password → HMAC-signed session cookie
3. Create tenants in admin → each gets a 32-char hex API key
4. API key shown **once** in a modal after creation/regeneration

## Sending Telemetry

```bash
curl -X POST http://localhost:4318/v1/traces \
  -H "X-Tenant-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"resourceSpans":[]}'
```

Endpoints: `/v1/traces`, `/v1/metrics`, `/v1/logs`

## Admin Dashboard

- Tenant CRUD with key management (copy, revoke/regenerate)
- User management (add/remove admin accounts)
- Usage dashboard per tenant: request counts (bar), data volume (line), signal type breakdown (doughnut) — 24h / 7d / 30d selectors

## Build

```bash
make build    # CGO_ENABLED=0 → static binary in bin/proxy
make test     # 14 tests
```

## Docker

```bash
docker build -t otlp-proxy .
docker run -e SIGNOZ_ENDPOINT=http://localhost:4318 -p 4318:4318 -p 8080:8080 otlp-proxy
```

Image ~10 MB. Multi-stage build: `golang:1.25-alpine` → `alpine:3.21`.
