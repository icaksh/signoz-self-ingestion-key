# Getting Started

This guide walks through running the OTLP proxy, creating a tenant, and
sending telemetry through it.

## 1. Configure

The only required variables are `SIGNOZ_ENDPOINT` (your upstream OTLP
receiver) and `SESSION_SIGNING_KEY` (a hex secret of at least 32 bytes):

```bash
export SIGNOZ_ENDPOINT=http://localhost:4318
export SESSION_SIGNING_KEY=$(openssl rand -hex 32)
```

Optionally set `SIGNOZ_INGESTION_KEY` if your upstream requires a bearer token.

See `.env.example` for the full list of variables and defaults.

## 2. Run

```bash
go run ./cmd/proxy
```

Two listeners start:

- `:4318` — OTLP ingestion (`/v1/traces`, `/v1/metrics`, `/v1/logs`)
- `127.0.0.1:8080` — admin dashboard

## 3. Create the admin user

Open `http://127.0.0.1:8080`. On first run you are redirected to `/setup`;
create the first admin user (password must be at least 12 characters).

## 4. Create a tenant

On the Tenants page, choose **New tenant**. Set a name and, optionally,
rate limits:

- **Rate limit (rps)** — requests per second
- **Burst (bytes/s)** — burst byte rate
- **Daily quota (MB)** — daily ingested-byte quota (stored as bytes)

After creating, the full API key is shown **once** — copy it now. Only a
12-character prefix is displayed afterward.

## 5. Send telemetry

Send OTLP to the proxy with the key in the `X-Tenant-Key` header:

```bash
curl -X POST http://localhost:4318/v1/traces \
  -H "X-Tenant-Key: ing_<tenantID>_<secret>" \
  -H "Content-Type: application/json" \
  --data-binary @trace.json
```

The proxy authenticates the key, stamps `tenant.id` and `tenant.name` onto
every resource, and forwards to `SIGNOZ_ENDPOINT`.

## 6. Monitor usage

Open **Usage** for a tenant to see requests, ingested volume, signal-type
breakdown, and daily quota usage across 24h / 7d / 30d ranges.

## Health check

```bash
curl http://localhost:4318/healthz
# {"status":"ok","dropped":0,"quota_failures":0}
```

## Running with Docker

```bash
cp .env.example .env
# edit .env with SIGNOZ_ENDPOINT and SESSION_SIGNING_KEY
docker compose up --build
```

The admin dashboard is bound to localhost on the host; the SQLite database is
persisted in the `proxy-data` volume.
