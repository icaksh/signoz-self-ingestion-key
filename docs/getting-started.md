# Getting Started — Local Testing

How to run the OTLP Proxy locally, create a tenant, and send test telemetry —
no syslog, no CA, just the core proxy.

## 1. Prerequisites

- Go 1.23+ (`go version`)
- A running SigNoz instance (or any OTLP receiver) at a reachable endpoint

If you don't have SigNoz, you can point at a dummy endpoint or use
`SIGNOZ_ENDPOINT=http://localhost:4318` (the default in SigNoz deployments).

## 2. Create a minimal `.env`

Copy `.env.example` to `.env` and fill in three required values:

```bash
cp .env.example .env
```

**Required — must be set:**

| Variable | Example | How to generate |
|:---|:---|:---|
| `SESSION_SIGNING_KEY` | `d28d...0ec0` | `openssl rand -hex 32` |
| `SIGNOZ_ENDPOINT` | `http://localhost:4318` | Your SigNoz OTLP receiver |
| `SIGNOZ_INGESTION_KEY` | `cinnabar` | Optional — SigNoz ingestion key (delete if not needed) |

Minimal `.env` (everything else uses defaults):

```bash
SIGNNOZ_ENDPOINT=http://localhost:4318
SESSION_SIGNING_KEY=<paste-your-hex-key>
```

## 3. Run the proxy

```bash
# Option A — with .env (using gocloud.dev, if supported)
go run ./cmd/proxy

# Option B — inline env vars (always works)
SESSION_SIGNING_KEY=$(openssl rand -hex 32) \
SIGNNOZ_ENDPOINT=http://localhost:4318 \
go run ./cmd/proxy
```

After startup you'll see:
```
[proxy] listening on :4318
[admin] listening on 127.0.0.1:8080
```

> The proxy listens on two ports:
> - **:4318** — OTLP ingestion (clients send traces/metrics/logs here)
> - **127.0.0.1:8080** — Admin dashboard (browser)

## 4. First-time admin setup

Open **http://localhost:8080** — you'll be redirected to `/setup`.

Create the initial admin user:
- Username: `admin`
- Password: at least 12 characters (e.g. `correct-password-123`)

After setup you'll be asked to sign in with those credentials.

## 5. Create a tenant

1. In the admin dashboard, click **New Tenant**
2. Fill in:
   - **Name**: `test-app`
   - **Description**: `local testing`
   - Rate limits: leave empty (unlimited for testing)
3. Click **Create**

The API key is shown **once** in a golden banner. **Copy it now** — it won't
be shown again. The key looks like `ing_1_abc123...def456`.

## 6. Send test telemetry

With the API key from step 5, send a test OTLP trace:

```bash
curl -X POST http://localhost:4318/v1/traces \
  -H "X-Tenant-Key: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "resourceSpans": [{
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "test-service"}}
        ]
      },
      "scopeSpans": [{
        "scope": {"name": "test-scope"},
        "spans": [{
          "name": "test-span",
          "kind": 1,
          "startTimeUnixNano": "1700000000000000000",
          "endTimeUnixNano": "1700000001000000000",
          "attributes": []
        }]
      }]
    }]
  }'
```

Expected: HTTP 200 and the trace appears in SigNoz.

**Wrong key → 401:**
```json
{"error":"invalid tenant key"}
```

**Wrong endpoint → 404** (only exact paths `/v1/traces`, `/v1/metrics`, `/v1/logs`).

## 7. Check usage

In the admin dashboard, click **Usage** next to your tenant. You'll see:
- Request counts over time (bar chart)
- Data volume over time (line chart)
- Signal type breakdown (doughnut chart)

Selectors: 24h / 7d / 30d.

## 8. Health checks

Both the proxy and admin expose `/healthz`:

```bash
curl http://localhost:4318/healthz   # proxy
curl http://localhost:8080/healthz   # admin
# → {"status":"ok","quota_failures":0}
```

## 9. Advanced: enable syslog (self-signed certs)

> **Full guide:** [`docs/syslog-local-setup.md`](docs/syslog-local-setup.md) —
> openssl script to generate mTLS certs, register a client, and send a test
> syslog message.

Quick version:

```bash
# 1. Generate certs (copy-paste the script from docs/syslog-local-setup.md)
# 2. Run with syslog enabled
SYSLOG_ENABLED=true \
SYSLOG_LISTEN_ADDR=127.0.0.1:6514 \
SYSLOG_SERVER_CERT_FILE=./certs/server.crt \
SYSLOG_SERVER_KEY_FILE=./certs/server.key \
SYSLOG_CLIENT_CA_FILE=./certs/ca.crt \
go run ./cmd/proxy
# 3. Register client cert fingerprint in admin UI
# 4. Test: printf "N bytes MSG" | openssl s_client ...
```

## 10. Advanced: enable CA (step-ca in Docker)

> **Full guide:** [`docs/ca-local-setup.md`](docs/ca-local-setup.md) —
> Docker-based step-ca setup, provisioner creation, cert issuance through
> admin UI, renewal, and revocation.

Quick version:

```bash
# 1. Start step-ca in Docker (see ca-local-setup.md)
# 2. Create provisioner: step ca provisioner add otlp-proxy --type JWK --create
# 3. Export key: step ca provisioner jwk otlp-proxy > certs/provisioner.jwk
# 4. Run with CA enabled
CA_ENABLED=true \
CA_ENDPOINT=https://localhost:9000 \
CA_PROVISIONER_NAME=otlp-proxy \
CA_PROVISIONER_KEY_FILE=./certs/provisioner.jwk \
CA_ROOT_CERT_FILE=./certs/root_ca.crt \
CA_EXTERNAL_HOSTNAME=localhost \
go run ./cmd/proxy
# 5. Issue certs through admin UI
```

## Troubleshooting

| Symptom | Check |
|:---|:---|
| `SESSION_SIGNING_KEY is required` | Generate with `openssl rand -hex 32` and set in `.env` |
| Admin page not styled | `.env.example` exists but `.env` is what the proxy reads — copy it |
| `SIGNOZ_ENDPOINT is required` | Set `SIGNOZ_ENDPOINT=http://localhost:4318` or your actual endpoint |
| 502 from proxy | SigNoz is unreachable — check `SIGNOZ_ENDPOINT` |
| 404 on `/v1/traces` | Exact path required — no trailing slash, no prefix |
| Port already in use | Change `PROXY_PORT` or `ADMIN_PORT` in `.env` |
