# Testing Syslog Locally (mTLS with self-signed certs)

This guide lets you test the syslog pipeline end-to-end on a single machine,
no step-ca required. You'll generate a self-signed CA, server cert, and
client cert using openssl, then import a client cert into the admin UI.

**Estimated time:** 10 minutes.

---

## 1. Generate certificates

Run the script from the project root:

```bash
bash scripts/gen-test-certs.sh
```

It creates `certs/` with:

- `ca.crt` and `client-ca.crt` for the syslog mTLS trust store
- `server.crt` and `server.key` for the proxy listener
- `client.crt` and `client.key` for the test client

It also prints the SHA-256 fingerprint you need for manual enrollment in the
admin UI.

## 2. Run the proxy with syslog enabled

```bash
SYSLOG_ENABLED=true \
SYSLOG_LISTEN_ADDR=127.0.0.1:6514 \
SYSLOG_SERVER_CERT_FILE=./certs/server.crt \
SYSLOG_SERVER_KEY_FILE=./certs/server.key \
SYSLOG_CLIENT_CA_FILE=./certs/client-ca.crt \
SYSLOG_COLLECTOR_ADDR=127.0.0.1:5140 \
go run ./cmd/proxy

# Or add these to your .env and run:
# go run ./cmd/proxy
```

You'll need an OTel Collector with a syslog receiver on `127.0.0.1:5140`, or
you can skip the collector for now (the proxy will log forward errors but
won't crash).

## 3. Register the client cert in the admin UI

1. Open `http://localhost:8080` → login
2. Create a tenant (e.g. `syslog-test`)
3. Go to the tenant's **Certs** tab
4. Click **Issue Certificate** → **Manual enrollment**
5. Paste the **fingerprint** (from step 1) and the **client serial number**
   (you can use `1`)
6. Leave `NotBefore` / `NotAfter` as defaults
7. Click **Enroll**

Now the client cert is registered and the proxy will accept syslog messages
from a client presenting this cert.

## 4. Send a test syslog message

```bash
# Using openssl s_client as a syslog client
MSG="<134>1 2026-08-03T12:00:00Z localhost test-app 1234 - - test syslog message"
LEN=${#MSG}
printf "%d %s" "$LEN" "$MSG" | \
openssl s_client -connect 127.0.0.1:6514 \
  -cert certs/client.crt -key certs/client.key \
  -CAfile certs/client-ca.crt -quiet 2>/dev/null
```

Expected: the connection is accepted, and the message appears in the OTel
Collector logs (or the proxy logs a forward error if no collector is
running).

## 5. Verify usage accounting

Back in the admin UI, go to the tenant's **Usage** tab. You should see the
syslog signal type in the breakdown (doughnut chart).

## Troubleshooting

| Symptom | Fix |
|:---|:---|
| `tls: failed to verify client certificate` | CA file doesn't match. Re-run the cert script. |
| Connection reset immediately | Client cert fingerprint not registered. Check admin UI. |
| Port 6514 already in use | Change `SYSLOG_LISTEN_ADDR` to another port. |
| `record overflow 1` during write | Message format: must be `N bytes MSG` (octet-counted). |
