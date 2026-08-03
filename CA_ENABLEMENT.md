# Enabling the step-ca Certificate Lifecycle

The proxy can manage **client certificates for the syslog mTLS relay**
through a [step-ca](https://smallstep.com/docs/step-ca/) instance: issue
(admin or CSR-based), renew, and revoke. Revoking a certificate takes effect
**immediately** — the mTLS listener rejects new connections from that cert.

The proxy never holds CA keys. It authenticates to step-ca with short-lived
JWTs signed by a **JWK provisioner private key** that you provide.

## What this enables

| Capability | Where | Notes |
|:---|:---|:---|
| Issue certs per tenant | Admin UI, `POST /tenants/{id}/certificates` | CSR upload (preferred) |
| Keygen fallback | Admin UI, `/certificates/keygen` | Key held in memory, one-time download |
| Renewal (admin) | Admin UI, `/certificates/{id}/renew` | New keypair, one-time download |
| Renewal (device) | `POST /renew` on `:6543` (mTLS) | Device must hold a valid cert |
| Revocation | Admin UI, `/certificates/{id}/revoke` | Local `revoked_at` + step-ca |
| Client bundle | `GET /api/certificates/{token}/download` | Zip + `install.sh`, 10-min token |

## Prerequisites

- A running **step-ca** with an HTTPS endpoint (e.g. `https://step-ca:9000`).
- The **root CA certificate** (PEM) of that step-ca.
- A **JWK provisioner private key** (JSON Web Key with the `d` field).
- `step` CLI (optional but recommended) and `openssl`.

## Step 1 — Get a JWK provisioner

### Option A (recommended): generate the key pair yourself

```bash
# Create the JWK key pair (public + private)
step crypto jwk create --pub jwk.pub --priv jwk.priv

# Register the provisioner with step-ca using your keys
step ca provisioner add otlp-proxy \
    --type JWK \
    --public-key jwk.pub \
    --private-key jwk.priv

# Restart step-ca so it picks up the provisioner
# (systemd/container restart — see your step-ca deployment)
```

Keep `jwk.priv`; the proxy uses it to sign JWTs. `jwk.pub` stays in step-ca.

### Option B: export an existing JWK provisioner

The `admin` provisioner created by `step ca init` works too. Its private key
is encrypted in step-ca's config; decrypt it with the provisioner password:

```bash
step ca provisioner list \
  | jq -r '.[] | select(.name == "admin") | .encryptedKey' \
  | step crypto jwe decrypt > provisioner.jwk
# prompted for the provisioner password; provisioner.jwk is the private JWK
```

Either way the result is a JSON Web Key file containing `"d"` — that file
(or its inline contents) is what the proxy reads.

## Step 2 — Configure the proxy

All CA settings are environment variables. When `CA_ENABLED=true` the config
loader validates every required value and the server refuses to start with a
missing one.

| Variable | Required | Default | Description |
|:---|:---|:---|:---|
| `CA_ENABLED` | yes | `false` | Set to `true` to enable |
| `CA_ENDPOINT` | yes | — | step-ca URL, e.g. `https://step-ca:9000` |
| `CA_PROVISIONER_NAME` | yes | — | Provisioner name (matches Step 1) |
| `CA_PROVISIONER_KEY` | one of | — | Inline JWK JSON string |
| `CA_PROVISIONER_KEY_FILE` | one of | — | Path to the JWK file |
| `CA_ROOT_CERT_FILE` | yes | — | step-ca root CA PEM (for bundles) |
| `CA_CERT_LIFETIME` | no | `2160h` | Issued cert lifetime (90 days) |
| `CA_RENEWAL_LISTEN_ADDR` | no | `:6543` | Device mTLS renewal endpoint |
| `CA_EXTERNAL_HOSTNAME` | yes | — | Public relay hostname (used in bundle) |
| `CA_SYSLOG_RELAY_PORT` | no | `6514` | Relay port baked into rsyslog conf |

### Bare binary / systemd

```bash
export CA_ENABLED=true
export CA_ENDPOINT=https://step-ca:9000
export CA_PROVISIONER_NAME=otlp-proxy
export CA_PROVISIONER_KEY_FILE=/etc/otlp-proxy/provisioner.jwk
export CA_ROOT_CERT_FILE=/etc/otlp-proxy/root_ca.crt
export CA_EXTERNAL_HOSTNAME=relay.example.com
# optional: CA_CERT_LIFETIME=2160h, CA_RENEWAL_LISTEN_ADDR=:6543
./otlp-proxy
```

### Docker Compose

The compose file already exposes `:6543` and passes the `CA_*` variables.
Put `provisioner.jwk` and `root_ca.crt` in `./certs/` next to `docker-compose.yml`
(already mounted read-only), then set in your `.env`:

```bash
CA_ENABLED=true
CA_EXTERNAL_HOSTNAME=relay.example.com
```

`CA_PROVISIONER_KEY_FILE` and `CA_ROOT_CERT_FILE` default to
`/certs/provisioner.jwk` and `/certs/root_ca.crt` inside the container, so
name your files accordingly (or override the paths via compose env).

### Inline key instead of file

If you prefer secrets in env (e.g. a secret manager), paste the JWK JSON:

```bash
export CA_PROVISIONER_KEY='{"use":"sig","kty":"EC","kid":"...","crv":"P-256","alg":"ES256","x":"...","y":"...","d":"..."}'
```

## Step 3 — Start and verify

```bash
# Startup must log the renewal listener:
./otlp-proxy   # -> [ca] renewal listener on :6543 (mTLS)

# Both health endpoints stay green:
curl -s http://127.0.0.1:8080/healthz   # {"status":"ok"}
curl -s http://localhost:4318/healthz    # {"status":"ok"}
```

If a required variable is missing the process exits with a message like
`config: CA_ENABLED=true requires CA_ENDPOINT` — see Troubleshooting.

## Step 4 — Issue a certificate

Open the admin dashboard, select a tenant, open **Certificates**, click
**Issue Certificate**. Two paths:

- **CSR-based (preferred)** — paste a CSR generated on the device:

  ```bash
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
      -nodes -keyout client.key -out client.csr -subj "/CN=my-device"
  ```

- **Generate Keypair** — the server creates the key, and a green panel
  appears with a **single-use download link** (valid 10 minutes).

## Device installation

Downloading the bundle produces `signoz-certs.zip`:

| File | Purpose |
|:---|:---|
| `ca.crt` | Relay's root CA (trust anchor) |
| `client.crt` | This device's certificate |
| `client.key` | Device private key (keygen/renew only) |
| `60-signoz.conf` | rsyslog TLS forwarder to the relay |
| `install.sh` | Idempotent installer (backup, validate, rollback) |

On the device (root shell):

```bash
unzip signoz-certs.zip -d signoz-certs && cd signoz-certs
chmod +x install.sh && ./install.sh
# Validates rsyslog config, rolls back on failure, restarts rsyslog
```

## Renewal

Two ways:

- **Admin** — Renew button on the certificate row; new keypair delivered via
  a fresh single-use download link.
- **Device (mTLS)** — a device holding a valid cert can renew with a new key:

  ```bash
  curl --cert client.crt --key client.key --cacert ca.crt \
       -X POST -H "Content-Type: application/pkcs10" \
       --data-binary @new.csr https://relay.example.com:6543/renew \
       -o new_client.crt
  ```

  The new certificate is registered for the same tenant; the old one stays
  valid until revoked.

## Revocation

Click **Revoke** on a certificate row. The proxy marks `revoked_at` locally
(so the mTLS listener rejects that cert immediately) and calls step-ca's
revoke endpoint. To also revoke on the CA side directly:

```bash
step ca revoke <serial> --cert root_ca.crt --key ...
```

## Troubleshooting

| Error / symptom | Cause | Fix |
|:---|:---|:---|
| `CA_ENABLED=true requires CA_ENDPOINT` | Missing var | Set `CA_ENDPOINT` |
| `... requires CA_PROVISIONER_NAME` | Missing var | Set `CA_PROVISIONER_NAME` |
| `... requires CA_PROVISIONER_KEY or CA_PROVISIONER_KEY_FILE` | Neither set | Provide one |
| `... requires CA_ROOT_CERT_FILE` | Missing var | Set `CA_ROOT_CERT_FILE` |
| `... requires CA_EXTERNAL_HOSTNAME` | Missing var | Set public relay hostname |
| `cannot access CA_ROOT_CERT_FILE <path>` | File missing | Place root CA at path, check perms |
| `ca: read provisioner key` | Key file unreadable | Check path + permissions |
| `ca: parse JWK` | Not valid JWK JSON | Use a real JWK (see Step 1) |
| `JWK key is not a signer (private key required)` | Public-only JWK | Key must contain `"d"` |
| `ca: parse cert lifetime` | Bad duration | e.g. `2160h`, `720h`, `30d` not allowed |
| `401` from step-ca | Name/key mismatch | Name + key must match registered ones |
| Admin UI amber banner | `CA_ENABLED=false` | Enable it; buttons hidden on purpose |
| `503 cert issuance unavailable` | CA off | Enable CA or expect the banner |
| Download shows `410 Gone` | Token used or >10 min old | Re-issue the certificate |
| `[ca] renewal: ...` | Renewal listener error | Free `:6543`; cert/CA valid |

## Security notes

- The proxy signs JWTs with the provisioner private key for **5 minutes at a
  time**; the key file itself is only read at startup.
- Issued private keys exist **only in memory** and are delivered once via a
  single-use 10-minute download link; the server never persists them.
- Revocation is checked on every mTLS connection via the cert fingerprint,
  so revoked certs stop working immediately (no CRL/OCSP delay).
- `CA_PROVISIONER_KEY_FILE` should be readable only by the proxy user
  (chmod 600) and mounted read-only in containers.
