# Testing step-ca Integration Locally

This guide sets up a local step-ca server and configures the proxy to issue,
renew, and revoke client certificates through the admin UI.

**Estimated time:** 15 minutes. Requires Docker.

If you want a single command that does the setup end-to-end, use
`scripts/setup-step-ca.sh`.

---

## 1. Start step-ca

```bash
# Create a step-ca data directory
mkdir -p /tmp/step-ca

# Start step-ca in Docker
docker run -d --name step-ca --network host \
  -v /tmp/step-ca:/home/step \
  smallstep/step-ca:latest \
  step-ca /home/step/config/ca.json \
  --password-file /home/step/secrets/password

# Wait a few seconds, then initialize
sleep 3

# Bootstrap: get the root cert
docker exec step-ca step ca bootstrap \
  --ca-url https://localhost:9000 \
  --fingerprint $(docker logs step-ca 2>&1 | grep "fingerprint" | head -1 | awk '{print $NF}') \
  --install

# Copy root cert to project
docker cp step-ca:/home/step/certs/root_ca.crt ./certs/root_ca.crt
cp ./certs/root_ca.crt ./certs/root.crt

# Create a provisioner for the proxy
docker exec step-ca step ca provisioner add otlp-proxy \
  --type JWK \
  --create \
  --password-file /home/step/secrets/password \
  --ca-config /home/step/config/ca.json

# Export the provisioner key
docker exec step-ca step ca provisioner list \
  | jq -r '.[] | select(.name == "otlp-proxy") | .encryptedKey' \
  | step crypto jwe decrypt --password-file /tmp/step-ca/secrets/password \
  > ./certs/provisioner.jwk
```

After this, you should have:
- `./certs/root_ca.crt` — the step-ca root CA cert
- `./certs/root.crt` — compatibility copy for `docker-compose.yml`
- `./certs/provisioner.jwk` — the provisioner JWK (contains the private key)

## 2. Run the proxy with CA enabled

```bash
CA_ENABLED=true \
CA_ENDPOINT=https://localhost:9000 \
CA_PROVISIONER_NAME=otlp-proxy \
CA_PROVISIONER_KEY_FILE=./certs/provisioner.jwk \
CA_ROOT_CERT_FILE=./certs/root_ca.crt \
CA_EXTERNAL_HOSTNAME=localhost \
CA_RENEWAL_LISTEN_ADDR=127.0.0.1:6543 \
go run ./cmd/proxy

# Or add to .env:
#   CA_ENABLED=true
#   CA_ENDPOINT=https://localhost:9000
#   CA_PROVISIONER_NAME=otlp-proxy
#   CA_PROVISIONER_KEY_FILE=./certs/provisioner.jwk
#   CA_ROOT_CERT_FILE=./certs/root_ca.crt
#   CA_EXTERNAL_HOSTNAME=localhost
#   CA_RENEWAL_LISTEN_ADDR=127.0.0.1:6543
```

> If step-ca uses a self-signed TLS cert, the proxy's TLS client will verify
> it. You may need to set `CA_ENDPOINT=http://localhost:9000` (plain HTTP) for
> local testing, or trust the step-ca cert on your system.

## 3. Issue a certificate through the admin UI

1. Open `http://localhost:8080` → login
2. Create a tenant (e.g. `ca-test`)
3. Go to the tenant's **Certs** tab
4. Click **Issue Certificate**

Two modes are available:

### A. CSR upload (recommended — keys never touch the proxy)

Generate a key + CSR on your machine:
```bash
openssl req -newkey rsa:2048 -nodes -keyout my-client.key -out my-client.csr \
  -subj "/CN=my-device"
```

Upload `my-client.csr` in the admin form. The proxy signs it and returns:
- `ca.crt` (root CA)
- `client.crt` (signed client cert)
- `client.key` — **you already have this** (it was generated locally)

### B. Server-side key generation (single-use download)

Click **Generate Keypair** in the form. The proxy:
1. Generates an ECDSA P-256 keypair in memory
2. Sends the CSR to step-ca via the provisioner
3. Returns a single-use download token (valid 10 minutes)
4. The download is a `.zip` with all files + rsyslog config + install script

**The private key is held only in memory and zeroed after the download.**

## 4. Renew a certificate

In the cert list, click **Renew** next to an existing cert. The proxy calls
step-ca with the same CN/SANs — you get a new cert with the same identity.

## 5. Revoke a certificate

Click **Revoke**. The cert is immediately:
- Marked as `revoked_at` in the local database
- The syslog mTLS listener rejects new connections from its fingerprint
- step-ca is notified (the cert appears in `step ca cert` as revoked)

## 6. Verify syslog integration works with CA-issued certs

After issuing a cert through the admin UI (CSR upload mode):

```bash
# Send a syslog message using the CA-issued cert
MSG="<134>1 2026-08-03T12:00:00Z localhost ca-test 1234 - - CA-issued cert"
LEN=${#MSG}
printf "%d %s" "$LEN" "$MSG" | \
openssl s_client -connect 127.0.0.1:6514 \
  -cert my-client.crt -key my-client.key \
  -CAfile certs/root_ca.crt -quiet 2>/dev/null
```

## Cleanup

```bash
docker rm -f step-ca
rm -rf /tmp/step-ca
rm -f certs/root_ca.crt certs/provisioner.jwk
```

## Troubleshooting

| Symptom | Fix |
|:---|:---|
| `x509: certificate signed by unknown authority` | Use `CA_ENDPOINT=http://localhost:9000` for local dev (skip TLS) |
| `provisioner not found` | Run `step ca provisioner add otlp-proxy --type JWK --create` in container |
| `certificate issuance requires provisioner auth` | Provisioner JWK expired. Regenerate: `step ca provisioner jwk otlp-proxy` |
| Container exits immediately | step-ca needs initial config. Use `step ca init` first or mount pre-configured config |
| Download link expired | 10-minute window. Re-issue the certificate. |
