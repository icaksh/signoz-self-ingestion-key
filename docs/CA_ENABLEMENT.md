# Certificate Lifecycle / step-ca

For the default deployment, certificate lifecycle support is provisioned by the
all-in-one TUI installer. See [AIO_INSTALL.md](AIO_INSTALL.md).

The default stack runs a private `step-ca` service beside the proxy. The proxy
is a CA **client**, not a CA: root/intermediate signing keys remain inside the
step-ca persistent volume. The proxy receives only the root certificate and a
JWK provisioner key used to create short-lived provisioning tokens.

## Runtime configuration

The installer writes the equivalent of:

```bash
CA_ENABLED=true
CA_ENDPOINT=https://step-ca:9000
CA_PROVISIONER_NAME=otlp-proxy
CA_PROVISIONER_KEY_FILE=/certs/provisioner.jwk
CA_ROOT_CERT_FILE=/certs/root.crt
CA_EXTERNAL_HOSTNAME=relay.example.com
CA_CERT_LIFETIME=2160h
CA_RENEWAL_LISTEN_ADDR=:6543

SYSLOG_SERVER_CERT_FILE=/certs/server.crt
SYSLOG_SERVER_KEY_FILE=/certs/server.key
SYSLOG_CLIENT_CA_FILE=/certs/client-ca.crt
```

## Certificate operations

The admin application supports:

- CSR-based issuance, where the device keeps its private key;
- server-side key generation with a single-use download bundle;
- replacement certificate issuance for rotation;
- passive step-ca revocation plus local revocation metadata;
- device self-service replacement over the mTLS renewal listener.

The application does not pretend to use native step-ca `/rekey` when it does
not possess the old device key. Replacement certificates are authorized with
a fresh JWK provisioner token. Native step-ca renew/rekey flows are mTLS
operations tied to the existing certificate/private key.

## Generated material

```text
certs/
├── root.crt
├── client-ca.crt
├── provisioner.jwk
├── server.crt
└── server.key
```

The CA's own signing keys are not in this directory.
