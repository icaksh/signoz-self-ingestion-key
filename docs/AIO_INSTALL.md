# All-in-One TUI Installation

The project ships an interactive `dialog`-based installer that deploys the complete stack:

- the OTLP Proxy application;
- a private Smallstep `step-ca` used by the certificate lifecycle; and
- an internal OpenTelemetry Collector Contrib service that converts authenticated syslog to OTLP logs.

Certificate lifecycle support is **enabled by default and is not a separate
manual post-install step**.

## Requirements

The installer needs Linux and Docker Engine with the Docker Compose plugin. It
will try to install `dialog`, `openssl`, and, if requested, Docker from the
host distribution package manager.

## Run

```bash
chmod +x install.sh scripts/install-tui.sh
./install.sh
```

Choose **Quick install / reconfigure everything**.

The wizard asks for:

- SigNoz OTLP endpoint and optional ingestion key;
- public DNS name/IP of this proxy for client TLS;
- bundled CA name;
- step-ca server DNS names;
- client certificate lifetime;
- whether the Admin UI is behind HTTPS;
- optional syslog mTLS forwarding.

## What the installer creates automatically

1. A strong admin session signing secret.
2. A random password for step-ca, stored in `secrets/step-ca-password`.
3. A persistent Docker volume for step-ca PKI state.
4. A pinned `smallstep/step-ca:0.30.2` service.
5. An initial JWK provisioner named `otlp-proxy`.
6. Provisioner certificate-duration limits matching the selected lifetime.
7. `certs/root.crt` (the CA trust anchor).
8. `certs/provisioner.jwk` (decrypted private JWK used only by the proxy to
   generate short-lived step-ca provisioning tokens).
9. `certs/server.crt` and `certs/server.key` for the proxy's mTLS listeners.
10. `certs/client-ca.crt` for verification of step-ca client certificates.
11. `.env` with `CA_ENABLED=true` and the required CA configuration.
12. `config/otelcol-syslog.yaml` for RFC5424 → OTLP log conversion.
13. A pinned OpenTelemetry Collector Contrib service on the private Compose network.
14. The built and running proxy container.

The CA's root and intermediate signing private keys stay inside the dedicated
step-ca Docker volume and are never mounted into the proxy container.

## Ports

Defaults:

| Service | Host bind | Port |
|---|---|---:|
| OTLP HTTP | `0.0.0.0` | 4318 |
| Admin UI | `127.0.0.1` | 8080 |
| Syslog mTLS | `0.0.0.0` | 6514 |
| Device certificate renewal mTLS | `0.0.0.0` | 6543 |
| step-ca API | `127.0.0.1` | 9000 |

The proxy reaches step-ca over the private Compose network at
`https://step-ca:9000`.

## Operations menu

The TUI also provides:

- deploy/rebuild;
- stack start/stop;
- status and certificate validation;
- repair/re-export CA material;
- rotate the proxy listener certificate;
- display the root CA fingerprint;
- display the CA password after confirmation;
- proxy, step-ca, and syslog-collector log viewers;
- sensitive backup of application and CA state.

## Trust distribution

Devices that use mTLS must trust:

```text
certs/root.crt
```

The root fingerprint is available from **Certificate / step-ca tools → Show
root CA fingerprint**.

## Security notes

`secrets/step-ca-password` and `certs/provisioner.jwk` are sensitive. The
installer creates them with restrictive modes and `.gitignore` excludes the
entire `secrets/` and `certs/` directories.

`provisioner.jwk` is not a CA signing key. It can authorize certificate
issuance within the JWK provisioner's policy, so it still needs protection.

The Admin UI is bound to localhost by default. Keep it there or put it behind a
proper HTTPS reverse proxy. If accessed through HTTPS, choose `ADMIN_COOKIE_SECURE=true`
in the installer.

## Resetting the CA

The TUI intentionally does not provide a one-click "destroy CA" option. Losing
or replacing the step-ca persistent volume changes the root of trust and breaks
existing client certificates. Back up CA state before any destructive PKI
operation.


## Bundled syslog conversion collector

When syslog mTLS is enabled, the AIO stack also runs an OpenTelemetry Collector Contrib service named `syslog-collector`. The client sends RFC5424 over mTLS to the proxy on `:6514`; the proxy authenticates the client certificate, stamps the authoritative tenant structured-data field, and forwards newline-delimited RFC5424 over the private Compose network to `syslog-collector:5140`. The collector converts the messages to OTLP logs and sends them to `SIGNOZ_ENDPOINT`. Port 5140 is intentionally not published to the host.

The generated rsyslog client configuration uses octet-counted TCP framing on the mTLS hop to the proxy. The proxy removes that framing before forwarding to the internal collector, so `enable_octet_counting` must remain disabled in the collector config.
