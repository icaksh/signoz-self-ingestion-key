# AIO syslog/collector patch

This build is based on the latest uploaded AIO package and preserves the existing sidebar/dialog fixes.

## Changes

- Added bundled `syslog-collector` (`otel/opentelemetry-collector-contrib:0.157.0`).
- AIO default is now `SYSLOG_COLLECTOR_ADDR=syslog-collector:5140` instead of container loopback.
- Collector receives newline-delimited RFC5424 from the proxy and exports OTLP/HTTP logs to `SIGNOZ_ENDPOINT`.
- Optional `SIGNOZ_INGESTION_KEY` is forwarded as the same Bearer Authorization header used by the Go OTLP proxy.
- Client rsyslog uses `TCP_Framing="octet-counted"` only on the mTLS client -> proxy hop.
- Client bundle installer resolves files relative to its own directory, not the shell's current directory.
- Client installer auto-detects/installs rsyslog GnuTLS support on apt/dnf/yum systems.
- Client bundle `install.sh` is emitted mode 0755 and `client.key` mode 0600.
- TUI can follow `syslog-collector` logs.

## Final data path

```text
rsyslog client
  -- RFC5424 + octet-counted + mTLS :6514 --> OTLP Proxy
  -- stamped RFC5424 + newline TCP ----------> syslog-collector:5140
  -- OTLP/HTTP ------------------------------> SigNoz
```

Port 5140 is internal to the Compose network and is not published to the host.

## Validation performed in build environment

- `bash -n install.sh` — pass
- `bash -n scripts/install-tui.sh` — pass
- `sh -n internal/pki/templates/install.sh.tmpl` — pass
- Docker Compose YAML parse — pass
- OTel collector YAML parse (with and without bearer header) — pass
- no-HTMX gate — pass

Go unit tests could not be executed in the build sandbox because the project requires Go 1.25.0 while the sandbox has Go 1.23.2.
