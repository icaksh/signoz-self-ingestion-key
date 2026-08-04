#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="${CERTS_DIR:-$ROOT_DIR/certs}"
CA_DAYS="${CA_DAYS:-3650}"
LEAF_DAYS="${LEAF_DAYS:-365}"
CLIENT_NAME="${CLIENT_NAME:-test-client}"
SERVER_DNS_NAME="${SERVER_DNS_NAME:-localhost}"
SERVER_IP="${SERVER_IP:-127.0.0.1}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Error: missing required command: %s\n' "$1" >&2
    exit 1
  }
}

main() {
  need_cmd openssl
  need_cmd cp
  need_cmd rm
  need_cmd tr
  need_cmd sed

  umask 077
  mkdir -p "$CERTS_DIR"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  cd "$CERTS_DIR"

  rm -f ca.key ca.crt ca.srl client.key client.crt client.csr server.key server.crt server.csr client-ca.crt

  printf 'Generating CA...\n'
  openssl req -x509 -newkey rsa:4096 -nodes \
    -days "$CA_DAYS" \
    -keyout ca.key \
    -out ca.crt \
    -subj "/CN=Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

  cp ca.crt client-ca.crt

  printf 'Generating server certificate...\n'
  openssl req -newkey rsa:2048 -nodes \
    -keyout server.key \
    -out "$tmpdir/server.csr" \
    -subj "/CN=${SERVER_DNS_NAME}" \
    -addext "subjectAltName=DNS:${SERVER_DNS_NAME},IP:${SERVER_IP}" \
    -addext "extendedKeyUsage=serverAuth"

  openssl x509 -req \
    -in "$tmpdir/server.csr" \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days "$LEAF_DAYS" \
    -extfile <(printf '%s\n' \
      "subjectAltName=DNS:${SERVER_DNS_NAME},IP:${SERVER_IP}" \
      "extendedKeyUsage=serverAuth")

  printf 'Generating client certificate...\n'
  openssl req -newkey rsa:2048 -nodes \
    -keyout client.key \
    -out "$tmpdir/client.csr" \
    -subj "/CN=${CLIENT_NAME}" \
    -addext "extendedKeyUsage=clientAuth"

  openssl x509 -req \
    -in "$tmpdir/client.csr" \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.crt \
    -days "$LEAF_DAYS" \
    -extfile <(printf '%s\n' \
      "extendedKeyUsage=clientAuth")

  printf 'Client fingerprint:\n'
  openssl x509 -in client.crt -fingerprint -sha256 -noout \
    | sed 's/.*=//' \
    | tr -d ':' \
    | tr '[:upper:]' '[:lower:]'

  printf '\nGenerated files in %s:\n' "$CERTS_DIR"
  ls -la
}

main "$@"
