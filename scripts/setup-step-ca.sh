#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_DIR="${CA_DIR:-/tmp/step-ca}"
CERTS_DIR="${CERTS_DIR:-$ROOT_DIR/certs}"
CONTAINER_NAME="${STEP_CA_CONTAINER:-step-ca}"
IMAGE="${STEP_CA_IMAGE:-smallstep/step-ca:latest}"
CA_NAME="${STEP_CA_NAME:-Local Dev CA}"
CA_DNS="${STEP_CA_DNS:-localhost}"
CA_ADDRESS="${STEP_CA_ADDRESS:-:9000}"
PROVISIONER_NAME="${CA_PROVISIONER_NAME:-otlp-proxy}"
CA_ENDPOINT="${CA_ENDPOINT:-https://localhost:9000}"
STEP_CA_PASSWORD_FILE="$CA_DIR/secrets/password"
STEP_CA_CONFIG_FILE="$CA_DIR/config/ca.json"
ROOT_CA_SRC="$CA_DIR/certs/root_ca.crt"
ROOT_CA_DST="$CERTS_DIR/root_ca.crt"
ROOT_CA_COMPAT_DST="$CERTS_DIR/root.crt"
PROVISIONER_JWK_DST="$CERTS_DIR/provisioner.jwk"

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

ensure_writable_dir() {
  local dir="$1"
  mkdir -p "$dir"
  if [[ -w "$dir" ]]; then
    return 0
  fi

  if command -v sudo >/dev/null 2>&1; then
    log "Fixing ownership of $dir with sudo"
    sudo chown -R "$(id -u):$(id -g)" "$dir"
  fi

  [[ -w "$dir" ]] || die "Cannot write to $dir. Run: sudo chown -R $(id -u):$(id -g) $dir"
}

ensure_password_file() {
  mkdir -p "$CA_DIR/secrets"
  if [[ -s "$STEP_CA_PASSWORD_FILE" ]]; then
    chmod 600 "$STEP_CA_PASSWORD_FILE"
    return 0
  fi

  if [[ -n "${STEP_CA_PASSWORD:-}" ]]; then
    printf '%s' "$STEP_CA_PASSWORD" > "$STEP_CA_PASSWORD_FILE"
    chmod 600 "$STEP_CA_PASSWORD_FILE"
    return 0
  fi

  if [[ -t 0 ]]; then
    local password
    read -r -s -p "step-ca password: " password
    printf '\n'
    printf '%s' "$password" > "$STEP_CA_PASSWORD_FILE"
    chmod 600 "$STEP_CA_PASSWORD_FILE"
    unset password
    return 0
  fi

  die "Missing $STEP_CA_PASSWORD_FILE. Set STEP_CA_PASSWORD or create the file first."
}

init_ca_if_needed() {
  if [[ -f "$STEP_CA_CONFIG_FILE" && -f "$ROOT_CA_SRC" ]]; then
    log "Existing step-ca data found in $CA_DIR"
    return 0
  fi

  log "Initializing new step-ca data in $CA_DIR"
  docker run --rm \
    -v "$CA_DIR:/home/step" \
    "$IMAGE" \
    step ca init \
    --name "$CA_NAME" \
    --dns "$CA_DNS" \
    --address "$CA_ADDRESS" \
    --provisioner "$PROVISIONER_NAME" \
    --password-file /home/step/secrets/password \
    --provisioner-password-file /home/step/secrets/password >/dev/null
}

ensure_container() {
  if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    log "Removing existing container: $CONTAINER_NAME"
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi

  log "Creating container: $CONTAINER_NAME"
  docker run -d --name "$CONTAINER_NAME" --network host \
    -v "$CA_DIR:/home/step" \
    "$IMAGE" \
    step-ca /home/step/config/ca.json \
    --password-file /home/step/secrets/password >/dev/null
}

wait_for_root_cert() {
  local i
  for i in $(seq 1 30); do
    if [[ -f "$ROOT_CA_SRC" ]]; then
      return 0
    fi
    sleep 1
  done
  die "step-ca did not produce $ROOT_CA_SRC"
}

ensure_provisioner() {
  if jq -e --arg name "$PROVISIONER_NAME" '.authority.provisioners[]? | select(.name == $name)' "$STEP_CA_CONFIG_FILE" >/dev/null; then
    log "Provisioner already exists: $PROVISIONER_NAME"
    return 0
  fi

  log "Creating provisioner: $PROVISIONER_NAME"
  docker exec "$CONTAINER_NAME" step ca provisioner add "$PROVISIONER_NAME" \
    --type JWK \
    --create \
    --password-file /home/step/secrets/password \
    --ca-config /home/step/config/ca.json >/dev/null

  log "Restarting step-ca so the new provisioner is loaded"
  docker restart "$CONTAINER_NAME" >/dev/null
}

export_provisioner_key() {
  local encrypted_key
  encrypted_key="$(
    jq -r --arg name "$PROVISIONER_NAME" \
      '.authority.provisioners[]? | select(.name == $name) | .encryptedKey // empty' \
      "$STEP_CA_CONFIG_FILE"
  )"

  [[ -n "$encrypted_key" ]] || die "Could not find encryptedKey for provisioner $PROVISIONER_NAME in $STEP_CA_CONFIG_FILE"

  printf '%s\n' "$encrypted_key" | docker exec -i "$CONTAINER_NAME" \
    step crypto jwe decrypt \
    --password-file /home/step/secrets/password \
    > "$PROVISIONER_JWK_DST"
  chmod 600 "$PROVISIONER_JWK_DST"
}

main() {
  need_cmd docker
  need_cmd jq

  docker info >/dev/null 2>&1 || die "Docker daemon is not reachable"

  ensure_password_file
  ensure_writable_dir "$CERTS_DIR"
  init_ca_if_needed
  ensure_container
  wait_for_root_cert

  cp "$ROOT_CA_SRC" "$ROOT_CA_DST"
  chmod 644 "$ROOT_CA_DST"
  cp "$ROOT_CA_DST" "$ROOT_CA_COMPAT_DST"
  chmod 644 "$ROOT_CA_COMPAT_DST"

  ensure_provisioner
  export_provisioner_key

  log "Done"
  log "Root cert: $ROOT_CA_DST"
  log "Compat root cert: $ROOT_CA_COMPAT_DST"
  log "Provisioner key: $PROVISIONER_JWK_DST"
  log "CA endpoint: $CA_ENDPOINT"
}

main "$@"
