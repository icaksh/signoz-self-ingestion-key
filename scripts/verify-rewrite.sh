#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Formatting Go files"
if command -v gofmt >/dev/null 2>&1; then
  find . -type f -name '*.go' \
    -not -path './.git/*' \
    -not -path './.pi/*' \
    -print0 | xargs -0 -r gofmt -w
else
  echo "ERROR: gofmt not found" >&2
  exit 1
fi

echo "==> go build ./..."
go build ./...

echo "==> go test ./..."
go test ./...

echo "==> go vet ./..."
go vet ./...

if [[ "${RUN_RACE:-0}" == "1" ]]; then
  echo "==> go test -race ./..."
  go test -race ./...
fi

echo "==> HTMX check"
bash scripts/check-no-htmx.sh

echo "==> Git diff summary"
git diff --stat || true

echo
echo "Verification completed successfully."
