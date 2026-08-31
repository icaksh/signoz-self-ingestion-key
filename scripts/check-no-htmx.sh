#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Checking NEW repository for functional HTMX remnants..."

# Functional HTMX = actual hx-* attributes in production markup/scripts, or a
# vendored htmx.min.js asset. Comments and tests that merely assert HTMX is
# *absent* are not functional remnants, so only production code is scanned and
# *_test.go files are excluded.
set +e
matches="$(
  grep -RniE 'hx-(get|post|put|patch|delete|target|swap|trigger|confirm|boost|include|vals|headers|on|push|select|sync|ext|indicator)|htmx\.min\.js' \
    cmd internal \
    --include='*.go' --include='*.html' --include='*.tmpl' --include='*.js' --include='*.css' \
    --exclude='*_test.go' \
    2>/dev/null
)"
status=$?
set -e

if [[ $status -eq 0 && -n "$matches" ]]; then
  echo "$matches"
  echo
  echo "ERROR: Potential live HTMX references remain in the NEW implementation." >&2
  exit 1
fi

if [[ $status -ne 0 && $status -ne 1 ]]; then
  echo "ERROR: grep failed with status $status" >&2
  exit "$status"
fi

# Guard: the forbidden vendored asset must not exist anywhere in production.
set +e
files="$(find cmd internal -type f \( -iname 'htmx*.js' -o -iname '*htmx*.min.js' \) 2>/dev/null)"
set -e
if [[ -n "$files" ]]; then
  echo "$files"
  echo "ERROR: htmx.min.js asset present in the NEW implementation." >&2
  exit 1
fi

echo "OK: no functional HTMX references found in the NEW implementation."
