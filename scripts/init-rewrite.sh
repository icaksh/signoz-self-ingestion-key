#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <legacy-directory | legacy.zip | git-url>" >&2
  exit 2
fi

bash "$ROOT/scripts/set-legacy-source.sh" "$1"
bash "$ROOT/scripts/bootstrap-skills.sh"

mkdir -p "$ROOT/docs" "$ROOT/todo"

echo
echo "Initialization complete."
echo
echo "Next:"
echo "  1. cd \"$ROOT\""
echo "  2. pi"
echo "  3. select DeepSeek with /model if needed"
echo "  4. /reload"
echo "  5. /plan"
echo
echo "After reviewing docs/rewrite-spec.md, docs/design-system.md and todo/rewrite.md:"
echo "  /new"
echo "  /implement"
