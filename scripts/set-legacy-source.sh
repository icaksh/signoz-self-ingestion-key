#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF_ROOT="$ROOT/.reference"
TARGET="$REF_ROOT/legacy"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <local-directory | local-zip | git-url>" >&2
  exit 2
fi

SOURCE="$1"
mkdir -p "$REF_ROOT"

remove_existing_target() {
  if [[ -L "$TARGET" ]]; then
    rm "$TARGET"
  elif [[ -d "$TARGET/.git" ]]; then
    rm -rf "$TARGET"
  elif [[ -d "$TARGET" ]]; then
    echo "ERROR: $TARGET exists and is not a managed symlink/git checkout." >&2
    echo "Remove or rename it manually if you intend to replace it." >&2
    exit 1
  elif [[ -e "$TARGET" ]]; then
    echo "ERROR: $TARGET already exists." >&2
    exit 1
  fi
}

if [[ -d "$SOURCE" ]]; then
  ABS="$(cd "$SOURCE" && pwd)"
  if [[ "$ABS" == "$ROOT" ]]; then
    echo "ERROR: Legacy source cannot be the new repository itself." >&2
    exit 1
  fi
  remove_existing_target
  ln -s "$ABS" "$TARGET"
  echo "Legacy source linked read-only-by-policy:"
  echo "  $TARGET -> $ABS"

elif [[ -f "$SOURCE" && "$SOURCE" == *.zip ]]; then
  command -v unzip >/dev/null 2>&1 || {
    echo "ERROR: unzip is required for ZIP references." >&2
    exit 1
  }
  remove_existing_target
  TMP="$REF_ROOT/.legacy-extract"
  rm -rf "$TMP"
  mkdir -p "$TMP"
  unzip -q "$SOURCE" -d "$TMP"

  shopt -s dotglob nullglob
  entries=("$TMP"/*)
  shopt -u dotglob nullglob

  if [[ ${#entries[@]} -eq 1 && -d "${entries[0]}" ]]; then
    mv "${entries[0]}" "$TARGET"
    rmdir "$TMP"
  else
    mv "$TMP" "$TARGET"
  fi
  chmod -R a-w "$TARGET" 2>/dev/null || true
  echo "Legacy ZIP extracted to:"
  echo "  $TARGET"

elif [[ "$SOURCE" =~ ^https?:// ]] || [[ "$SOURCE" =~ ^git@ ]]; then
  remove_existing_target
  git clone --depth 1 "$SOURCE" "$TARGET"
  chmod -R a-w "$TARGET" 2>/dev/null || true
  echo "Legacy repository cloned to:"
  echo "  $TARGET"

else
  echo "ERROR: Not a readable directory, ZIP, or supported Git URL: $SOURCE" >&2
  exit 1
fi

if [[ ! -e "$TARGET" ]]; then
  echo "ERROR: Failed to configure legacy source." >&2
  exit 1
fi

echo
echo "IMPORTANT: .reference/legacy is reference-only."
echo "All new implementation belongs in: $ROOT"
