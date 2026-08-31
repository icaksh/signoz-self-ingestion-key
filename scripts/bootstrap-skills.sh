#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$ROOT/.pi/vendor"

mkdir -p "$VENDOR"

clone_or_update() {
  local url="$1"
  local dest="$2"

  if [[ -d "$dest/.git" ]]; then
    echo "Updating $(basename "$dest")..."
    git -C "$dest" fetch --depth=1 origin main
    git -C "$dest" reset --hard origin/main
  elif [[ -e "$dest" ]]; then
    echo "ERROR: $dest exists but is not a git checkout." >&2
    exit 1
  else
    echo "Cloning $url..."
    git clone --depth 1 "$url" "$dest"
  fi
}

clone_or_update \
  "https://github.com/justinwetch/HIGAgentSkills.git" \
  "$VENDOR/HIGAgentSkills"

clone_or_update \
  "https://github.com/samber/cc-skills-golang.git" \
  "$VENDOR/cc-skills-golang"

clone_or_update \
  "https://github.com/addyosmani/web-quality-skills.git" \
  "$VENDOR/web-quality-skills"

required=(
  "$VENDOR/HIGAgentSkills/SKILL.md"
  "$VENDOR/HIGAgentSkills/routing-index.md"
  "$VENDOR/cc-skills-golang/skills/golang-design-patterns/SKILL.md"
  "$VENDOR/cc-skills-golang/skills/golang-database/SKILL.md"
  "$VENDOR/cc-skills-golang/skills/golang-security/SKILL.md"
  "$VENDOR/cc-skills-golang/skills/golang-context/SKILL.md"
  "$VENDOR/cc-skills-golang/skills/golang-concurrency/SKILL.md"
  "$VENDOR/cc-skills-golang/skills/golang-testing/SKILL.md"
  "$VENDOR/cc-skills-golang/skills/golang-performance/SKILL.md"
  "$VENDOR/cc-skills-golang/skills/golang-benchmark/SKILL.md"
  "$VENDOR/web-quality-skills/skills/accessibility/SKILL.md"
  "$VENDOR/web-quality-skills/skills/best-practices/SKILL.md"
  "$VENDOR/web-quality-skills/skills/performance/SKILL.md"
  "$VENDOR/web-quality-skills/skills/web-quality-audit/SKILL.md"
)

for path in "${required[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "ERROR: Expected skill file missing: $path" >&2
    exit 1
  fi
done

echo
echo "Skills installed successfully under .pi/vendor/."
echo "If Pi is already running, execute /reload."
echo "Then use /plan, review the generated artifacts, and use /implement."
