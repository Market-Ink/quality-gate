#!/usr/bin/env bash
# MarketInk Quality Gate — one-time onboarding for a project (macOS/Linux).
#
# What it does (all inside the TARGET repo, nothing destructive):
#   1. Vendors the scanner into  <repo>/.quality-gate/  (scan.js, lib, rules,
#      baselines, prompts) and creates <repo>/.quality-gate.json from the
#      example if the project doesn't have one yet
#   2. Installs the hooks into    <repo>/.githooks/       (pre-commit, pre-push)
#   3. Points git at them:         git config core.hooksPath .githooks
#   4. Adds quality-reports/ to    <repo>/.gitignore
#
# After this, commit .githooks/ and .quality-gate/ so the setup travels with the
# repo. Teammates who clone/pull still run ONE command once (see the end).
#
# Usage:  ./install-hooks.sh /path/to/your-project
set -euo pipefail

REPO="${1:-}"
if [ -z "$REPO" ]; then
  echo "usage: ./install-hooks.sh /path/to/your-project" >&2
  exit 2
fi

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # the quality-gate dir
REPO="$(cd "$REPO" && pwd)"

if [ ! -d "$REPO/.git" ]; then
  echo "error: not a git repository: $REPO (run 'git init' there first)." >&2
  exit 2
fi

echo "Onboarding Quality Gate into: $REPO"

# 1. Vendor the scanner ------------------------------------------------------
mkdir -p "$REPO/.quality-gate"
cp "$TOOL_DIR/scan.js"                  "$REPO/.quality-gate/scan.js"
for d in lib rules baselines; do
  rm -rf "$REPO/.quality-gate/$d"
  cp -R "$TOOL_DIR/$d" "$REPO/.quality-gate/$d"
done
[ -d "$TOOL_DIR/.quality" ] && cp -R "$TOOL_DIR/.quality" "$REPO/.quality-gate/"
echo "  [ok] vendored scanner -> .quality-gate/"
if [ ! -f "$REPO/.quality-gate.json" ]; then
  cp "$TOOL_DIR/examples/quality-gate.json" "$REPO/.quality-gate.json"
  echo "  [ok] created .quality-gate.json (extends the org baseline - edit to taste)"
fi

# 2. Install the hooks -------------------------------------------------------
mkdir -p "$REPO/.githooks"
cp "$TOOL_DIR/hooks/pre-commit" "$REPO/.githooks/pre-commit"
cp "$TOOL_DIR/hooks/pre-push"   "$REPO/.githooks/pre-push"
chmod +x "$REPO/.githooks/pre-commit" "$REPO/.githooks/pre-push"
echo "  [ok] installed hooks -> .githooks/ (pre-commit, pre-push)"

# 3. Point git at the committed hooks ---------------------------------------
git -C "$REPO" config core.hooksPath .githooks
echo "  [ok] git config core.hooksPath .githooks"

# 4. Ignore generated reports ------------------------------------------------
touch "$REPO/.gitignore"
for entry in "quality-reports/" ".quality-gate/quality-reports/"; do
  grep -qxF "$entry" "$REPO/.gitignore" || echo "$entry" >> "$REPO/.gitignore"
done
echo "  [ok] ensured report paths in .gitignore"

cat <<'EOF'

Done. The gate now runs automatically on commit and push in this repo.
Next:
  1. Commit the setup so it travels with the repo:
       git add .githooks .quality-gate .quality-gate.json .gitignore && git commit -m "Add MarketInk Quality Gate hooks"
  2. Every teammate runs this ONCE after cloning (git can't auto-enable hooks):
       git config core.hooksPath .githooks

Toggles (env vars): QG_BLOCK=1 to block on findings, QG_AI=1 to add the AI review on push.
EOF
