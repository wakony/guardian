#!/usr/bin/env bash
# install-hook.sh — Installs guardian-config-check as a git pre-commit hook
set -euo pipefail

# Find .git directory (walk up from current directory)
find_git_dir() {
  local dir="$PWD"
  while [ "$dir" != "/" ]; do
    if [ -d "$dir/.git" ]; then
      echo "$dir/.git"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  return 1
}

GIT_DIR=$(find_git_dir) || {
  echo "Error: Not inside a git repository."
  echo "Run this script from within a git repository."
  exit 1
}

HOOKS_DIR="$GIT_DIR/hooks"
HOOK_FILE="$HOOKS_DIR/pre-commit"

mkdir -p "$HOOKS_DIR"

# Determine how to invoke the scanner
if command -v guardian-config-check &>/dev/null; then
  SCANNER_CMD="guardian-config-check --pre-commit"
elif command -v npx &>/dev/null; then
  SCANNER_CMD="npx guardian-config-check --pre-commit"
else
  # Fallback: resolve relative to this script
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  SCANNER_CMD="node \"$SCRIPT_DIR/bin/cli.js\" --pre-commit"
fi

# Check if pre-commit hook already exists
if [ -f "$HOOK_FILE" ]; then
  if grep -q "guardian-config-check\|config-check" "$HOOK_FILE" 2>/dev/null; then
    echo "guardian-config-check hook already installed in $HOOK_FILE"
    exit 0
  fi

  echo "Existing pre-commit hook found. Appending guardian-config-check..."
  cat >> "$HOOK_FILE" << HOOKEOF

# --- Guardian Config Check — Supply Chain Defense ---
$SCANNER_CMD
HOOKEOF
else
  cat > "$HOOK_FILE" << HOOKEOF
#!/usr/bin/env bash
# Pre-commit hook: guardian-config-check supply chain defense
# Installed by: guardian-config-check install-hook.sh

$SCANNER_CMD
HOOKEOF
fi

chmod +x "$HOOK_FILE"

echo "guardian-config-check pre-commit hook installed."
echo "  Hook: $HOOK_FILE"
echo "  Command: $SCANNER_CMD"
echo ""
echo "Every commit will now be scanned for supply chain indicators."
echo "To remove: delete the guardian-config-check lines from $HOOK_FILE"
