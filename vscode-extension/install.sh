#!/usr/bin/env bash
# Builds the Ignite VS Code extension into a .vsix and installs it into
# your local VS Code (or Cursor/other VS Code-family editor whose `code`-
# equivalent CLI is on PATH), instead of relying on F5's Extension
# Development Host — which requires manually picking the "Run Ignite
# Extension" launch config and only works while that debug session stays
# open. This installs it as a real, persistent extension.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Any of these work — code (VS Code), code-insiders, cursor. First on PATH wins.
CLI="${IGNITE_VSCODE_CLI:-}"
if [ -z "$CLI" ]; then
  for candidate in code code-insiders cursor; do
    if command -v "$candidate" >/dev/null 2>&1; then
      CLI="$candidate"
      break
    fi
  done
fi
if [ -z "$CLI" ]; then
  echo "✗ No VS Code CLI ('code') found on PATH." >&2
  echo "  In VS Code: Cmd+Shift+P → 'Shell Command: Install code command in PATH', then rerun this script." >&2
  echo "  Or set IGNITE_VSCODE_CLI=/path/to/code-cli-equivalent and rerun." >&2
  exit 1
fi
echo "→ Using editor CLI: $CLI"

echo "→ Installing dependencies..."
npm install --no-audit --no-fund

echo "→ Compiling..."
npm run compile

echo "→ Packaging .vsix..."
npx --yes @vscode/vsce package --allow-missing-repository --skip-license -o ignite-vscode.vsix

VSIX="$(pwd)/ignite-vscode.vsix"
echo "→ Installing $VSIX into $CLI..."
"$CLI" --install-extension "$VSIX" --force

echo "✓ Installed. Reload the editor window (Cmd+Shift+P → 'Developer: Reload Window') to activate it."
