#!/usr/bin/env bash
# Installs Seal for the current user:
#   1. builds the release binary and copies it to ~/.local/bin/seal
#   2. points git's global gpg.ssh.program at it (nothing else in the git config changes)
#   3. installs the Claude Code guard hook (scripts/seal-guard.sh) that refuses git commands
#      which would sign around Seal, and registers it in ~/.claude/settings.json
# Idempotent: run again after pulling to update. Requires: swift, git, jq.
set -euo pipefail

cd "$(dirname "$0")/.."
bin="${SEAL_BIN_DIR:-$HOME/.local/bin}"
settings="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"

mkdir -p "$bin"
swift build -c release >/dev/null
install -m 755 .build/release/seal "$bin/seal"
install -m 755 scripts/seal-guard.sh "$bin/seal-guard"
echo "installed $bin/seal and $bin/seal-guard"

git config --global gpg.ssh.program "$bin/seal"
echo "git config --global gpg.ssh.program $bin/seal"
if [ "$(git config --global --get gpg.format || true)" != "ssh" ]; then
  echo "note: gpg.format is not 'ssh'; Seal only handles SSH signing. Set gpg.format=ssh and user.signingkey first." >&2
fi

if command -v jq >/dev/null; then
  mkdir -p "$(dirname "$settings")"
  [ -f "$settings" ] || echo '{}' > "$settings"
  hook="$bin/seal-guard"
  jq --arg hook "$hook" '
    .hooks //= {} | .hooks.PreToolUse //= [] |
    if any(.hooks.PreToolUse[]; .hooks[]?.command == $hook) then . else
      .hooks.PreToolUse += [{matcher: "Bash", hooks: [{type: "command", command: $hook}]}]
    end' "$settings" > "$settings.tmp" && mv "$settings.tmp" "$settings"
  echo "registered $hook as a PreToolUse hook in $settings (restart Claude Code sessions to apply)"
else
  echo "jq not found: add $bin/seal-guard as a PreToolUse hook for Bash in $settings by hand" >&2
fi
