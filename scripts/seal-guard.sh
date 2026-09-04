#!/usr/bin/env bash
# PreToolUse hook for Bash: refuses git commands that would sign around Seal.
# Seal (gpg.ssh.program) is the author's signing gate; every commit and tag must
# go through its Review. Reads the hook JSON on stdin, inspects tool_input.command,
# exits 2 with a reason on stderr to block, 0 to allow.
#
# Only segments that invoke git are inspected (after splitting on newlines, ;, &&,
# ||, |), so prose that mentions a flag, say in a heredoc writing documentation,
# does not trip it. A segment invokes git when, after optional VAR=value prefixes,
# `env`, `sudo`, `cd X &&`-style chaining, or `command`, its first word is `git`,
# or when it sets a GIT_CONFIG_* variable.
set -uo pipefail

input="$(cat)"
command="$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)"
[ -n "$command" ] || exit 0

case "$command" in
  *git*|*GIT_CONFIG*) ;;
  *) exit 0 ;;
esac

# What a segment may not contain. Case-insensitive, extended regex.
patterns=(
  '--no-gpg-sign'                                   # commit, merge, rebase, cherry-pick, revert
  '--no-sign([[:space:]]|$)'                        # tag
  '--gpg-sign='                                     # a different key
  '(^|[^[:alnum:]_])gpgsign[[:space:]]*=[[:space:]]*(false|0|no|off)'
  '(^|[^[:alnum:]_])gpgsign[[:space:]]+(false|0|no|off)'   # git config commit.gpgsign false
  '(^|[^[:alnum:]_])gpg\.(ssh\.)?program([^[:alnum:]_]|$)'
  '(^|[^[:alnum:]_])gpg\.format([^[:alnum:]_]|$)'
  '(^|[^[:alnum:]_])gpg\.ssh\.allowedSignersFile([^[:alnum:]_]|$)'
  '(^|[^[:alnum:]_])user\.signingkey([^[:alnum:]_]|$)'
  '(^|[^[:alnum:]_])GIT_CONFIG_(COUNT|KEY|VALUE|GLOBAL|NOSYSTEM|PARAMETERS)([^[:alnum:]_]|$)'
)

# A lone read of the config is fine.
readonly_config='^git config( --(global|local|system|worktree))?( --(get|get-all|get-regexp|list)| -l)( .*)?$'
# A segment that runs git: optional assignments / wrappers, then the word git.
runs_git='^(([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*|env|sudo|command|exec|nohup|time)[[:space:]]+)*git([[:space:]]|$)'
sets_git_config='^((env|sudo|export)[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*GIT_CONFIG_(COUNT|KEY|VALUE|GLOBAL|NOSYSTEM|PARAMETERS)='

# Split into segments; heredoc bodies and quoted prose end up in segments that do not start with git.
segments="$(printf '%s\n' "$command" | sed -E 's/(&&|\|\||;|\|)/\n/g')"

while IFS= read -r segment; do
  segment="$(printf '%s' "$segment" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  [ -n "$segment" ] || continue
  if ! printf '%s' "$segment" | grep -Eq -- "$runs_git" && ! printf '%s' "$segment" | grep -Eq -- "$sets_git_config"; then
    continue
  fi
  if printf '%s' "$segment" | grep -Eq -- "$readonly_config"; then
    continue
  fi
  for pattern in "${patterns[@]}"; do
    if printf '%s' "$segment" | grep -Eiq -- "$pattern"; then
      echo "seal-guard: blocked '$segment'. Seal is the signing gate: git commands must not disable signing, change the signing program, key, or format, or override git config through the environment. Sign through the Review or ask the author." >&2
      exit 2
    fi
  done
done <<< "$segments"
exit 0
