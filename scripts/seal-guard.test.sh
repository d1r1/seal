#!/usr/bin/env bash
# Tests for seal-guard.sh at its seam: hook JSON in, exit code out.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/seal-guard.sh"
failures=0

run() { jq -cn --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}' | "$script" 2>/dev/null; }

blocked() {
  run "$1"; local code=$?
  [ $code -eq 2 ] || { echo "FAIL: should block (got $code): $1"; failures=$((failures + 1)); }
}
allowed() {
  run "$1"; local code=$?
  [ $code -eq 0 ] || { echo "FAIL: should allow (got $code): $1"; failures=$((failures + 1)); }
}

blocked 'git commit --no-gpg-sign -m x'
blocked 'git commit -m x --no-gpg-sign'
blocked 'git tag --no-sign v1'
blocked 'git commit --gpg-sign=DEADBEEF -m x'
blocked 'git -c commit.gpgsign=false commit -m x'
blocked 'git -c tag.gpgsign=0 tag v1'
blocked 'git config --global commit.gpgsign false'
blocked 'git config commit.gpgsign no'
blocked 'git -c gpg.ssh.program=ssh-keygen commit -m x'
blocked 'git -c gpg.program=/bin/true commit -m x'
blocked 'git config --global gpg.ssh.program /bin/true'
blocked 'git -c gpg.format=openpgp commit -m x'
blocked 'git -c user.signingkey=/tmp/other commit -m x'
blocked 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false git commit -m x'
blocked 'GIT_CONFIG_GLOBAL=/dev/null git commit -m x'
blocked 'GIT_CONFIG_NOSYSTEM=1 git commit -m x'
blocked 'cd /tmp && git commit -q -m "x" --no-gpg-sign && echo done'
blocked 'GIT_CONFIG_PARAMETERS="'"'"'commit.gpgsign=false'"'"'" git commit -m x'

allowed 'git commit -m "feat: sign it"'
allowed 'git commit -S -m x'
allowed 'git tag -s v1 -m v1'
allowed 'git log --show-signature -1'
allowed 'git config --get user.signingkey'
allowed 'git config --global --get-regexp gpg'
allowed 'git config --list'
blocked 'git config --get user.signingkey; git config user.signingkey /tmp/k'
allowed 'swift test'
allowed 'ls -la'
allowed 'git status'
allowed 'git config user.name t'
allowed 'echo "the gpgsign flag" > notes.txt'
allowed $'cat > README.md <<EOF\nUse --no-gpg-sign to skip, or set gpg.ssh.program.\nEOF'
allowed $'python3 - <<EOF\ns = "git -c commit.gpgsign=false"\nEOF'
allowed 'grep -rn "no-gpg-sign" docs/'
allowed "blocked 'env GIT_CONFIG_GLOBAL=/dev/null git commit -m x'"   # a test line quoted in prose
blocked $'echo start\ngit commit --no-gpg-sign -m x'
blocked 'env GIT_CONFIG_GLOBAL=/dev/null git commit -m x'
blocked 'cd /tmp && GIT_CONFIG_NOSYSTEM=1 git commit -m x'
blocked 'sudo git -c gpg.ssh.program=/bin/true commit -m x'

if [ $failures -eq 0 ]; then echo "seal-guard.test.sh: ok"; else exit 1; fi
