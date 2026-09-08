# Seal

A macOS signing program for git that shows what is about to be signed before the signature is made.
Seal is set as `gpg.ssh.program`: on every signing request it opens a Review window, laid out like
terminal output, showing where the request came from (directory, branch, Claude Code session or terminal
application), the author, the full commit message, and `diff --stat`, and asks for Touch ID inside the
window. It exists so that a commit made by an agent on your behalf is approved with eyes open.

The private key never leaves your SSH agent (1Password, or any agent behind `SSH_AUTH_SOCK`); Seal only
gates the request and hands signing to `ssh-keygen -Y sign` (see `docs/adr/0001-gate-not-key-holder.md`).

## Requirements

- macOS 13 or later with Touch ID (the device password is the fallback)
- A Swift toolchain (`swift --version`; Xcode or the Command Line Tools provide it), `git`, and `jq`
- An SSH agent holding your signing key, reachable through `SSH_AUTH_SOCK` (1Password, `ssh-agent`,
  Secretive, or any other)
- git already signing with SSH: `gpg.format=ssh` and `user.signingkey` set to a public key held by that
  agent (or to a key file), with the same public key registered with GitHub as a **signing** key

Check the last two in one go:

```sh
git config --get gpg.format          # expect: ssh
git config --get user.signingkey     # expect: a public key, or a path to one
ssh-add -l                           # expect: your signing key listed
```

If `gpg.format` is not `ssh`, set up SSH commit signing first. Seal replaces the signing *program*; it
does not set signing up for you.

## Install

```sh
git clone https://github.com/d1r1/seal && cd seal
scripts/install.sh
```

Run it again after pulling to update. There is no daemon and nothing to start after a reboot.

### What the installer changes on your machine

It touches three things outside the clone, and nothing else:

| Change | Where | Override |
| --- | --- | --- |
| Installs the `seal` and `seal-guard` binaries | `~/.local/bin/` | `SEAL_BIN_DIR` |
| Points `gpg.ssh.program` at `~/.local/bin/seal` | your **global** git config | — |
| Adds `seal-guard` as a `PreToolUse` hook for Bash | `~/.claude/settings.json` | `CLAUDE_SETTINGS` |

Your `user.signingkey`, `gpg.format`, `commit.gpgsign`, `tag.gpgsign`, and `allowed_signers` are left
alone. If you do not use Claude Code, the hook is inert; to skip it entirely, install by hand:

```sh
swift build -c release
install -m 755 .build/release/seal ~/.local/bin/seal
git config --global gpg.ssh.program ~/.local/bin/seal
```

## Install with an agent

If you would rather have a coding agent do it, paste this into a session:

```
Install Seal (https://github.com/d1r1/seal), a macOS git signing gate, on this machine.

1. Check the prerequisites and stop and tell me if any is missing: macOS 13+, swift, git, jq,
   gpg.format is "ssh", user.signingkey is set, and `ssh-add -l` lists that key.
2. Record my current global gpg.ssh.program setting so I can roll back.
3. Clone the repo somewhere sensible, read its README, and run scripts/install.sh.
4. Report exactly what changed: the binaries installed, the git config line set, and whether the
   guard hook was registered in ~/.claude/settings.json.
5. Verify with a signed commit in a throwaway repository. A Review window will open and ask for
   Touch ID. I have to approve it by hand; you cannot. If I deny it, seal exits 1 with
   "seal: signing denied" and no commit is created: report that and do not retry.
6. Show me `git log --show-signature -1` from that repository.
```

Two things the agent should know before it starts. The install changes your **global** git config, so it
affects every repository on the machine. And from the moment it succeeds, every commit the agent makes,
including the ones it makes for itself, needs your finger on the sensor: the agent cannot verify its own
install unattended. That is the point of the tool, not a limitation of it.

## Uninstall

```sh
git config --global --unset gpg.ssh.program
rm -f ~/.local/bin/seal ~/.local/bin/seal-guard
```

To go back to a previous signing program instead, point `gpg.ssh.program` at it (for 1Password:
`/Applications/1Password.app/Contents/MacOS/op-ssh-sign`). Remove the `seal-guard` entry from the
`hooks.PreToolUse` array in `~/.claude/settings.json` by hand.

## What the Review shows

```
~/src/seal  │  main  │  seal-touch-id
Author:    d1r1 <me@d1r1.me>

git commit "feat(review): lay the Review out like terminal output

    Path, branch and session on one line, then author, then the
    git command with the message inside the quotes."

 Sources/seal/Review.swift | 120 ++++++++++-------
 1 file changed, 70 insertions(+), 50 deletions(-)

[Touch ID]  Touch ID to sign · Esc to deny
```

The third item on the first line is the Claude Code session title when the request came from one, else
the terminal application. A merge commit shows one stat block per parent; a tag shows `tag v1.0` in place
of the branch, `Tagger:` and `Tagged:`, and the tagged commit's stat. Escape, closing the window, or a
cancelled Touch ID leaves git without a signature, so no commit or tag is created. Every request gets
its own Review; there is no "approve for a while". Overlapping requests open one window each and ask
for Touch ID one at a time.

When the agent holding the key is locked, it shows its own unlock prompt after Seal's; that is the
agent's behaviour, not Seal's.

## The guard hook

`scripts/seal-guard.sh` refuses, from inside Claude Code, any git command that would sign around Seal:
the flags that skip signing or pick another key, `gpgsign=false`, changes to `gpg.ssh.program`,
`gpg.program`, `gpg.format`, `user.signingkey`, or `GIT_CONFIG_*` overrides in the environment. Only
segments that actually run git are inspected, so prose mentioning a flag (a heredoc writing docs, a
grep) passes. Reading the config (`git config --get ...`) is allowed. The agent sees a one-line reason
and is told to ask the author.

This protects against an agent's shortcut, not a hostile user; the real enforcement is a "require
signed commits" rule on the repository.

## Using it from an agent

| Outcome | What the agent sees | What it should do |
| --- | --- | --- |
| Signed | exit 0 | carry on |
| Denied (Escape, close, or Touch ID cancelled) | exit 1, `seal: signing denied`, `fatal: failed to write commit object` | report that the author declined; do not retry; ask why |
| Not seen (author away) | the tool's own timeout kills git; no decision | say the Review was not answered; offer to retry when the author is back |
| Key holder unreachable (agent not running or socket missing) | exit 2, `seal: ssh-keygen exited N: ...` | ask the author to start or unlock the agent, then retry |

## Exit statuses

| Status | Meaning | stderr |
| --- | --- | --- |
| 0 | Signed | |
| 1 | No Approval: denied, window closed, Touch ID cancelled, or git exited before a decision | `seal: signing denied` or `seal: git exited before a decision was made` |
| 2 | Key holder failure: `ssh-keygen` could not sign (agent unreachable) | `seal: ssh-keygen exited N: <ssh-keygen's message>` |
| 3 | Malformed request: unparseable object body or missing arguments | `seal: malformed request: <reason>` |

Every other `-Y` mode (`verify`, `find-principals`, `check-novalidate`, `match-principals`) is handed to
`ssh-keygen` unchanged, so `git log --show-signature` and `git tag -v` work as before.

## Development

```sh
swift test
scripts/seal-guard.test.sh
```

Tests create real temporary repositories and drive `SealCore` through its public interface. The Review
window and Touch ID are checked by hand: point `gpg.ssh.program` at `.build/debug/seal` in a scratch
repository and commit.
