# Seal

A macOS signing program for git that shows what is about to be signed before the signature is made.
Seal is set as `gpg.ssh.program`: on every signing request from a terminal it opens a card, laid out like terminal
output, showing where the request came from (directory, branch, Claude Code session or terminal
application), the author, who attested to the change, the commit title with the message behind an
expander, the Problem, Why and Risks trailers, the change counts with the parent and tree hashes, and
`diff --stat`, and asks for Touch ID inside the window. It exists so that a commit made by an agent on
your behalf is approved with eyes open. A request from a Paseo agent goes to the notary instead (see
[The agent path](#the-agent-path)).

Seal signs with a **group key**: one Ed25519 key that exists only as three FROST shares, threshold two
(RFC 9591). Seal holds one share; your share sits on the Mac sealed to the Secure Enclave, so that Touch
ID unwraps it for each signature; the third share is a recovery share you keep offline. No signature
exists without you, by arithmetic rather than policy, and the signature is an ordinary `ssh-ed25519`
signature that `ssh-keygen` and GitHub verify as usual (`docs/adr/0002-seal-holds-a-frost-share.md`).
A request for any other key, for example your personal 1Password key, goes through `ssh-keygen -Y
sign` against your SSH agent as before (`docs/adr/0001-gate-not-key-holder.md`).

## Requirements

- macOS 13 or later with Touch ID (the device password is the fallback)
- A Swift toolchain (`swift --version`; Xcode or the Command Line Tools provide it), `cargo` (Rust, for
  the `seal-frost` helper), `git`, and `jq`
- git already signing with SSH: `gpg.format=ssh`; `user.signingkey` set to the group key after
  `seal setup`, or to a public key held by an agent behind `SSH_AUTH_SOCK`
- The signing key registered with GitHub as a **signing** key

Check in one go:

```sh
git config --get gpg.format          # expect: ssh
git config --get user.signingkey     # expect: key::ssh-ed25519 ... (the group key), or your personal key
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
| Installs the `seal`, `seal-frost` and `seal-guard` binaries | `~/.local/bin/` | `SEAL_BIN_DIR` |
| Points `gpg.ssh.program` at `~/.local/bin/seal` | your **global** git config | — |
| Adds `seal-guard` as a `PreToolUse` hook for Bash | `~/.claude/settings.json` | `CLAUDE_SETTINGS` |

Your `user.signingkey`, `gpg.format`, `commit.gpgsign`, `tag.gpgsign`, and `allowed_signers` are left
alone. If you do not use Claude Code, the hook is inert; to skip it entirely, install by hand:

```sh
swift build -c release && (cd frost && cargo build --release)
install -m 755 .build/release/seal ~/.local/bin/seal
install -m 755 frost/target/release/seal-frost ~/.local/bin/seal-frost
git config --global gpg.ssh.program ~/.local/bin/seal
```

## The group key

```sh
seal setup
```

Once. It generates the group key with a trusted dealer inside `seal-frost`, then leaves four files in
`~/Library/Application Support/seal/`:

| File | Content | Mode |
| --- | --- | --- |
| `group.pub` | the group public key, one OpenSSH line | 0644 |
| `group.json` | the FROST public key package | 0644 |
| `share-mac.json` | Seal's share | 0600 |
| `share-user.sealed` | your share, sealed to a Secure Enclave key that needs the current Touch ID enrolment | 0600 |

It prints the **recovery share once**; store it in 1Password, Seal never writes it. It then prints the
group public key and the three hand steps, which are yours: register the key on GitHub as a signing key
(https://github.com/settings/ssh/new, type **Signing Key**), add it to `allowed_signers`, and set
`user.signingkey` to `key::<the line>`. Seal changes no git config. The full check, including a scratch
repository and GitHub's verdict, is in [`docs/hand-steps.md`](docs/hand-steps.md).

Setup refuses to run while a group key exists. Re-keying is removing the directory and running setup
again, then registering the new key; earlier signatures stay valid. Re-enrolling Touch ID invalidates
the sealed share the same way (`biometryCurrentSet`), so it also means a new group.

What this protects: the Mac share alone is below the threshold and signs nothing; your share is
unusable without the sensor; the recovery share is not on the signing path. What it does not: the
enclave key is not bound to the Seal binary (that needs an Apple provisioning profile), so any process
running as you can ask to unwrap, and you still have to touch the sensor for each ask.

## Install with an agent

If you would rather have a coding agent do it, paste this into a session:

```
Install Seal (https://github.com/d1r1/seal), a macOS git signing gate, on this machine.

1. Check the prerequisites and stop and tell me if any is missing: macOS 13+, swift, cargo, git, jq,
   gpg.format is "ssh", user.signingkey is set.
2. Record my current global gpg.ssh.program setting so I can roll back.
3. Clone the repo somewhere sensible, read its README, and run scripts/install.sh.
4. Report exactly what changed: the binaries installed, the git config line set, and whether the
   guard hook was registered in ~/.claude/settings.json.
5. Do not run `seal setup` or change user.signingkey: both are mine. Tell me the commands.
6. Verify with a signed commit in a throwaway repository. A card will open and ask for Touch ID.
   I have to approve it by hand; you cannot. If I deny it, seal exits 1 with
   "seal: signing denied" and no commit is created: report that and do not retry.
7. Show me `git log --show-signature -1` from that repository.
```

Two things the agent should know before it starts. The install changes your **global** git config, so it
affects every repository on the machine. And from the moment it succeeds, every commit that takes the card
path, including the ones the agent makes for itself, needs your finger on the sensor: the agent cannot
verify its own install unattended. That is the point of the tool, not a limitation of it. A commit from a
Paseo agent goes to the notary instead and needs no touch; see [The agent path](#the-agent-path).

## Uninstall

```sh
git config --global --unset gpg.ssh.program
rm -f ~/.local/bin/seal ~/.local/bin/seal-frost ~/.local/bin/seal-guard
```

To go back to a previous signing program instead, point `gpg.ssh.program` at it (for 1Password:
`/Applications/1Password.app/Contents/MacOS/op-ssh-sign`). Remove the `seal-guard` entry from the
`hooks.PreToolUse` array in `~/.claude/settings.json` by hand. The group key's directory,
`~/Library/Application Support/seal/`, is yours to keep or delete; deleting it retires the group key
(remove it from GitHub too).

## What the card shows

```
🔏 Sign?  seal · main
~/dev/src/github.com/d1r1/seal  │  implement: Seal signs with FROST group key
Author:    d1r1 <me@d1r1.me>
────────────────────────────────────────────────────────
🤖 implementer  ✅ stub: not checked
🔍 reviewer     ✅ stub: not checked
🧑 you          ⏳ Touch ID
────────────────────────────────────────────────────────
📝 feat(card): show the approval card instead of the Review        ▸ expand
🐛 Problem  the Review could not be answered from a phone
💡 Why      one card on the Mac now, the same card on the phone later
⚠️ Risks    —
📊 4 files · +70 −50 · parent a1b2c3d → tree e4f5a6b

 Sources/seal/CardWindow.swift | 120 ++++++++++-------
 1 file changed, 70 insertions(+), 50 deletions(-)

[Touch ID]  Touch ID to sign · Esc to deny
```

The second line is the Origin: the directory and the Claude Code session title when the request came
from one, else the terminal application. The attestation lines are a **stub** in this version: they
always show ✅ and say so; real attestations from the implementer and reviewer stages come later.
Problem, Why and Risks are the `Problem:`, `Why:` and `Risks:` trailers of the commit message; a
missing one shows `—`. The expander shows the full message body. A merge commit lists its parents in the
📊 line and shows one stat block per parent; a tag shows `tag v1.0` in the header, `Tagger:` and
`Tagged:`, and the tagged commit's stat. Escape, closing the window, or a cancelled Touch ID leaves git
without a signature, so no commit or tag is created. Every request gets its own card; there is no
"approve for a while". Overlapping requests open one window each and ask for Touch ID one at a time.

For the group key the Touch ID prompt is the Secure Enclave's, unwrapping your share; for another key it
is LocalAuthentication followed by `ssh-keygen`, and an agent holding that key may add its own unlock
prompt.

## The guard hook

`scripts/seal-guard.sh` refuses, from inside Claude Code, any git command that would sign around Seal:
the flags that skip signing or pick another key, `gpgsign=false`, changes to `gpg.ssh.program`,
`gpg.program`, `gpg.format`, `user.signingkey`, or `GIT_CONFIG_*` overrides in the environment. Only
segments that actually run git are inspected, so prose mentioning a flag (a heredoc writing docs, a
grep) passes. Reading the config (`git config --get ...`) is allowed. The agent sees a one-line reason
and is told to ask the author.

This protects against an agent's shortcut, not a hostile user; the real enforcement is a "require
signed commits" rule on the repository.

## The agent path

When git runs Seal from a Paseo agent (`PASEO_AGENT_ID` set and not empty), Seal opens no card: it
forwards the request to the notary's socket, `~/Library/Application Support/notary/notary.sock`, and
writes the signature the notary returns (seal-frost `docs/adr/0003-notary-signs-a-completed-flow.md`).
The variable selects the path and authenticates nothing; the notary decides. A refusal exits 1 with
`seal: signing denied: <reason>`; a notary error, a malformed answer, or no notary listening exits 2
with `seal: notary: <reason>` or `seal: notary socket not found at <path>`. Terminal commits are
unchanged. The protocol is Desk's `docs/notary-protocol.md`.

## Using it from an agent

| Outcome | What the agent sees | What it should do |
| --- | --- | --- |
| Signed | exit 0 | carry on |
| Denied (Escape, close, or Touch ID cancelled) | exit 1, `seal: signing denied`, `fatal: failed to write commit object` | report that the author declined; do not retry; ask why |
| Not seen (author away) | the tool's own timeout kills git; no decision | say the card was not answered; offer to retry when the author is back |
| Key holder failure | exit 2, `seal: seal-frost exited N: ...`, `seal: cannot unwrap the user share: ...`, or `seal: ssh-keygen exited N: ...` | report the line to the author; do not retry |

## Exit statuses

| Status | Meaning | stderr |
| --- | --- | --- |
| 0 | Signed | |
| 1 | No Approval: denied, window closed, Touch ID cancelled, or git exited before a decision; on the agent path, the notary refused | `seal: signing denied`, `seal: git exited before a decision was made`, or `seal: signing denied: <reason>` |
| 2 | Key holder failure: the helper failed or a share is missing (`seal-frost`), the sealed share would not open for a reason other than a cancel, `ssh-keygen` could not sign (agent unreachable), or on the agent path the notary failed, answered malformed, or is not listening | `seal: seal-frost exited N: <message>`, `seal: cannot unwrap the user share: <reason>`, `seal: ssh-keygen exited N: <message>`, `seal: notary: <reason>`, `seal: notary socket not found at <path>` |
| 3 | Malformed request: unparseable object body or missing arguments | `seal: malformed request: <reason>` |

Every other `-Y` mode (`verify`, `find-principals`, `check-novalidate`, `match-principals`) is handed to
`ssh-keygen` unchanged, so `git log --show-signature` and `git tag -v` work as before.

## Development

```sh
swift test                     # builds frost/ once with cargo when the helper is missing
(cd frost && cargo test)
scripts/seal-guard.test.sh
scripts/build-debug.sh         # .build/debug/seal with seal-frost next to it, for a hand check
```

Tests create real temporary repositories and drive `SealCore` through its public interface, including
the FROST path with test shares sealed to a software P-256 key (no Touch ID). The window and the Secure
Enclave are checked by hand: `docs/hand-steps.md`.
