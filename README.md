# Seal

A macOS signing program for git that shows what is about to be signed before the signature is made.
Seal stands in for `op-ssh-sign` as `gpg.ssh.program`: on every signing request it opens a Review
window listing where the request came from and what the object is, and asks for Touch ID. The private
key stays in the 1Password SSH agent; Seal only gates the request (see `docs/adr/0001-gate-not-key-holder.md`).

## Install

```sh
swift build -c release
install -m 755 .build/release/seal ~/.local/bin/seal
git config --global gpg.ssh.program ~/.local/bin/seal
```

Nothing else in the git config changes: `gpg.format`, `user.signingkey`, `gpg.ssh.allowedSignersFile`,
and the signing key registered with GitHub stay as they are. Seal signs through the agent named by
`SSH_AUTH_SOCK`, which on this machine is the 1Password agent.

To go back:

```sh
git config --global gpg.ssh.program /Applications/1Password.app/Contents/MacOS/op-ssh-sign
```

## What the Review shows

Session, Directory, Command, then for a commit Branch, Author (and Committer when different), Message,
and one Changes block per parent; for a tag Tag, Tagged, Tagger, Message, and the tagged commit's Changes.
Deny or closing the window leaves git without a signature, so no commit or tag is created.

## Exit statuses

| Status | Meaning | stderr |
| --- | --- | --- |
| 0 | Signed | |
| 1 | No Approval: denied, window closed, Touch ID failed, or git exited before a decision | `seal: signing denied` or `seal: git exited before a decision was made` |
| 2 | Key holder failure: `ssh-keygen` could not sign (agent unreachable, 1Password locked) | `seal: ssh-keygen exited N: <ssh-keygen's message>` |
| 3 | Malformed request: unparseable object body or missing arguments | `seal: malformed request: <reason>` |

Every other `-Y` mode (`verify`, `find-principals`, `check-novalidate`, `match-principals`) is handed to
`ssh-keygen` unchanged, so `git log --show-signature` and `git tag -v` work as before.

## Development

```sh
swift test
```

Tests create real temporary repositories and drive `SealCore` through its public interface. The Review
window and Touch ID are checked by hand: point `gpg.ssh.program` at `.build/debug/seal` in a scratch
repository and commit.
