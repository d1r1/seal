# Hand steps: the group key on this Mac

Everything here runs from a terminal you opened yourself, not from an agent: Seal's guard hook
refuses `-c gpg.ssh.program=...` and any `user.signingkey` override inside Claude Code, on
purpose. Nothing below changes your global git config, `allowed_signers` or the installed
`~/.local/bin/seal` until step 4, which is yours to take.

## 1. Build and create the group key

```sh
cd ~/dev/src/github.com/d1r1/seal
scripts/build-debug.sh
.build/debug/seal setup
```

Expected: four files under `~/Library/Application Support/seal/` (`group.pub`, `group.json`,
`share-mac.json` 0600, `share-user.sealed` 0600), the recovery share printed once, and the group
public key as one `ssh-ed25519 ...` line. Store the recovery share in 1Password now; Seal never
writes it. Setup refuses to run a second time while the directory holds a group key.

## 2. Sign a commit in a scratch repository

```sh
SEAL=~/dev/src/github.com/d1r1/seal/.build/debug/seal
GROUP="$(cat ~/Library/Application\ Support/seal/group.pub)"
mkdir -p /tmp/seal-scratch && cd /tmp/seal-scratch && git init -q
printf 'me@d1r1.me namespaces="git" %s\n' "$GROUP" > allowed_signers
git config gpg.format ssh
git config gpg.ssh.program "$SEAL"
git config user.signingkey "key::$GROUP"
git config gpg.ssh.allowedSignersFile "$PWD/allowed_signers"
echo hello > README.md && git add README.md
git commit -S -m 'test: sign with the group key' -m 'Risks: none, scratch repository'
git log --show-signature -1
```

Expected: the card opens (attestation stub lines, the title, `⚠️ Risks    none, scratch
repository`, the stat), Touch ID is asked once by the Secure Enclave, and the log shows
`Good "git" signature for me@d1r1.me with ED25519 key SHA256:...`. Deny with Escape or cancel
the prompt: `seal: signing denied`, `fatal: failed to write commit object`, no commit.

`git config` here writes the scratch repository's own `.git/config`; the global config is
untouched. The `key::` form makes git write the key to a temporary file and pass `-U`, which is
how Seal sees the group key (it compares the key blob with `group.pub`).

## 3. Verify on GitHub

Register the group key at https://github.com/settings/ssh/new with key type **Signing Key**
(`gh ssh-key add --type signing` needs the `admin:ssh_signing_key` scope and fails silently
without it). Then, in the scratch repository:

```sh
gh repo create d1r1/seal-group-check --private --source . --push
gh api repos/d1r1/seal-group-check/commits/$(git rev-parse HEAD) --jq .commit.verification
```

Expected: `{"verified": true, "reason": "valid", ...}`. GitHub re-verifies an already pushed
commit when the key is registered later, so the order of the two steps does not matter. Delete
the repository afterwards: `gh repo delete d1r1/seal-group-check --yes`.

The committer email must be one verified on the account; `no_user` or `unverified_email` means
the email, not the key. `unknown_key` means the key was not added as a signing key.

## 4. Switch every commit to the group key

When 2 and 3 pass, and only then:

```sh
scripts/install.sh                                    # ~/.local/bin/seal and seal-frost
printf 'me@d1r1.me namespaces="git" %s\n' "$GROUP" >> ~/.config/git/allowed_signers
git config --global user.signingkey "key::$GROUP"
```

The personal 1Password key stays registered on GitHub for the signatures it already made and for
an emergency you perform by hand (`git -c user.signingkey=<personal key> commit ...` from your
own terminal: Seal sees a key that is not the group key and takes today's `ssh-keygen` path).

## Reading a failure

| What you see | Meaning |
| --- | --- |
| `seal: seal-frost exited 2: ... share-mac.json ...` | the Mac share is missing; run setup again (new group) |
| `seal: cannot unwrap the user share: ...` (exit 2) | the sealed share would not open and it was not a cancel: Touch ID re-enrolled invalidates the enclave key; run setup again (new group) |
| `seal: signing denied` (exit 1) | Escape, the window closed, or the prompt was cancelled |
| the card opens but Touch ID is the LocalAuthentication dialog and 1Password answers | the `-f` key is not the group key: `user.signingkey` still names the personal key |
