# 0002: Seal signs with a FROST group key and holds one of its shares

Status: accepted (user OK in the implement tab, 2026-09-18)
Date: 2026-09-18
Supersedes: [0001](0001-gate-not-key-holder.md) for the group key; 0001 still holds for the personal key

## Context

ADR 0001 made Seal a gate in front of the 1Password SSH agent: Seal shows the Review, takes
Approval with Touch ID, and hands signing to `ssh-keygen -Y sign`. It works, but only for a user
sitting at the Mac. The user now drives agents from a phone through Paseo while git runs on this
always-on Mac, and neither the Review window nor 1Password's prompt can be answered from there.

The design session in `seal-frost` (ADR 0001 there, 2026-09-17 and 2026-09-18) decided the
replacement and proved it end to end: one Ed25519 group key, FROST threshold 2 of 3 (RFC 9591,
`frost-ed25519` 3.0.0), whose signatures are plain Ed25519 signatures. A commit signed that way
inside the SSHSIG envelope is `Good "git" signature` for OpenSSH 10.3p1 and `reason: valid` on
GitHub once the group key is registered as a signing key. The shares are: 🧑 the user (a phone
later; a Secure Enclave-wrapped, Touch ID-bound copy on the Mac now), 🖥 the Mac (Seal), and 🧊
recovery (offline, never on the signing path). The user is in every signature by arithmetic:
the only two shares on the signing path are 🧑 and 🖥.

This ADR records what that decision means for Seal. It covers step 1 of the plan in
`seal-frost/docs/phone-approval.md`: the group key signs locally on the Mac, the user's share is
unwrapped by Touch ID, the attestation check is a stub, and the approval card replaces the Review.
The phone, the relay and real attestations are later steps and are not designed here.

## Decision

1. **Seal holds the 🖥 share and becomes the FROST coordinator.** For a Signing request whose
   `-f` key is the group key, Seal runs both FROST rounds with the 🖥 share and the unwrapped 🧑
   share, aggregates, and writes `<buffer>.sig` itself. "Seal never holds or sees a private key"
   from ADR 0001 no longer holds for the group key. It still holds for the personal 1Password key:
   a request whose `-f` key is not the group key goes to `ssh-keygen -Y sign` exactly as before.
   The key named by `-f` selects the Key holder; no git config or environment variable does.

2. **The cryptography lives in a Rust helper, `seal-frost`, built from the pilot.** SealCore
   runs it as a child process, the way it runs `ssh-keygen` today. Two commands:
   `seal-frost keygen` (trusted dealer, RFC 9591 Appendix C, three shares, threshold two) and
   `seal-frost sign -n <namespace> -f <keyfile> <buffer>`, which takes the coordinator's own
   share and the group's public key package from Seal's support directory, reads the second share
   from stdin, and writes the SSHSIG next to the buffer, as `ssh-keygen -Y sign` would. Shares
   travel over pipes, never through arguments or the environment. Swift holds the unwrapped 🧑
   share in memory for the length of one signature and nothing else; the 🖥 share is read only by
   the helper. A static library linked into Swift was the alternative; a child process keeps the
   SwiftPM build plain, keeps `frost-ed25519` and `ssh-key` behind one small JSON contract, and
   is the shape the phone step needs anyway (a participant that is not in Seal's process).

3. **Share layout on the Mac**, under `~/Library/Application Support/seal/`:

   | File | Content | Mode |
   | --- | --- | --- |
   | `group.pub` | the group public key, one OpenSSH line | 0644 |
   | `group.json` | the FROST public key package (verifying shares and group key) | 0644 |
   | `share-mac.json` | the 🖥 share, a `frost-ed25519` key package | 0600 |
   | `share-user.sealed` | the 🧑 share, encrypted to a Secure Enclave P-256 key | 0600 |

   The 🧑 wrap: a CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey` created with
   `biometryCurrentSet`, stored by its data representation in the same file; an ephemeral P-256
   key; ECDH, HKDF-SHA256, ChaCha20-Poly1305 over the share. Unwrapping needs one key agreement
   with the enclave key, and the enclave asks for Touch ID (device password as fallback) each
   time. The Secure Enclave finding (`.scratch/seal/notes/se-key-holder.md`) applies unchanged:
   the key is not bound to the Seal binary, so any process running as the user can ask to unwrap,
   and the user still has to touch the sensor for each ask. The 🧊 share is printed once by the
   setup command and is never written to disk by Seal; the user stores it in 1Password.

4. **Approval for the group key is the unwrap.** The card's Touch ID is the Secure Enclave's own
   prompt, raised through the same `LAContext` the card's glyph is bound to. A successful unwrap
   is the Approval and yields the share for this one signature; a cancelled or failed prompt is
   Denial (exit 1). No second Touch ID follows. For the personal key the card keeps today's
   `LAContext` evaluation followed by `ssh-keygen`.

5. **The card replaces the Review for every request**, in the layout of
   `seal-frost/docs/phone-approval.md`: attestations first, then the message collapsed to its
   title with an expander, then 🐛 Problem, 💡 Why and ⚠️ Risks, then 📊 with the counts and
   `parent → tree`, then the `diff --stat` blocks and the Touch ID footer. In this step the two
   attestation lines are a stub that always shows ✅ and says so ("stub: not checked"); 🧭 After is
   omitted. Problem, Why and Risks come from the message's `Problem:`, `Why:` and `Risks:`
   trailers; a missing one shows "—". Touch ID stays the only action (Issue 09), so the card has no
   Approve, Deny or Diff buttons; Escape denies.

6. **Setup is one command, `seal setup`, run once by the user.** It calls the helper's `keygen`,
   writes the four files above, prints the 🧊 share and the group public key, and prints the hand
   steps: register the key on GitHub as a signing key, add it to `allowed_signers`, and set
   `user.signingkey` to `key::<group key>`. Seal changes no git config. It refuses to run when a
   group key already exists; re-keying is deleting the directory and running setup again, then
   registering the new key.

7. **Exit statuses are unchanged.** 0 signed; 1 denied, closed, Touch ID cancelled or git gone;
   2 Key holder failure, now also the helper failing, a share file missing or unreadable, or the
   wrapped share not unwrapping for a reason other than the user's cancel (for example biometry
   re-enrolled, which invalidates a `biometryCurrentSet` key); 3 malformed request. The failure
   message names `seal-frost` where it named `ssh-keygen`. Pass-through modes are unchanged.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Keep ADR 0001 and reach the 1Password key from the phone | The phone can only send a boolean; 1Password's own prompt cannot be answered remotely at all (seal-frost ADR 0001). |
| FROST as a static library linked into `seal` | Rust staticlib in SwiftPM needs a binary target or unsafe linker settings and puts every share in the Swift process; the phone step needs an out-of-process participant regardless. |
| Both shares as plain 0600 files, Touch ID through `LAContext` only | Approval would be Seal's own logic again, not enforced by anything; the enclave wrap makes the 🧑 share unusable without the sensor, which is what "the user is in every signature" means on a single Mac. |
| Run the whole signer in Rust as `gpg.ssh.program` and drop Seal | Loses the Review's Origin, the process tree, the card, the tests and the guard; Seal is the surface the user already trusts. |
| Keep the personal key on the daily path and use the group key only for agent commits | The design session answered "every commit": one key, one card, one `user.signingkey`. The personal key stays registered for old signatures and emergencies. |

## Consequences

- **Seal is a Key holder now.** The 🖥 share is a 0600 file readable by any process running as
  the user, and one share is below the threshold: alone it signs nothing. Together with the 🧑
  wrap it signs only after the sensor is touched. That is the exposure the design accepted.
- **Two binaries to install**: `seal` and `seal-frost`. The installer builds both (`swift build`
  and `cargo build`), so `cargo` becomes a build requirement. Seal finds the helper next to its
  own executable.
- **No key migration for the past**: existing signatures made with the personal key stay valid;
  the group key is one more `ssh-ed25519` signing key on the GitHub account and one more line in
  `allowed_signers`.
- **Losing the Mac loses 🖥 and the 🧑 copy**: with 🧊 alone nothing signs. The recovery path is a
  new group (setup again, register the new key); old signatures stay valid.
- **Re-enrolling Touch ID invalidates the 🧑 wrap** (`biometryCurrentSet`). Then setup must be run
  again, which is a new group, or the 🧊 share is fed to a re-wrap. The re-wrap command is not
  built in this step; this is a known gap.
- **Tests drive the FROST path without Touch ID**: SealCore takes the unwrapped 🧑 share as the
  content of the Approval, so tests supply a plain test share and the executable supplies the
  enclave unwrap. The enclave wrap itself is tested with a software P-256 key through the same
  code path.
- **Attestations are a stub on the card.** Until step 2, the card's ✅ lines carry no information
  and say so. Nothing in Seal is gated on them yet.
- **The phone is unaffected by this step's protocol choice**: the helper's `sign` command runs
  both participants in one process; the phone step splits it into round 1 and round 2 messages
  and adds the relay. That is a new helper command, not a change to what is built here.
