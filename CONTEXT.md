# Seal

A macOS signing program for git that shows what is about to be signed before the signature is made. It stands in for `op-ssh-sign` as `gpg.ssh.program`, so that the approval step is also the review step, especially when an agent runs `git commit` on the author's behalf. Since ADR 0002 it also holds one share of a threshold group key and coordinates the group's signature.

## Language

**Signing request**:
One invocation of Seal by git to sign a single object (a commit or a tag). What git hands over is the object body; everything shown to the author is derived from it.
_Avoid_: prompt, signing call, commit request

**Origin**:
Where a **Signing request** came from: the **Session** it was issued in, the directory, the git command line that triggered it, and the Paseo agent id (`PASEO_AGENT_ID`, when set and not empty). The agent id selects the **Agent path** and authenticates nothing.
_Avoid_: caller, context, source

**Session**:
The named unit of work a **Signing request** belongs to. For an agent it is the Claude Code session, shown by its title; for a human it is the terminal application.
_Avoid_: terminal, window, tab

**Card**:
The window Seal shows for a **Signing request**: the **Origin**, the **Attestation** lines, the message collapsed to its title, the Problem, Why and Risks trailers, the change counts with the parent and tree hashes, and the change summary. It replaced the **Review** (ADR 0002); the word Review names the pre-0002 window only.
_Avoid_: dialog, preview, confirmation screen, review

**Approval**:
The author's decision to sign, given inside the **Card** with Touch ID (or the device password when Touch ID is unavailable). For the **Group key** it is the Secure Enclave unwrapping the **User share**, and it carries that share for one signature; for the personal key it is a LocalAuthentication evaluation. Without it no signature is made and git creates no object.
_Avoid_: passkey, authorization, consent

**Key holder**:
What produces the signature once **Approval** is given. For the **Group key** it is the FROST group: Seal's **Mac share** and the **User share**, aggregated by the helper `seal-frost`. For the personal key it is the 1Password SSH agent through `ssh-keygen -Y sign`, and Seal never sees that key. On the card path the key git names with `-f` selects the holder; on the **Agent path** the **Notary** is the holder, with its own key, whatever `-f` names.
_Avoid_: signer, backend, key store

**Group key**:
One Ed25519 public key whose private key exists only as three FROST **Shares**, threshold two. Registered on GitHub as a signing key and listed in `allowed_signers` like any `ssh-ed25519` key; its signatures are ordinary Ed25519 signatures.
_Avoid_: threshold key, shared key, multisig

**Share**:
One of the three FROST key packages of the **Group key**: the **User share** (🧑), the **Mac share** (🖥), and the **Recovery share** (🧊). Any two sign; only the first two are on the signing path.
_Avoid_: fragment, piece, key part

**User share**:
The author's **Share**. On the Mac it exists only as a **Sealed share**; a phone copy comes later.

**Mac share**:
Seal's **Share**, a 0600 file under `~/Library/Application Support/seal/`. Alone it signs nothing.

**Recovery share**:
The third **Share**, printed once by `seal setup` for the author to store offline (1Password). Never written by Seal, never on the signing path.

**Sealed share**:
The **User share** encrypted to a Secure Enclave P-256 key created with `biometryCurrentSet`, so that unwrapping needs Touch ID each time. The file `share-user.sealed` holds the enclave key's blob, the ephemeral public key and the ciphertext.
_Avoid_: wrapped share, encrypted share, blob

**Attestation**:
A stage's signed statement over the commit's parent and tree (implementer, reviewer), shown at the top of the **Card**. In the current step the two lines are a stub that always shows ✅ and says "stub: not checked"; nothing is gated on them yet.
_Avoid_: approval, sign-off, review result

**Helper**:
The `seal-frost` executable next to `seal`: the dealer that generates the **Group key** and the coordinator that runs both FROST rounds and writes the SSHSIG. **Shares** reach it through pipes only.
_Avoid_: signer, backend

**Notary**:
A local service under the author's account (Desk `bin/notary`) that listens on `~/Library/Application Support/notary/notary.sock`, holds one plain `ssh-ed25519` key, and signs or refuses each request it is sent (seal-frost ADR 0003). The protocol is the contract in `~/dev/ws/desk/docs/notary-protocol.md`.
_Avoid_: signing server, daemon

**Agent path**:
What Seal does with a **Signing request** whose **Origin** carries a Paseo agent id: it forwards the request to the **Notary** as one JSON line and writes the signature the notary returns to `<buffer>.sig`. No **Card** opens and no **Approval** is asked for; the notary's refusal or error ends it with the same exit statuses as the card path. The request carries no key: the notary signs with its own key whatever `-f` names, so `user.signingkey` stays the personal key in every repository.
_Avoid_: dialog path, headless mode

**Pass-through**:
Any `gpg.ssh.program` mode other than signing (`verify`, `find-principals`, `check-novalidate`, `match-principals`), which Seal hands to `ssh-keygen` unchanged.
_Avoid_: proxy, delegation

## Relationships

- On the card path (no Paseo agent id) a **Signing request** gets exactly one **Card** and is signed only after one **Approval**; there is no approval that covers more than one request. On the **Agent path** there is no **Card**; the **Notary** decides.
- **Approval** gates; the **Key holder** signs. For the **Group key** Seal is both the gate and one of the two **Share** holders on the path; the **User share** is the author's, unlocked by the sensor, so no signature exists without the author.
- A **Signing request** takes either the **Card** or the **Agent path**, never both; `PASEO_AGENT_ID` alone decides which.
- The **Group key**'s signatures and the personal key's are verified the same way; the personal key stays the value of `user.signingkey` in every repository and signs on the card path wherever `-f` does not name the **Group key**.

## Flagged ambiguities

- "passkey" was used for **Approval**. Resolved: **Approval** is Touch ID inside the **Card**, not a WebAuthn credential; the word passkey is not used.
- "Review" survives in code comments and Issues written before ADR 0002. Resolved: it names the old window; new text says **Card**.
