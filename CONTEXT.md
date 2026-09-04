# Seal

A macOS signing program for git that shows what is about to be signed before the signature is made. It stands in for `op-ssh-sign` as `gpg.ssh.program`, so that the approval step is also the review step, especially when an agent runs `git commit` on the author's behalf.

## Language

**Signing request**:
One invocation of Seal by git to sign a single object (a commit or a tag). What git hands over is the object body; everything shown to the author is derived from it.
_Avoid_: prompt, signing call, commit request

**Origin**:
Where a **Signing request** came from: the **Session** it was issued in, the directory, and the git command line that triggered it.
_Avoid_: caller, context, source

**Session**:
The named unit of work a **Signing request** belongs to. For an agent it is the Claude Code session, shown by its title; for a human it is the terminal application.
_Avoid_: terminal, window, tab

**Review**:
The window Seal shows for a **Signing request**: the **Origin** and the object's branch, author, message, and change summary, as a flat list.
_Avoid_: dialog, preview, confirmation screen

**Approval**:
The author's decision to sign, given inside the **Review** with Touch ID (or the device password when Touch ID is unavailable). Without it no signature is made and git creates no object.
_Avoid_: passkey, authorization, consent

**Key holder**:
The program that owns the private key and produces the signature once **Approval** is given. Today it is the 1Password SSH agent; Seal never sees the key.
_Avoid_: signer, backend, key store

**Pass-through**:
Any `gpg.ssh.program` mode other than signing (`verify`, `find-principals`, `check-novalidate`, `match-principals`), which Seal hands to `ssh-keygen` unchanged.
_Avoid_: proxy, delegation

## Relationships

- A **Signing request** gets exactly one **Review** and is signed only after one **Approval**; there is no approval that covers more than one request.
- **Approval** gates; the **Key holder** signs. Seal is the gate, not the holder.

## Flagged ambiguities

- "passkey" was used for **Approval**. Resolved: **Approval** is Touch ID inside the **Review**, not a WebAuthn credential; the word passkey is not used.
