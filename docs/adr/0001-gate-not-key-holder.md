# 0001: Seal is a gate in front of the 1Password key, not a key holder

Status: accepted
Date: 2026-09-04

## Context

Git signs every commit and tag through `gpg.ssh.program`, which today is `op-ssh-sign`. 1Password asks for Touch ID but shows nothing about what is being signed, so an agent-run `git commit` is approved blind. The original Issue asked for a "passkey" instead of the 1Password prompt. Three ways to own the approval exist:

- Keep the key in 1Password and put a Review in front of it.
- Move the key into the Secure Enclave, bound to Touch ID, and sign inside Seal.
- Keep a software key on disk, gated by Touch ID in Seal.

## Decision

The key stays in 1Password. Seal shows the Review, takes Approval with Touch ID through LocalAuthentication, and only then runs `ssh-keygen -Y sign` against the 1Password agent socket. Seal never holds or sees a private key and implements no cryptography. Every non-signing mode is a Pass-through to `ssh-keygen`.

## Consequences

- No key migration: `allowed_signers`, GitHub, and existing signatures keep working.
- 1Password still asks for its own approval once per terminal session until it locks; Seal's Review is the per-object gate on top of that.
- The gate is Seal's own logic, not hardware. A process that calls the 1Password agent directly is not stopped by Seal; that is the same exposure as today, and Seal adds visibility rather than a stronger key.
- Moving to a Secure Enclave key later is a new Key holder behind the same Review, plus a key migration.
