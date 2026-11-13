# PCMF R12 — governed witness learning + 72-hour encrypted missed-proposal queue

Date: 2026-11-13. Owner intent: reduce false-positive approvals by learning from authenticated outcomes, and prevent indefinitely pending, unreviewable memory proposals. A missed proposal must retain its exact original text for at most 3 days, then be discarded and denied *for that proposal*.

## Proven implementation

**Witness evidence (experimental):** `witness_ledger_r12.py` stores only metadata and Ed25519 owner-signed review labels in a private append-only SHA256-linked journal. Tampering, truncated journals, forged signatures, duplicate review receipts, case replay, wrong policy root and wrong version cause hard failure. Classification labels include `FALSE_POSITIVE_TECHNICAL`, `TRUE_POSITIVE_SENSITIVE`, `UNKNOWN`. `propose()` can suggest narrow rule candidates after representative signed evidence, never change or authorize canonical PCMF policy. Public-key trust pin must come from a separately authenticated owner-controlled setup; the tests only create synthetic signing keys.

**Exact-note deferred queue (experimental):** `deferred_queue_r12.py` creates an owner-controlled X25519 recipient key, encrypted at rest by a passphrase-derived AES-GCM/Scrypt key. A submitting client can encrypt exact note text under the recipient public key *only after the owner enables capture*. A trusted authenticated PCMF pending lookup callback must establish pending root ID/token, exact SHA256 and UTF-8 byte count before and after capture. Neither the original note nor the owner private key is written in plaintext. Files use 0700 directories, 0600 files, and atomic fsync writes.

**72-hour TTL:** the expiration deadline is fixed on enqueue, exactly 259200 seconds after capture. `unlock()` and `list_available()` fail closed at the deadline. `sweep()` removes expired encrypted note files and writes a small metadata-only per-proposal tombstone `EXPIRED_DENIED_THIS_PROPOSAL_LOCAL_ONLY`, preventing the UI from treating that exact request as actionable. The sweep helper `queue_gc_r12.py` requires a mode-0600 owner configuration with an explicit enabled flag and root ID. The supplied user-systemd service/timer samples sweep every minute and on reactivation. They are **not installed or enabled** in the production user session.

**Very important limits:**
- A timer may run late or the computer may be offline. Authorization is blocked immediately once 72 hours elapse, but the encrypted file is physically unlinked at the next GC invocation. Do not claim physical erasure at exactly the deadline.
- File unlink is not guaranteed secure erasure on SSDs, snapshots, backups, exFAT media, or copy-on-write filesystems. The private key and recovery backups also require a separate lifecycle/erasure policy.
- `EXPIRED_DENIED_THIS_PROPOSAL_LOCAL_ONLY` is a local exact-item tombstone **not** native PCMF `rejected` status. Native PCMF's current `reject` can issue broad future-deny effects. Canonical per-item expiry/cancel API and governed integration are still required.
- Owner permission to retain arbitrary notes is **not enabled by default**. The submission adapter, owner UI, root/issuer authentication, safe production key enrollment, and native audit linkage are future integration gates.
- No old hash-only pending review can be reconstructed. The 13 legacy PCMF pending requests remain canonical, unchanged.
- Witness approvals are not learned automatically. A classifier may propose change candidates after authenticated owner labels; promotion requires explicit owner authorization and adversarial validation.
- User systemd timer is a deployment *template* only; no existing machine service, native writer, model runtime, or Sol configuration is modified.
- The current implementation is an isolated prototype. A production security review must examine concurrent enqueue/sweep transactions, clock rollback, key backup/recovery, timer lifecycle, and process-memory handling.

## Reproduce

On TechMagnet Ubuntu with Python cryptography:
`python3 -m unittest discover -s . -p 'test_*.py' -v`

The R12 test suite covers signed witness replay, tamper/duplicate protection, context gating, encrypted note roundtrip, wrong-owner-key refusal, explicit capture opt-in, exact hash mismatch, 72-hour cutoff and timestamp-bound cleanup.

This directory contains test binaries from local builds only; release source archive should include source/tests/README/scheduler templates and SHA256 manifest, excluding binaries, cache and any private owner key material.

## Next development gates

1. Build a native PCMF per-token **expire/cancel** operation that leaves a governed immutable event but never installs broad rejection, with replay and owner authorization testing.
2. Add authenticated submitter integration that provides exact notes to the X25519 owner-public-key queue atomically with native pending generation. Fail closed without explicit owner opt-in.
3. Add the Control Center owner UI for key setup, per-item countdown, encrypted unlock, explicit accept/reject, and status distinction between `READY`, `NEEDS_ORIGINAL` and `EXPIRED`.
4. Run simulated restart/offline/adversarial retention tests. Then install and enable GC with owner approval, verify a real synthetic token end-to-end, and read back canonical state.
5. Integrate signed witness labels with the native classifier decision reason IDs and versioned review receipts. No automatic promotion into live PCMF policy.
