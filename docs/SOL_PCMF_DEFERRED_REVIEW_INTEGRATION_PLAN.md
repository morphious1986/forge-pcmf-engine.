# Planned Sol ↔ PCMF deferred owner-review integration

**Status:** design and acceptance contract only. No Sol runtime, router, model, inference lease, or production memory writer is modified by this document.

## Current boundaries
- PCMF already exposes a governed memory interface and a native local-model adapter; this does **not** mean the new owner Control Center deferred-review workflow is integrated into Sol.
- PCMF is the sole authority for admission and review-token state. Sol must not own or reproduce the canonical memory ledger.
- The Control Center's encrypted inbox is owner-opt-in only. A historical hash-only pending request cannot be reconstructed from its digest.

## Proposed Sol lifecycle
1. Sol proposes a bounded candidate memory (not a credential, raw transcript, or unrestricted hidden scratchpad), with provenance and an idempotent request ID.
2. The PCMF governed submitter classifies it. Non-sensitive requests follow normal deterministic admission. If `REVIEW_REQUIRED`, the authorized submitter receives a 64-hex pending token bound to the canonical root ID and original content digest.
3. The owner can opt in to encrypted capture. Without opt-in, Sol **must not persist** the candidate outside its ordinary, short-lived request context. The deferred inbox only accepts an exact-note hash and byte-length match with the live pending stub.
4. Later, the Control Center requires owner passphrase unlock and checks that the review remains current before and after decryption.
5. A separate **native OS-authenticated owner-review** step authorizes a specific note or rejects it. `reject_once` must not be simulated through the legacy broad-deny `reject` operation.
6. On authorization, the original submitting client may resubmit the exact note through PCMF's canonical governed path using idempotency and root identity checks. **Authorization does not imply admission** until independently read back.
7. If rejected, deferred, or unanswered, that memory is not admitted; independent authorized Sol project tasks may continue. CPU/GPU leases, model ownership, safety, security, and deployment authorizations remain independent.
8. Every state transition is auditable by non-secret metadata. No secret keys or raw sensitive notes in public logs, source control, or global assistant memory.

## Release prerequisites
- Owner-approved encrypted capture settings and passphrase/key lifecycle; default off.
- Synthetic Sol submitter harness, token-race/adversarial tests, duplicate/retry tests, and explicit fail-closed behavior.
- Native reviewer challenge tested end-to-end with a disposable PCMF instance and synthetic note, then separately owner-verified against canonical production.
- Independent security review of secure retention/expiry, stale escrows, process isolation, filesystem permissions, and sensitive-note zeroization limitations.
- Explicit owner authorization for Sol-facing runtime integration and any production engine cutover; production Sol/router remain unmodified until these gates pass.

This design does not authorize model inference or service preemption.
