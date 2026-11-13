# PCMF Control Center R2 — deferred review and project-continuation contract

Status: **development candidate / community review**, not a production cutover.

## Scope
The PCMF owner controls whether a proposed memory is stored. This is separate from permission to continue project work. A deferred, declined, or unanswered memory cannot independently suspend already authorized project activity. Independent execution safeguards (including exclusive resource leases, credentials, destructive operations, deployment, or safety gates) remain authoritative.

### Review states
- `PENDING`: a hash-only request stub remains available after a missed notification. It is not approved.
- `AUTHORIZED`: the owner authorized a request, but original exact-content resubmission and admission may still be required.
- `CONSUMED`: approved submission was admitted and its review authorization was consumed.
- `REJECTED_ONCE`: reject exactly one proposed memory without creating a future allow/deny rule. This operation is implemented and regression-tested in an isolated native candidate, **not released to production**.
- `DEFERRED`: user interface leaves the existing pending stub unchanged, with no admission or classifier effect.

## Privacy boundaries
The deployed review queue holds metadata and a content digest, **not the original sensitive note**. It is not possible to reconstruct the note from the digest. Therefore missed-window review currently requires the owner or original submitting client to supply the exact original entry again. A future deferred-content escrow would require an independently reviewed threat model and owner-controlled encryption; no unapproved raw note should be written to logs, UI history, Git, or the review queue.

## Classification advisor
Owner decision history can produce non-binding suggestions when similar, metadata-matched requests repeatedly receive approval. Suggestions must never change sensitivity, admit content, create `allow_rule` entries, or override protected categories by themselves. Owner confirmation and a separate classifier regression suite are required before a rule change.

## Release/evidence boundaries
The R2 GTK desktop viewer, policy advisor, and isolated native `reject_once` candidate were tested privately. This public branch is **source-review material** only; it does not contain personal memory, instance identifiers, local mount points, keys, production binaries, private archive manifests, or deployment instructions for a live machine. A local isolated installer test succeeded, but independent release/cutover review is still required.

## Acceptance requirements for a future production release
1. Owner-approved exact-entry review with deferred retrieval; verify no raw sensitive content leaks into pending metadata.
2. `reject_once` must touch one token and create no future denial rule.
3. A subsequent similar memory must still receive normal classification and review.
4. Storage rejection must not alter independent execution authorization.
5. No automatic declassification, no unattended approvals, and no unsafe inference lease bypass.
6. Reproducible tests, portable install/uninstall checks, rollback, and owner-authorized cutover.
