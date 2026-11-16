# PCMF: Status Language and Semantic Round-Trip Reliability

Status: **public engineering lesson / proposed protocol guidance**, not a production release.
Scope: model-facing project status, governed continuity, handoff and recall.

## Problem

An LLM can write a status with one intended meaning, a memory engine can preserve
the exact bytes, and a later LLM session can assign it a different operational
meaning. In the documented development case, a phrase intended to mean
"incomplete; continue permitted engineering work" was later read as a
project-wide instruction to stop. No underlying authorization or integrity
policy had changed.

This is a **temporal semantic round-trip failure**:
write -> persist -> recall -> interpret. Byte-for-byte preservation is necessary
for provenance but insufficient for preservation of operational meaning.

## Separate progress from governance

Progress indicators should communicate *what remains to do*, for example:

- `MORE_DEVELOPMENT_NEEDED`
- `TESTING_NEEDED_FOR_NEXT_STEP`
- `VERIFICATION_NEEDED`
- `READY_FOR_NEXT_STEP`
- `STAGED_NOT_DEPLOYED`

Actual authority gates must remain explicit and enforceable:

- `REVIEW_REQUIRED`
- `OWNER_APPROVAL_REQUIRED`
- `INTEGRITY_BLOCKED`
- `AUTHORITY_BLOCKED`

A progress term is not an authority grant. A governance gate may not be
bypassed by rewording it; conversely, an ordinary progress term must not
implicitly create a stronger prohibition than the real authority state.

## Proposed enforcement contract

1. Represent current model-facing status as a finite, versioned field rather
   than free-form prose alone.
2. Bind it to a clear, typed operational meaning and permitted-next-action
   semantics, subject to separate authorization.
3. Reject ambiguous proposed *progress* statuses with a deterministic
   `REWORD_REQUIRED` response and suggested accepted vocabulary. This is
   a pre-admission validation response, **not** owner approval.
4. Keep original historical wording immutable as provenance.
5. Regression-test the full write/persist/recall/interpret cycle, including
   later sessions and alternate model-context interpretations.
6. Ensure every enforcement path preserves independent security,
   privacy, and owner-approval checks.

## Engineering provenance and limits

Derived from the local PCMF language-semantics study committed as
`b8cfa8f` and refined by `d78c58b` (2026-11-13) in an isolated
development history. This public article intentionally excludes local
machine paths, owner identifiers, live memory content, keys, and connector
configuration.

The internal study recorded synthetic/native test claims, but those are not
a reproducible external acceptance report. The protocol proposal here does
**not** assert that production engines enforce it, nor grant automatic
admission or model/tool execution.

The generalizable lesson applies to memory engines, recovery documents,
agent handoffs, tool receipts, and long-running project state.
