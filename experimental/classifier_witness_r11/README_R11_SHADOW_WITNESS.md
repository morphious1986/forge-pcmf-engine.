# PCMF deterministic classifier R11 — witnessed shadow experiment

Date: 2026-11-13. Owner problem: approval prompts trigger too often on routine technical state and long numeric strings.

## Verified native root cause
The canonical C11 `pcmf_policy.c` screens unlabeled numeric tokens with 9+ digits over a maximum span of 20. A compact `build_timestamp=YYYYMMDDHHMMSS` or `build_id=12345678901234` can therefore generate `POTENTIALLY_SENSITIVE_CONTENT` even in an otherwise ordinary technical note. The baseline accepts 64-digit checksums already, so do not claim hashes generally trigger review. Actual contents of the 13 old hash-only pending reviews cannot be reconstructed; 11 had reason `POTENTIALLY_SENSITIVE_CONTENT`, one size/uncertain and one privacy-class gate.

## Implemented experimental branch
- `pcmf_policy_baseline.c` is the exact **unmodified** native R14 C11 baseline.
- `pcmf_policy.c` is an **isolated C11 shadow** with constrained exemptions for exact `build_timestamp` (14 digits with bounded valid date/time), `build_id` and `ci_run_id` (9–20 digits), and strictly bounded SHA-256-labeled tokens (already ordinarily accepted by baseline).
- Prefix collisions, unlabeled numbers, credential labels, private-key disclosures, account-number disclosures, and invalid timestamps remain conservative.
- `test_shadow_r11.c` compiles separately with both policies. `witness_harness_r11.py` is **research/test harness only**, not part of the production C11 engine.
- Witness report is deterministic, reproducible and does not store raw production notes, private tokens, or credentials.

## Evidence as of R11
- 21/21 baseline synthetic cases PASS; 21/21 shadow cases PASS.
- 3 changed outcomes: labeled build timestamp, numeric build ID and CI run ID; baseline Review -> shadow Auto-Admit Eligible.
- 14 synthetic cases that baseline review-gated remain review-gated by shadow.
- The source also reveals a possible semantic false positive in a sentence about a disabled password prompt. No exception is enabled for this yet.
- No real owner-reviewed examples have been collected or labeled. **These synthetic results do not establish a production false-positive rate.**

## Proposed governed witness learning design
1. At proposal time, retain **metadata**: decision reason ID, recognized technical/personal signal class, policy version hash, project/domain, and an opaque request ID. Never use the unredacted candidate as an observation log.
2. When an owner explicitly classifies a request, add an authenticated witness with narrow reason labels (`FALSE_POSITIVE_TECHNICAL_IDENTIFIER`, `TRUE_POSITIVE_SENSITIVE`, `UNKNOWN`), source provenance, policy fingerprint, and a stable opaque candidate digest. **Unreviewed and missing-text legacy requests are not positive or negative labels.**
3. Aggregate counts by precise rule + trusted project context and compare baseline vs shadow. Record false positives, false negatives, uncertain examples, and abstentions. Owner overrides remain authoritative; classifier output cannot approve memory.
4. Propose a bounded, versioned policy change only after a sufficient and representative labeled sample, adversarial regression suite, and explicit owner promotion. Thresholds must be chosen and reviewed with measured error costs—not guessed.
5. Any promotion has a revertible version hash and continued shadow/production drift monitoring. Hard credential, privacy, integrity, scope and writer-authorization gates always precede technical exemptions.

## Strict boundaries
This is **NOT deployed to native PCMF**, not linked into canonical engine or Sol. No production review queue, pending token, memory, credential, model routing, or native writer was changed. Existing owner UI R10 remains active. Do not promote from a synthetic-only witness report. Restore production behavior by simply leaving the shadow source uninstalled.
