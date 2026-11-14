# PCMF R245 — Isolated Development Update

Publication status: **source-review information only**. The R245 work described here has **not** been integrated into the public R244 production source, approved for deployment, or released as a supported build.

## Development progress

The latest isolated PCMF candidate explores relevance-ranked memory retrieval with explicit client-scoped access constraints. The goal is to improve retrieval usefulness without weakening provenance, privacy classification, or owner-governed admission.

The candidate also includes additional regression coverage for compatibility, invalid-input handling, access constraints, and release-test isolation. A separate status-language study addresses the risk that later model sessions reinterpret a persisted progress label as an authorization decision.

These are distinct areas of work. Retrieval does not confer writer rights or owner approval. Model-facing status language cannot override governance gates.

## Recorded isolated-development verification

| Verification area | Recorded result |
| --- | --- |
| Native self-tests in disposable environments | 35/35 passed |
| Search-adapter compatibility and negative tests | 7/7 passed |
| Guard regression tests | 11/11 passed |
| Isolated release verification | Passed |
| Isolated sanitizer-based tests | Passed |
| R245 production integration | Not performed |

These are **internal development findings**, not independently reproduced community results, a security certification, or proof of production readiness.

## Material excluded from this public update

**No R245 runtime implementation or integration scripts are included.** No deployment commands, private engineering receipts, live memory, credentials, operational paths, or environment-specific configuration are included. Local repair and control procedures remain private until independently reviewed and explicitly selected for public source publication.

## Next acceptance conditions

1. Create a separate source-only candidate from a per-file allowlist and clean public history.
2. Obtain independent code and security review before adopting the implementation.
3. Run reproducible isolated tests, including privacy, crash/recovery, and negative paths.
4. Keep release acceptance and owner authorization independent of GitHub publication.
5. Publish only reviewed portable material and synthetic examples.

The status-language research has its own public documentation-only review. The repository `SECURITY.md` governs private reporting of vulnerabilities.

**GitHub visibility is not deployment authorization.**
