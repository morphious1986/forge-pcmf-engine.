# HISTORICAL R14 DOCUMENT (reference only)
This document records an older development checkpoint and is not the live R17/R244 release contract. See the repository root README.md and CHANGELOG_PUBLIC.md for the current community source scope.

# Remaining deployment and authentication holds (R14)

These gates are intentionally left closed. Everything that could be built,
tested, and verified independently of owner authorization and external
systems HAS been completed and verified (see `TEST_REPORT.md`).

## 1. Canonical Library writer — `HOLD_R241_R242` (owner authorization)

Untouched and preserved. R14 has **no code path** to any canonical Library
store; the hold constant is echoed in every response. The R10 README gate
"Preserve R241/R242 Library canonical writer hold until independent
cross-location owner/namespace/current-generation reconciliation is proven"
remains exactly as it was.

## 2. Existing production PCMF service — cutover requires owner authorization

On the owner's machine the existing live PCMF service must remain
operational until a verified, authorized replacement. The R14 installer
implements the complete replacement protocol (verify → protect → install →
test → cutover → cleanup, with rollback) but **refuses** to replace an
active service without `--authorize-cutover` / typed
`I AUTHORIZE CUTOVER`. Until the owner runs that authorized cutover,
R14 installs side-by-side and reports
`HOLD_SERVICE_CUTOVER_NOT_AUTHORIZED`.

## 3. Actual ChatGPT automatic hook — NOT installed, NOT verified

No component of R14 intercepts ChatGPT (or any other) traffic. Client
registration rejects ChatGPT-impersonating identities
(`RESERVED_IDENTITY_IDS_FORBIDDEN_NOT_CHATGPT`), and all event source types
explicitly declare `LOCAL_CLIENT_SIGNED_NOT_CHATGPT` /
`OWNER_LOCAL_SIGNED_NOT_CHATGPT` with `content.origin=LOCAL_CLIENT_NOT_CHATGPT`.
Connecting the supported GPT-side interface remains a separate owner task:
register a Forge-controlled conversation producer via
`pcmf clients register` and connect it to the documented PCMF_IPv1
interface (docs/FORGE_INTEGRATION.md). Mini MCP transports establish bounded
calls only — automatic all-message capture is neither claimed nor provided.

## 4. Sol production integration — NOT authorized (disabled by default)

The full adapter contract is implemented and tested (native test
`sol_adapter_flow`), but `sol` clients are refused until the owner runs the
two-gate authorization (`pcmf sol enable` + typed
`I AUTHORIZE SOL INTEGRATION` in the setup menu, then client registration).
Sol-side adapter development is out of scope until Sol exists.

## 5. Service activation in sessions without systemd user scope

On systems without a systemd user session (or without linger), the service
cannot be auto-started. The installer reports
`HOLD: SERVICE_NOT_ACTIVATED`; the daemon runs in foreground mode instead
(fully functional). This is an environment constraint, not a defect.

## 6. Owner-machine-only verifications

The following were proven here with disposable synthetic data and must be
re-confirmed once on the owner's production-equivalent environment before
any cutover (gate #4 of the R10 checklist):

- no competing R55 Python/Node writer during admission (production
  equivalence)
- single-writer fencing under the production directory layout (verified
  here on the same code path)
- cross-location owner/namespace reconciliation (R241/R242 prerequisite)

## Disposition

`NATIVE_R14_COMPLETE`, `PRODUCTION_CUTOVER_AWAITING_OWNER_AUTHORIZATION`,
`REAL_CONVERSATION_INGRESS_NOT_VERIFIED`, `SOL_NOT_AUTHORIZED_DISABLED`,
`CANONICAL_WRITER_HOLD_R241_R242`.
