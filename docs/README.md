# HISTORICAL R14 DOCUMENT (reference only)
This document records an older development checkpoint and is not the live R17/R244 release contract. See the repository root README.md and CHANGELOG_PUBLIC.md for the current community source scope.

# PCMF Living Memory R14 — native C11/C++20 completion

Recorded: 2026-10-24 (America/New_York). Build: `PCMF_LIVING_MEMORY_R14`.
Canonical Library writer hold: **`HOLD_R241_R242`** — preserved everywhere,
never bypassed, echoed in every response and proof packet.


## R244 explicit tier writes

R244 adds governed client-scoped tier.set transitions for existing subjects.
Forge/ChatGPT and Sol may set HOT/WARM/COLD only inside their already-authorized
profile/project/subject scope. The transition is appended as a TIER_CHANGE
event under the writer lock; memory content is not rewritten. This does not
grant owner authority. The ChatGPT connector exposes pcmf_tier_write, intended
only for explicit user-directed tier requests. The older pcmf_tier_request
staging operation remains for compatibility and still does not mutate memory.

The package also ships the matching Sol adapter under integrations/sol/app/.

## What this is

PCMF (Personal Canonical Memory Fabric) Living Memory is an **evidence-based
memory engine** — not a transcript database and not a generic RAG system.
Memory is admitted only through deterministic, authenticated, policy-gated
events in a tamper-evident hash-chained ledger; every admission is
reproducible, verifiable, and provable after the fact.

R14 **continues and completes** the existing PCMF implementation lineage
(R9 classifier → R10 writer → R11/R12/R13 native verification). It does not
start a new system. The historical R9/R10/R13 sources are shipped unmodified
under `legacy/`, and the R9 policy classifier, the R55 canonical event schema
(`pcmf.deterministic.event.v2`), the collection-index schema, the writer
fencing, and the atomic ledger-then-index commit order are all preserved.

## Capabilities (all native, no Python/Node/network)

- Deterministic memory admission with source authentication (HMAC-SHA256)
- Event + witness tracking, hash-chained ledger with per-stream sequences
- Claim/state reconstruction: corrections supersede, revocations retract
- Subject and project isolation; profile-scoped clients
- Chronological memory with HOT / WARM / COLD / DORMANT states
- Relevant HOT retrieval **before** model interactions (`hot.get`)
- Controlled admission **after** interactions (`observe.submit`)
- Sensitive-content review queue — raw sensitive content is **never**
  persisted before owner review (hash-only stubs)
- Duplicate detection (content + nonce idempotency), conflict handling
- Durable storage: fsync + atomic rename, single-writer flock fencing
- Crash recovery: interrupted pairs fail closed; index always derivable
- Ledger integrity verification, full replay with exact readback
- Memory proof packets (`proof.get`)
- Clear failure and authorization states (structured JSON reasons)

## Layout

```
bin/        pcmf (CLI), pcmf-serve (daemon), pcmf-setup (menu), pcmf-selftest
src/        policy (C11), self-contained SHA-256/HMAC (C11), JSON, engine (C++20)
tests/      native selftest suite (33 tests)
scripts/    build.sh test.sh install.sh uninstall.sh usb_export.sh package_release.sh
systemd/    pcmf.service (user unit template)
docs/       README (this file), FORGE_INTEGRATION.md, SOL_INTEGRATION.md,
            OPERATIONS.md, TROUBLESHOOTING.md, HOLDS.md, TEST_REPORT.md
legacy/     R9/R10/R13 sources, unmodified (verified baseline)
```

## Quick start

```sh
scripts/build.sh                 # build all four native binaries
scripts/test.sh                  # full verification incl. baseline + installer
./bin/pcmf init --root ~/.local/share/pcmf
./bin/pcmf observe --subject TeaRoutine --domain DAILY_ROUTINE \
    --class ROUTINE_STATE --note "Prefers loose leaf tea at 7am"
./bin/pcmf hot --project general
./bin/pcmf-setup                 # the 16-function administration menu
```

## Governance preserved

| Gate | Status in R14 |
|---|---|
| Canonical Library writer | `HOLD_R241_R242` — no code path exists to any canonical store |
| ChatGPT automatic hook | Not installed, not claimed; client ids may never impersonate ChatGPT/OpenAI |
| Mini Commander | PCMF is fully independent; no OS grants required or requested |
| Sol production | Disabled by default; explicit owner authorization flow only |
| Live PCMF ledger | Never touched; all tests use disposable synthetic roots |

See `HOLDS.md` for the precise list of operations that still require owner
authorization or external integration.

## Turn flow (Forge / future Sol)

1. **Before** a model interaction: authenticated client calls `hot.get`
   (PCMF_IPv1) and receives relevant HOT memory with proof anchors.
2. **After** the interaction: client calls `observe.submit` with the
   observation; the engine admits eligible memory automatically (no
   per-memory approval), holds sensitive candidates for review, and returns
   a structured verdict + evidence.
3. Periodically or on demand: `store.verify`, `store.replay`, `proof.get`,
   `backup create`.

Protocol details: `docs/FORGE_INTEGRATION.md`.
