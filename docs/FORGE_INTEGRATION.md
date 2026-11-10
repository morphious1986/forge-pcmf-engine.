# Forge integration — PCMF_IPv1 protocol (R14)

Forge connects to PCMF Living Memory as a **registered, revocable local
client** over a local AF_UNIX socket. This is an authenticated local
interface; it is NOT a ChatGPT integration and MUST NOT be presented as one.
PCMF never identifies a local client as an authenticated ChatGPT client, and
no automatic ChatGPT message hook exists or is installed by this release.

## Transport

- Socket: `$XDG_RUNTIME_DIR/pcmf/pcmf.sock` (fallback `~/.local/run/pcmf/pcmf.sock`)
- Type: `AF_UNIX`, `SOCK_STREAM`; socket mode `0600` in a `0700` directory
- Frame: two lines
  1. request JSON, single line
  2. lowercase hex HMAC-SHA256( key, request-line + "\n" ), 64 chars
- Responses: one JSON line, always containing `"canonical_writer":
  "HOLD_R241_R242"` and `"engine":"PCMF_LIVING_MEMORY_R14"`.

Direct local use without the daemon is also supported (the `pcmf` CLI uses
the identical `Engine::request()` path), so Forge may embed the same flow.

## Request envelope (v1)

```json
{"v":"PCMF_IPv1","client":"forge_local","op":"observe.submit",
 "nonce":"<32 hex chars, fresh per request>","ts":1761350000,
 "params":{ ... }}
```

- `nonce`: 16 random bytes, hex. A reused nonce with the identical logical
  request returns `DUPLICATE_NOOP` (idempotent retry). A reused nonce with
  different content is a `HOLD ... NONCE_REPLAY_CONFLICT`.
- `ts`: unix seconds; accepted window: `-300 … +120` seconds by default
  (configurable via `config.set ts_window_past/ts_window_future`).

## Client lifecycle (owner operations)

```sh
# scopes file (JSON): profiles/projects/subjects/event_classes arrays,
# subjects may use trailing-* prefixes; max_privacy is fixed to
# INTERNAL_PROJECT for non-owner clients.
cat > /tmp/forge_scopes.json <<'EOF'
{"profiles":["personal"],"projects":["general"],"subjects":["*"],
 "event_classes":["PREFERENCE","PROJECT_STATE","WORKFLOW_STATE",
 "FAILURE_GOTCHA","OBSERVATION","ROUTINE_STATE","COMMITMENT",
 "CORRECTION","REVOCATION"],"max_privacy":"INTERNAL_PROJECT"}
EOF
pcmf clients register --id forge_local --role forge --scopes-file /tmp/forge_scopes.json
pcmf clients list
pcmf clients revoke --id forge_local     # key file is destroyed
```

Registration refuses client ids containing `chatgpt`/`openai` (reserved
identity protection) and `sol*` ids while Sol integration is disabled.

## Client operations

### 1. Retrieve HOT memory before an interaction

```json
{"v":"PCMF_IPv1","client":"forge_local","op":"hot.get","nonce":"...","ts":...,
 "params":{"profile":"personal","project":"general","limit":5,
           "subject":"TeaRoutine","include_warm":false}}
```

Returns the newest **effective** event per subject (revoked and superseded
claims excluded), state-filtered to HOT (optionally + WARM), ranked newest
first, each item carrying `event_id`, `event_hash`, `sequence_id`,
`observed_at`, `summary`, `memory_state`, plus a store health block and the
active memory windows. Non-owner clients must declare `profile` and
`project`; all declared dimensions are scope-checked.

### 2. Submit a memory observation after an interaction

```json
{"v":"PCMF_IPv1","client":"forge_local","op":"observe.submit","nonce":"...","ts":...,
 "params":{"profile":"personal","project":"general","subject":"TeaRoutine",
           "domain":"DAILY_ROUTINE","event_class":"ROUTINE_STATE",
           "note":"Owner brews loose leaf tea at 07:00 on workdays",
           "privacy_class":"INTERNAL_PROJECT"}}
```

`note`: 3–700 bytes, printable; sensitive screening is deterministic
(policy unit). Verdicts:

| response `status` | meaning |
|---|---|
| `OK` + `stored:true` | admitted automatically (genuine auth + scope + privacy + writer checks passed; **no per-memory approval**) |
| `DUPLICATE_NOOP` | idempotent replay or identical content already effective |
| `REVIEW_REQUIRED` + `review_token` | sensitive/uncertain: hash-only stub queued; **raw content is never persisted before review** |
| `REJECT` | scope/policy violation (deterministic reason) |
| `HOLD_INTEGRITY_OR_AUTHORITY` | auth, replay, time-window, or store-integrity failure (fail closed) |

Corrections and revocations are ordinary events referencing a prior event:

```json
{"op":"observe.submit","params":{"event_class":"CORRECTION",
 "ref_event_id":"<64-hex event id>","note":"...", ...}}
{"op":"observe.submit","params":{"event_class":"REVOCATION",
 "ref_event_id":"<64-hex event id>","note":"...", ...}}
```

### 3. Verification and proofs

- `store.verify` — chain + index health
- `store.replay` — full replay, index rebuild comparison, exact readback
- `proof.get {"event_id":...}` — memory proof packet (chain anchors,
  ledger hash, index membership, verification timestamp); also persisted
  under `<root>/proofs/<event_id>.json`
- `memory.state` — HOT/WARM/COLD/DORMANT subject census

### 4. Owner-only operations (owner role)

`client.register`, `client.revoke`, `client.list`, `review.list`,
`review.resolve`, `store.recover`, `backup.create|verify|restore`,
`config.get|set`, `sol.enable|disable`, `profiles.add`.

## Sensitive-memory review flow

1. Forge submits sensitive content → `REVIEW_REQUIRED` + `review_token`.
   Only a stub (hash, size, scope, reason) is stored.
2. Owner inspects `pcmf review list` (stub only) and decides:
   - `allow_rule`  → this (client, profile, project, subject, domain, class)
     combination auto-admits in future as `privacy_class=REVIEWED_SENSITIVE`
   - `allow_once` + exact content → admits that one item (hash must match
     the reviewed stub; content swapping is rejected)
   - `reject` → future matching content is deterministically rejected

## Error taxonomy (fail-closed)

`PROTOCOL_VERSION_UNSUPPORTED`, `REQUEST_NOT_VALID_JSON`,
`SIGNATURE_FORMAT`, `SOURCE_SIGNATURE_INVALID`, `UNKNOWN_CLIENT`,
`CLIENT_REVOKED`, `EXPIRED_OR_FUTURE_REQUEST`, `NONCE_REPLAY_CONFLICT`,
`SCOPE_*`, `OWNER_AUTHORITY_REQUIRED`, `SOL_INTEGRATION_DISABLED`,
`STORE_UNHEALTHY`, `INDEX_PREIMAGE_MISMATCH`, `LEDGER_*`,
`SUBJECT_DOMAIN_CONFLICT`, `CONTENT_DUPLICATE`, `SENSITIVE_CONTENT_DENIED_BY_OWNER`.

Any response or log line from PCMF carries `canonical_writer:
HOLD_R241_R242` — Forge must treat this as a constant of the system.
