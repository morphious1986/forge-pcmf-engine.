# Future Sol integration — adapter contract (R14)

Status: **DISABLED BY DEFAULT**. Sol production integration is NOT
authorized. Sol is not assumed to be installed, and this release contains no
Sol components. Everything below is the prepared, tested adapter contract so
that connecting Sol later requires only configuration — not new engine work.

## Design position

Sol will connect through the **same PCMF_IPv1 protocol** Forge uses — there
is no separate Sol API to maintain. A Sol adapter is therefore just a local
client with `role=sol`, a dedicated key, and its own scopes.

## Enabling (explicit owner authorization, two gates)

Gate 1 — integration flag:

```sh
pcmf sol enable
# engine requires the owner-issued op; writes state/sol_authorized.json
# {"sol_integration":"enabled","authorized_by":"owner",
#  "authorization":"OWNER_EXPLICIT_AUTHORIZATION", ...}
```

Gate 2 — client registration (`sol*` ids are refused while disabled):

```sh
pcmf clients register --id sol_adapter --role sol --scopes-file /tmp/sol_scopes.json
```

Disabling (`pcmf sol disable`) immediately blocks every `sol`-role client at
request time (`SOL_INTEGRATION_DISABLED`), independent of keys.

## Adapter contract (identical to Forge)

| Concern | Contract |
|---|---|
| Transport | AF_UNIX socket `0600`, PCMF_IPv1 frames (see FORGE_INTEGRATION.md) |
| Before interaction | `hot.get` — relevant HOT memory, proof anchors included |
| After interaction | `observe.submit` — deterministic admission, no per-memory approval for eligible nonsensitive content |
| Sensitive content | Same review queue and owner rules as Forge |
| Corrections/revocations | `CORRECTION`/`REVOCATION` events with `ref_event_id` |
| Replay protection | Per-request nonce + timestamp window, uniform for all clients |
| Isolation | Sol sees only its scoped profiles/projects/subjects |
| Proofs | `store.verify`, `store.replay`, `proof.get` identical |
| Revocation | `pcmf clients revoke --id sol_adapter` destroys the key |

The full flow (enable → register → observe → disable → blocked) is covered
by the native test `sol_adapter_flow` in `pcmf-selftest`, proving adapter
compatibility without Sol being present.

## What Sol-side work remains (out of scope for PCMF)

1. A Sol-side adapter process that speaks PCMF_IPv1 (the `pcmf send`
   subcommand and `src/pcmf_engine.h` `Frame` API are reference clients).
2. Owner-approved scope profile for Sol's memory surface.
3. Explicit decision on which Sol interactions produce memory events.

None of these can or should be built before Sol exists and the owner
authorizes the integration; the PCMF side is complete and gated.
