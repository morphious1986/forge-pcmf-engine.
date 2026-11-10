# Troubleshooting (R14)

## Statuses and what they mean

- `HOLD_INTEGRITY_OR_AUTHORITY` — fail-closed. Look at `reason`:
  - `SOURCE_SIGNATURE_INVALID` — wrong key or corrupted frame; re-register
    the client or check the key file (must be `0600`, 32 bytes).
  - `EXPIRED_OR_FUTURE_REQUEST` — clock skew beyond the configured window.
    Check system time; adjust `ts_window_past`/`ts_window_future` if needed.
  - `CLIENT_REVOKED` / `UNKNOWN_CLIENT` — identity problem; `pcmf clients list`.
  - `NONCE_REPLAY_CONFLICT` — the nonce was reused with different content.
    Generate a fresh nonce per logical request.
  - `INDEX_PREIMAGE_MISMATCH` — interrupted ledger/index pair. Run
    `pcmf recover` (regenerates the index from the verified ledger).
  - `LEDGER_TORN_LINE` / `LEDGER_NOT_CANONICAL` / `EVENT_ID_MISMATCH` —
    the ledger itself was damaged (disk issue or manual edit). Do NOT edit
    it by hand. Restore the latest verified backup:
    `pcmf backup restore --name <snapshot>`; recovery from a tampered
    ledger is refused by design (`LEDGER_CHAIN_BROKEN_RECOVERY_REFUSED`).
- `REVIEW_REQUIRED` — sensitive/uncertain content held. `pcmf review list`
  shows hash-only stubs; decide with `pcmf review resolve`.
- `REJECT` — policy rejection (scope, size, unknown domain/class). Reasons
  are deterministic; see `docs/FORGE_INTEGRATION.md` taxonomy.
- `DENIED` — authenticated but not authorized (scope/role).

## Store will not accept writes

1. `pcmf status --root <root>` — check `chain_ok`, `index_ok`.
2. `index_ok:false` → `pcmf recover` → `pcmf replay`.
3. `chain_ok:false` → restore from backup (above). Never hand-edit
   `STORE/local_memory.jsonl`.
4. Permission errors (`ROOT_NOT_PRIVATE`, `FILE_NOT_PRIVATE_OR_WRONG_SIZE`)
   → the engine enforces `0700` dirs / `0600` files owned by the current
   user:
   `chmod 700 <root> <root>/STORE <root>/keys <root>/config ...` and
   `chmod 600 <root>/keys/owner.key`.

## Service will not start

- systemd user session required: `loginctl enable-linger $USER` (once), then
  `systemctl --user daemon-reload && systemctl --user enable --now pcmf.service`.
- Unit uses `%h` (home) — verify `~/.config/systemd/user/pcmf.service`
  points at the current data root.
- Socket exists but clients fail: the socket is `0600` inside a `0700`
  directory; run clients as the same user.
- Daemon logs its bind result as one JSON line on stdout; run it in
  foreground to see it:
  `~/.local/lib/pcmf/current/bin/pcmf-serve --root <root>`.

## Client cannot retrieve memory

- Non-owner clients MUST pass `profile` and `project` to `hot.get`
  (`SCOPE_PROFILE_REQUIRED` otherwise) and may only use scoped values.
- Empty result with `memory_items:0` — subjects may have aged out of HOT;
  widen windows (`pcmf config set hot_days 14`) or use `--include-warm`.
- `SOL_INTEGRATION_DISABLED` — sol-role clients are blocked until the owner
  explicitly enables the integration.

## Installer issues

- `PACKAGE_CHECKSUM_MISMATCH` — the package was modified in transit.
  Re-transfer; never bypass the check.
- `STAGE_ALREADY_EXISTS` — a previous attempt with the same build id
  exists; use a fresh package or remove the stale stage directory.
- `HOLD: SERVICE_NOT_ACTIVATED` — expected without a systemd user session;
  the binaries are fully functional in direct mode.
- Only one active version may exist: after a successful install the
  `versions/` directory holds the current release plus the previous one as
  recovery. Anything else indicates an interrupted run — re-run the
  installer; it completes cleanup.

## Diagnostics

```sh
pcmf selftest-quick: ~/.local/lib/pcmf/current/bin/pcmf-selftest quick
full suite:          ~/.local/lib/pcmf/current/bin/pcmf-selftest <bindir>
pcmf-setup           # menu item 11 runs diagnostics
```
