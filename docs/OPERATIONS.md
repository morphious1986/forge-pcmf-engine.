# Operations guide — install, update, rollback, backup, service (R14)

All operations are native shell scripts and binaries. No Python, no Node.js,
no internet access required.

## Fresh install (Ubuntu-based, x86_64)

```sh
tar xzf pcmf-living-memory-R14-<build>-ubuntu-amd64.tar.gz
cd pcmf-living-memory-R14-<build>
sh scripts/install.sh                 # add --no-service to skip service setup
```

The installer:

1. verifies the whole package against `SHA256SUMS` (fail → nothing changed)
2. detects any existing installation and any running service
3. stages the release under `~/.local/lib/pcmf/versions/<version>-<build>/`
   and re-verifies the staged copy
4. runs the native selftest (quick subset) from the staged binaries
5. initializes a fresh, `0700` data root at `~/.local/share/pcmf` **only if
   none exists** (an existing data root is never touched)
6. installs launchers into `~/.local/bin` (`pcmf`, `pcmf-serve`,
   `pcmf-setup`) and the systemd user unit
7. activates the release (symlink `current`) and runs post-install checks
8. keeps the previous release as recovery and removes older program versions
   only after the new one is verified — exactly one active version remains

Replacing an **active** service additionally requires
`--authorize-cutover` (or typing `I AUTHORIZE CUTOVER` when interactive).
Without authorization the release is staged and a
`HOLD_SERVICE_CUTOVER_NOT_AUTHORIZED` hold is reported — the running
installation is never touched.

## Update

Run the same installer from the newer release package; it auto-detects the
existing install and follows the update path:

1. verify new release → 2. protective `preupdate-<build>` backup of the
memory data root → 3. stage + test replacement → 4. switch active release →
5. cleanup obsolete versions. The working installation is never deleted
before the replacement is proven.

## Rollback

```sh
~/.local/lib/pcmf/current/scripts/install.sh --rollback
```

Switches the active symlink back to the recorded previous version (service
cutover rules apply), rewrites the manifest, and health-checks. The
previous release directory is preserved for exactly this purpose.

## Uninstall

```sh
~/.local/lib/pcmf/current/scripts/uninstall.sh          # program files only
# memory data root + backups PRESERVED; --purge-data requires typing
# 'PURGE ALL MEMORY DATA'
```

## Service management

```sh
systemctl --user status pcmf.service
systemctl --user restart pcmf.service
pcmf-setup                            # menu item 15 wraps the same commands
```

Without a systemd user session (headless/linger disabled), the installer
reports `HOLD: SERVICE_NOT_ACTIVATED`; run the daemon manually:

```sh
~/.local/bin/pcmf-serve --root ~/.local/share/pcmf
```

## Backup / restore

```sh
pcmf backup create --name nightly-$(date +%F)   # full snapshot incl. keys
pcmf backup verify --name nightly-2026-10-24
pcmf backup restore --name nightly-2026-10-24   # owner op; verifies first,
                                                # keeps pre-restore state
```

Snapshots live under `<root>/backups/<name>/` with their own
`manifest.json` + `SHA256SUMS`. The installer's `preupdate-*` snapshots use
the same mechanism.

## USB deployment (for ExampleNode transport)

```sh
# from a release package directory:
sh scripts/usb_export.sh --dest /media/$USER/USBDRIVE
# verifies source checksums, copies, writes SHA256SUMS on the device,
# byte-compares every file (cmp), and preserves previous releases in
# PCMF_RELEASES/
sh scripts/usb_export.sh --dest /media/$USER/USBDRIVE --verify-only
```

The device ends up with `PCMF_RELEASES/<version>-<build>/` containing
binaries, full source, scripts, systemd unit, docs, and the original
tarball — everything needed to install offline on another Ubuntu machine.

## Memory engine quick reference

```sh
pcmf init --root ~/.local/share/pcmf
pcmf status | verify | replay | state | health
pcmf hot --project general [--subject S] [--include-warm] [--limit N]
pcmf observe --project general --subject S --domain DAILY_ROUTINE \
    --class ROUTINE_STATE --note "..."
pcmf proof --event-id <64hex>
pcmf clients list | review list | config get
pcmf sol enable | disable          # owner authorization flow (disabled default)
pcmf-setup                         # full 16-item administration menu
```

Exit codes: `0` OK/REVIEW/duplicate · `2` HOLD/integrity · `5` REJECT ·
`6` DENIED.

## Memory states

A subject's state derives from its newest effective event (`recorded_at`,
UTC):

| State | Default window | Meaning |
|---|---|---|
| HOT | ≤ 7 days | returned by `hot.get` automatically |
| WARM | ≤ 30 days | `hot.get --include-warm` |
| COLD | ≤ 180 days | archived in ledger, retrievable by replay/proof |
| DORMANT | older | preserved, excluded from retrieval |

Windows are owner-configurable: `pcmf config set hot_days 3` etc.
