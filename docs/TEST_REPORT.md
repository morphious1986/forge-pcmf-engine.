# HISTORICAL R14 DOCUMENT (reference only)
This document records an older development checkpoint and is not the live R17/R244 release contract. See the repository root README.md and CHANGELOG_PUBLIC.md for the current community source scope.

# PCMF Living Memory R14 — Test Report (actual results)

- Build: `PCMF_LIVING_MEMORY_R14`
- Recorded: 2026-10-24 UTC (local session timezone America/New_York)
- Host: Linux 5.10.134 x86_64, GCC/Clang toolchain `cc/c++ (Debian 14.2.0-19) 14.2.0`
- Standards: C11 + C++20, `-Wall -Wextra -Werror -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2`
- Dependencies: **none beyond libc** (self-contained FIPS 180-4 SHA-256 / RFC 2104 HMAC)
- Canonical writer gate: `HOLD_R241_R242` asserted in tests, echoed in every response
- Verification command: `sh scripts/test.sh` (evidence: `test-evidence/test_log_20261024T235606Z.log`)

## 1. Historical baseline reproduction (sources unmodified)

| Suite | Result |
|---|---|
| R9 C11 policy tests (`legacy/pcmf-native-r9-hardening`) | `PASS_R9_NATIVE_C11_POLICY_TESTS=9` |
| R9 C++20 host boundary tests | `PASS_NATIVE_HOST_BOUNDARY_TESTS=17` |
| R9 static isolation (no PT_INTERP / no DT_NEEDED) | `PASS_ISOLATED_STATIC_BINARIES_NO_INTERPRETER_OR_NEEDED` |
| R10 ingress fail-closed build (OpenSSL 3 transitive `-lzstd -lz -lm` documented; sources untouched) | `PASS_LEGACY_R10_BUILD_AND_FAIL_CLOSED` |
| R13 native process-boundary denials | `PASS_R13_NATIVE_CPP_INGRESS_DENIALS=8 LIVE_MEMORY_UNTOUCHED` |

The historical Python oracle (`test_clone_r10.py`, absent from the R13
handoff) was replaced by native equivalents: canonical-chain verification,
replay and exact-readback, scoped recall, and duplicate/conflict semantics
are covered natively by `engine_replay_readback`, `engine_duplicates_conflicts`,
`engine_scope_isolation`, `process_crash_recovery`, and `store.replay`.

## 2. R14 native selftest — 33/33 PASS

`PCMF_LIVING_MEMORY_R14_SELFTEST engine=PCMF_LIVING_MEMORY_R14
canonical_writer=HOLD_R241_R242 mode=full`
`SELFTEST_SUMMARY passed=33 failed=0`

| # | Test | Area (mission §8 mapping) |
|---|---|---|
| 1 | crypto_sha_empty | SHA-256 NIST vector (empty) |
| 2 | crypto_sha_abc | SHA-256 NIST vector ("abc") |
| 3 | crypto_sha_twoblock | SHA-256 448-bit vector |
| 4 | crypto_sha_million_a | SHA-256 million-'a' vector |
| 5 | crypto_hmac_rfc4231 | HMAC-SHA256 RFC 4231 cases 1, 2, 3, 6 |
| 6 | crypto_hex_ct | hex codecs + constant-time compare |
| 7 | policy_r9_regression | R9 nine-check regression (order-stable struct) |
| 8 | policy_r14_extensions | everyday domains/classes, privacy-class gate |
| 9 | engine_init_and_marker | fresh installation, double-init fails closed |
| 10 | engine_root_privacy_enforced | non-private root refused |
| 11 | engine_authenticated_admission | valid authenticated synthetic input admitted |
| 12 | engine_invalid_signature | invalid signatures denied |
| 13 | engine_expired_and_future | expired/future identities denied |
| 14 | engine_revoked_and_unknown | revoked/unknown identities; ChatGPT-impersonation ids refused |
| 15 | engine_malformed_requests | malformed/oversized requests fail closed |
| 16 | engine_scope_isolation | cross-profile isolation, subject-prefix scopes, class scopes |
| 17 | engine_duplicates_conflicts | duplicate events, nonce replay conflict, subject/domain conflict |
| 18 | engine_corrections_revocations | corrections supersede, revocations retract (eligibility/review) |
| 19 | engine_sensitive_review_flow | sensitive rejection/review; raw content never persisted pre-review; allow/deny rules |
| 20 | engine_allow_once | owner-resubmitted reviewed content; content-swap blocked |
| 21 | engine_memory_states | HOT/WARM/COLD/DORMANT transitions |
| 22 | engine_replay_readback | replay and exact readback (5 events) |
| 23 | engine_proof_packets | HOT retrieval anchors + proof packets |
| 24 | engine_backup_roundtrip | backup create/verify/restore after tamper |
| 25 | process_crash_recovery | atomic commits + interrupted writes + crash recovery (exit 97 injection) |
| 26 | process_corrupt_index | corrupt index detected, rebuilt from verified ledger |
| 27 | process_ledger_tamper | ledger tampering detected; recovery refuses; writes fail closed |
| 28 | process_torn_ledger | torn-line detection |
| 29 | process_concurrent_writers | concurrent writers: exactly one append, rest idempotent NOOP / conflict HOLD |
| 30 | process_restart_persistence | restart persistence |
| 31 | daemon_roundtrip | PCMF_IPv1 over AF_UNIX: ping/observe/bad-sig/garbage; clean shutdown |
| 32 | sol_adapter_flow | future Sol adapter compatibility (disabled→enable→register→observe→disable→blocked) |
| 33 | installer_fresh_home | fresh install into disposable HOME; uninstall preserves memory data |

## 3. Installer lifecycle (real two-release exercise)

| Step | Result |
|---|---|
| Package R14 (build 100001) + R14.1 (build 100002) | `PASS_PACKAGE_RELEASE` |
| Fresh install (disposable HOME, `--no-service`) | `PASS_INSTALL version=R14 build=100001`, `PASS_FRESH_INSTALL`, `PASS_DATA_ROOT_INITIALIZED` |
| Unauthorized update attempt over active R14 | `HOLD_SERVICE_CUTOVER_NOT_AUTHORIZED` (safety gate proven) |
| Authorized update to R14.1 | `PASS_INSTALL version=R14.1 build=100002`, 2 versions on disk (current + recovery) |
| Rollback to R14 | `PASS_ROLLBACK active=R14-100001 restored_from=R14.1-100002`, `PASS_ROLLBACK_ACTIVE` |
| Uninstall | `PASS_UNINSTALL_PROGRAM_REMOVED`, `PASS_UNINSTALL_MEMORY_DATA_PRESERVED` |
| Overall | `PASS_INSTALLER_LIFECYCLE` |

Service activation inside the sandbox reports the expected
`SERVICE_NOT_ACTIVATED` hold (no systemd user session); the systemd user
unit is installed and the direct-run daemon mode was verified by
`daemon_roundtrip`.

## 4. USB deployment export

| Step | Result |
|---|---|
| Export to destination (release R14 build 200001) | `PASS_USB_EXPORT target=.../PCMF_RELEASES/R14-200001` |
| Independent verify-only pass | `PASS_USB_VERIFY` |
| Installer present in USB package | `PASS_USB_PACKAGE_COMPLETE` |
| Previous releases preserved, byte-compare (cmp) per file | asserted in `usb_export.sh`, `PASS_USB_EXPORT_PROCEDURE` |

## 5. Checksums

### Binaries (this build)

```
859a1ed26aa4bbdb68e129d6d2d2cff0ed24fff0bd649823472c859f97e3d908  bin/pcmf
7a2016eda23fa0d8392703c736de471d7fbde886ab64113a1e66ff08e7786f45  bin/pcmf-serve
97582db339f09fe7bb1addc68d9794f28ab711c50282e271fe1050246a2f73e3  bin/pcmf-setup
8e3672797967939f976c1f60eeecef9a23e0e03e0794bb4826d13a09f20e0e3b  bin/pcmf-selftest
```

### R14 sources + scripts + docs

Manifest of per-file SHA-256 over `src/ tests/ scripts/ systemd/ docs/`:
`test-evidence/r14_source_SHA256SUMS`
(sha256 of that manifest: `600f581d2d045cf0d05f00aa4c104a9ed41118efbf90d06ebb9926df3a3c1c6c`)

### Preserved baseline (R13 handoff)

`legacy/` ships the unmodified R9/R10 sources; the original archive
checksum is:

```
78a3ced8e2cbd78a72c49c924c327fd4e9b6af24c47dcec16dd32f02aaf1428b  PCMF_NATIVE_R13_GLM_HANDOFF_20261024.zip
```

Full baseline file list: `baseline-evidence/BASELINE_SHA256SUMS`.

## 6. Constraints respected during testing

- All tests used disposable synthetic roots (`/tmp/pcmf-selftest-*`,
  `/tmp/pcmf-install-test-*`); no real or canonical memory was touched.
- The canonical writer hold `HOLD_R241_R242` was never bypassed and is
  asserted present in responses throughout the suite.
- No Python, Node.js, npm, Electron, or network access was used at build,
  test, install, or export time.

## 7. Disposition

```
PASS_R14_FULL_VERIFICATION
NATIVE_R14_COMPLETE
BASELINE_REPRODUCED (R9: 9+17+static, R10 fail-closed, R13: 8)
SELFTEST 33/33
INSTALLER_LIFECYCLE_PASS (fresh/update/rollback/uninstall)
USB_EXPORT_PASS
CANONICAL_WRITER_HOLD_R241_R242
```
