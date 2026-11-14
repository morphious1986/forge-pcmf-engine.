# Public Source Publication Safety Process — R1

Status: **publication workflow guidance**, not an assertion that any repository, commit, or release is free of vulnerabilities.

## Principle

A public code tree is fully visible, including draft pull requests and historical public commits. A draft flag controls review readiness, **not confidentiality**. Excluding material from a later commit does not undo an earlier public disclosure.

## Minimum disclosure

Publish only material with a clear public purpose and explicit owner authorization. Exclude personal memories, credentials, authentication material, private review records, live state, backup contents, deployment inventories, host identifiers, machine-access configuration, and environment-specific operational details.

Prefer synthetic reproducible examples to production traces. Do not put vulnerability reproduction details, private proof packets, or confidential assumptions in public issues. The repository `SECURITY.md` provides a private reporting path.

## Source publication workflow

1. Select files **individually** from an isolated, source-only staging tree. Never publish an entire private development branch by default.
2. Inspect the files **and their proposed Git history** for private content, hidden files, binary data, licensing conflicts, and metadata exposure.
3. Run static and secret-scanning checks on the **exact final candidate**. Heuristic matching is only one screening layer.
4. Use synthetic fixtures. Test in disposable environments without live services, secrets, or user data.
5. Independently review the candidate diff, especially authorization, persistence, installation, and external-access changes.
6. Publish to a separate draft branch. Verify uploaded blobs by GitHub readback, and recheck the public diff.
7. Merge or tag only after the appropriate review and owner-authorization requirements are satisfied.

## Evidence policy

Keep complete private receipts, local snapshots, and recovery material outside the public repository. Public evidence may summarize scope, candidate version and pass/fail outcomes without disclosing sensitive inputs or host topology. State all limitations.

## Publication tooling

A companion offline preflight checker flags selected common credential signatures, private host paths, binaries, symlinks, and unsafe paths in an explicit candidate file list. It deliberately fails closed when it cannot inspect a file.

**A clean result is not a security guarantee.** The checker cannot prove clean Git history, detect every type of secret, establish license compliance, or show that an implementation is free of vulnerabilities. Independent review remains necessary.
