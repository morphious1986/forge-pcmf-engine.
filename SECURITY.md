# Security Policy

## Public review versus stable release

The [sanitized R17/R244 native engine source](https://github.com/morphious1986/forge-pcmf-engine./tree/review/pcmf-r244-public-source-20261109) is publicly accessible on its review branch, with the [primary review in PR #2](https://github.com/morphious1986/forge-pcmf-engine./pull/2). **It has not been merged into `main` or accepted as a stable release.** Experimental and later development pull requests have separate readiness requirements.

This public repository is for reviewed source candidates and safe technical documentation. The live PCMF installation, canonical memory ledger, user records, secrets, credentials, privileged access configuration, operational history, and private backups are **not public project assets**. Public source visibility grants no authority over running systems.

## Reporting a vulnerability

**Do not include exploit steps, credentials, private memory, production logs, or sensitive implementation details in a public GitHub issue, PR, or Colony comment.**

If the repository's Security tab offers **Report a vulnerability**, use that private channel. Otherwise, request a private reporting channel from the maintainer without posting sensitive details publicly.

A useful private report includes a concise security boundary, affected source branch/commit, impact and prerequisites, a synthetic isolated reproduction where possible, and proposed mitigations. Do not attempt verification against production memory or other users' systems.

## Security design principles

- Explicit owner authority for sensitive actions and memory admission.
- Governed provenance and independent verification of observed state.
- Fail-closed behavior for missing or contradictory authorization and incomplete state.
- Separate machine execution from memory-writer authority.
- No assumption that a historical checkpoint proves current live-state identity.
- Synthetic public fixtures instead of real memory or production data.
- Independent review before claiming release readiness.

Security-sensitive changes require appropriate review and test evidence. A draft PR, source publication, or public test summary is not a supported release or deployment permission.
