# Security Policy

## Publication boundary

This public repository is for the **PCMF engine and safe documentation**. The live PCMF installation, canonical memory ledger, user data, secrets, credentials, privileged machine-access configuration, and private backups are **not public project assets**.

The first complete source release is pending review. Until a release and supported versions are documented, do not assume any published README is an installed or supported build.

## Reporting a vulnerability

Please avoid publishing exploit details, credentials, memory records, or private host information in a public GitHub issue or pull request.

If GitHub's **Report a vulnerability** option is available in the repository's Security tab, use it to send a private report. If it is not available, request a private reporting channel from the maintainer without posting the sensitive details publicly.

A useful private report includes:
- A concise description and expected security boundary.
- A reproduction using synthetic data and an isolated environment.
- Affected component and version or commit, if known.
- Impact, prerequisites, and any safe mitigation proposal.

## Security design principles

- Explicit owner authority for sensitive actions.
- Governed memory admission and independently verified provenance.
- Fail-closed behavior on mismatched or incomplete state.
- Separation of execution tools from memory authority.
- No assumption that an immutable checkpoint proves current live-state identity.
- No secret, personal, or production-memory disclosure in tests or examples.

Security fixes should be reviewed and verified before publication. Maintainers may request more evidence or hold changes until risks are resolved.
