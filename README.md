# Forge PCMF / Living Memory Engine

An open-source persistent-memory and continuity engine for AI systems and agents, designed around **deterministic state, governed memory admission, provenance tracking, owner authorization, and auditable decisions**.

**Native source is publicly available for community review.** The sanitized R17/R244 source is on a public review branch; it has **not** been merged into `main`, tagged as a stable release, or approved for production installation.

## Find the code and help review it

**Start with the native source, not the experimental UI branch:**

- **[Browse the R17/R244 native source](https://github.com/morphious1986/forge-pcmf-engine./tree/review/pcmf-r244-public-source-20261109)** — source code, synthetic tests, build scripts, and review documentation.
- **[R17/R244 community source-review PR #2](https://github.com/morphious1986/forge-pcmf-engine./pull/2)** — the primary place to discuss the native engine, submit review findings, and see the source diff.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to reproduce tests and propose a review or change without accessing anyone's private system.
- [SECURITY.md](SECURITY.md) — private vulnerability-reporting guidance; do not publish exploitable details or confidential evidence in issues.
- [Repository issues](../../issues) — suitable for non-sensitive bug reports, synthetic reproductions, portability questions, and feature proposals.

**Additional workstreams are independent of primary source review:**

- [PR #3](https://github.com/morphious1986/forge-pcmf-engine./pull/3) — experimental Control Center, deferred review, and governance research; **draft**.
- [PR #4](https://github.com/morphious1986/forge-pcmf-engine./pull/4) — synthetic Memory Integrity Challenge benchmark; **draft**.
- [PR #5](https://github.com/morphious1986/forge-pcmf-engine./pull/5) — documentation on status-language semantic round-trip reliability; **draft**.
- [PR #6](https://github.com/morphious1986/forge-pcmf-engine./pull/6) — sanitized R245 development summary and publication checks, **not the R245 runtime source**; **draft**.

Please do not mistake the experimental PRs for the base engine, or GitHub visibility for deployment authorization.

## What PCMF is designed to do

PCMF separates a model's memory *proposal* from the deterministic, governed decision to accept, reject, or require owner review. Public engineering areas include provenance and replay, client-scoped state retrieval, single-writer fencing, fail-closed conflict handling, synthetic tests, and portable local-first integrations.

Capabilities described on different review branches have different maturity levels. No public source review is proof of full production acceptance.

## Getting started with review

Use the public R244 review branch and its own README for build prerequisites and **synthetic test** commands. Run tests only in a disposable VM, container, or separate test user with an isolated home directory. Some release tests exercise installer and uninstall behavior; never point them at real memory stores or a running installation.

Reviewers can contribute by opening a non-sensitive issue, commenting on [PR #2](https://github.com/morphious1986/forge-pcmf-engine./pull/2), or submitting a focused PR based on the appropriate review branch. No credentials, personal data, production access, or local machine access are needed.

## Security and privacy

**Never publish** personal memory, credentials, tokens, live ledgers, user data, privileged machine configuration, private backups, or identifiable production traces. Use invented, synthetic examples. Report vulnerabilities through the private channel described in [SECURITY.md](SECURITY.md).

The public code is separate from the canonical PCMF writer and private operational state. No repository commit, PR, or merge grants authority over an installed system.

## License and release status

[Apache License 2.0](LICENSE). The source is offered for inspection and collaboration under its applicable license and notices.

**Publication:** sanitized native R17/R244 source is public on its review branch. **Review:** open. **Stable release:** not declared. **Production installation and memory migration:** not authorized by this publication.
