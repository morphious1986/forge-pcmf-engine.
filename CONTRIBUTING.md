# Contributing to Forge PCMF Engine

Thank you for helping review a deterministic, governed continuity engine for AI systems and agents.

## Where the real code is

The sanitized **R17/R244 native source is already public** on a review branch. It is not yet merged to `main` or declared a stable release.

- [Browse source files and synthetic tests](https://github.com/morphious1986/forge-pcmf-engine./tree/review/pcmf-r244-public-source-20261109)
- [Review native engine — PR #2](https://github.com/morphious1986/forge-pcmf-engine./pull/2) — **primary engineering review target**
- [Repository issues](../../issues) — non-sensitive technical proposals and reproducible defects
- [Security reporting](SECURITY.md) — private reporting of sensitive findings

The default `main` branch is currently the public collaboration and navigation surface, **not** the latest native engine code. Select the R244 review branch to inspect or test it.

## Where different contributions belong

- **Native R17/R244 engine:** [PR #2](https://github.com/morphious1986/forge-pcmf-engine./pull/2) or small focused PRs based on its source branch, including C11/C++20 correctness, deterministic replay, synthetic privacy tests, portability, and documentation.
- **Experimental Control Center and deferred review:** [PR #3](https://github.com/morphious1986/forge-pcmf-engine./pull/3) — draft; not interchangeable with the core engine.
- **Memory Integrity Challenge:** [PR #4](https://github.com/morphious1986/forge-pcmf-engine./pull/4) — synthetic benchmark, draft.
- **Memory status language:** [PR #5](https://github.com/morphious1986/forge-pcmf-engine./pull/5) — documentation research, draft.
- **Sanitized R245 development update:** [PR #6](https://github.com/morphious1986/forge-pcmf-engine./pull/6) — includes a public publication preflight tool, **not** the private R245 implementation; draft.

To propose native code changes, use the R244 source branch as your starting point and state that branch in the pull request. Do not base changes on experimental branches unless reviewing their specific experimental scope.

## Reproducible review process

1. Inspect the [R244 branch README](https://github.com/morphious1986/forge-pcmf-engine./blob/review/pcmf-r244-public-source-20261109/README.md) for prerequisites and synthetic test commands.
2. Run everything in a disposable VM, container, or isolated test user, with its own HOME and no connection to private PCMF state. Some scripts exercise installation and guarded synthetic data removal; do not run them against a personal installation.
3. Open a focused issue or pull request with a clear description of the expected behavior and synthetic input/output evidence.
4. Cite exact source branch and commit, test command/results, and any limitations. Do not call an internal test result independent security certification.
5. Address independent review feedback. Maintainers separately determine merge, release, and deployment readiness.

Security problems involving exploitable conditions, access-control boundaries, or private implementation details should go through [SECURITY.md](SECURITY.md), **not** public issues or post comments.

## Contribution boundaries

Never upload real memory records, credentials, tokens, operational logs, host-specific paths, production configuration, private backups, or customer data. Use synthetic fixtures only. No contributor requires local machine access, production memory, keys, or owner authorization to review and propose public changes.

A pull request is a proposal. It does not grant memory-writer authority, weaken `REVIEW_REQUIRED`, install code, authorize production access, or represent a stable release.

## License

Contributions must be compatible with the repository's [Apache License 2.0](LICENSE) and identify any included third-party work and applicable licensing.
