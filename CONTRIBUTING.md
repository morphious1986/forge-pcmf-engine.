# Contributing to Forge PCMF Engine

Thanks for helping build a trustworthy, open-source continuity engine for AI systems and agents.

## Project status

This repository is being prepared for a security-reviewed source release. The presence of a README or license **does not** mean the native engine source, binaries, or production integrations have been published or accepted here yet.

You can contribute now by opening an issue with a design proposal, an API suggestion, documentation feedback, test ideas, or security-safe reproducible bug reports. Code contributions can follow once the reviewed source is published.

## Ways to collaborate

- **Issues:** bugs, feature requests, portability problems, testing gaps, and architecture proposals.
- **Fork + pull request:** propose a small, reviewable change with clear motivation, tests where applicable, and updated documentation.
- **Reviews:** help assess correctness, reproducibility, security, accessibility, and backward compatibility.
- **Documentation:** installation guidance, diagrams, examples using invented data, and clearer threat-model explanations.

Search existing issues and pull requests before opening duplicates.

## Contribution workflow

1. Open an issue for substantial changes so maintainers and contributors can agree on scope.
2. Fork the repository and create a focused branch.
3. Make the smallest coherent change; include tests and documentation when appropriate.
4. Run the published validation commands once the implementation is available.
5. Open a pull request describing the behavior, verification performed, and any compatibility/security impact.
6. Address review feedback. Maintainers decide whether and when to merge.

**No direct write access or production PCMF access is needed to contribute.** A pull request is a proposal, not automatic admission into the engine.

## Important boundaries

- Never commit live memory contents, personal records, credentials, access tokens, host details, production configuration, private backups, or real customer data.
- Use only synthetic or explicitly publishable test fixtures.
- Do not bypass governed admission, provenance checks, owner authorization, fail-closed behavior, or single-writer authority.
- Do not assume a saved checkpoint represents the current live state.
- Do not make changes to someone else's running installation as part of a contribution.
- Security-sensitive concerns should use the private channel described in [SECURITY.md](SECURITY.md), not a public issue.

## License

The repository uses [Apache License 2.0](LICENSE). Contributions intended for inclusion must be compatible with that license. Please identify any third-party material and its license before submitting it.

The goal is an approachable, independently testable engine **without publishing private operational memory**.
