# Forge PCMF / Living Memory Engine

An open-source persistent-memory and continuity engine for AI systems and agents, designed around **deterministic state, governed memory admission, provenance tracking, owner authorization, and auditable decisions**.

> **Early-stage public collaboration repository.** The native PCMF engine source has **not yet been published here**. Its first public source package is subject to security, privacy, dependency, and licensing review. No installation or production-use claims are made by this README.

## What we're working toward

PCMF separates a model's *proposal* from the deterministic decision to accept, reject, or review a lasting memory. The public project aims to make state transitions testable, keep a trace of decisions, and prevent unverified snapshots or model-generated claims from silently becoming authoritative.

Key design areas for community review:
- Provenance and evidence needed for durable memory admission.
- Explicit owner consent and review-required stop conditions.
- Single-writer continuity and fail-closed conflict handling.
- Clear boundaries between execution tools, personal memory, and system state.
- Reproducible tests, documentation, threat modeling, and portable deployments.

These are project goals and design constraints, **not a claim that every feature is available in a published release**.

## Help build it

**Contributors are welcome now**, including people working on C++, Linux, agent infrastructure, evaluation, security, test engineering, and technical writing.

1. Browse or open an [issue](../../issues) to discuss a feature, bug, test plan, or design question.
2. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the proposed fork → branch → pull request → review workflow.
3. Use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) when submitting a change.
4. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

Contributions are reviewed before merging. You do **not** need access to the owner's machines, private memory, or production installation to contribute.

## Security and privacy boundary

**Never upload** personal memory records, credentials, tokens, live ledger databases, privileged configuration, production backups, or real user/customer data. Please use synthetic examples. The public engine is separate from private operational state.

## License

[Apache License 2.0](LICENSE). It permits use, modification, distribution, and commercial adoption under its terms.

## Release status

Public source review and initial installation documentation: **pending**. The repository currently contains governance and collaboration documentation, not a complete downloadable engine.
