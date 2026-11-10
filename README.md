# Forge PCMF / Living Memory — Native Community Engine

R17/R244 · C11/C++20 · Ubuntu-compatible Linux x86-64 · Apache License 2.0.

PCMF is a governed, persistent memory and continuity engine for AI agents. The core uses deterministic admission rules, client-scoped access, provenance checks, owner approval for sensitive decisions, and an auditable event ledger.

This is community SOURCE for experimentation and review, NOT an export of the running PCMF instance. It contains no production memory, credentials, original operational Git history, or model weights.

## Build and run the synthetic tests

Prerequisites: gcc/clang with C11/C++20, POSIX Linux facilities, Python 3, GNU coreutils, and libX11 development headers for the optional GUI.

    sh scripts/build.sh
    ./bin/pcmf-selftest "$(pwd)/bin"
    python3 tests/test_public_safety_paths.py
    python3 tests/test_public_socket_boundary.py

Run scripts/test.sh only inside a disposable VM, container, or test user with its own HOME and user-service boundary. It includes an installer, uninstaller, and a guarded synthetic data purge. Never point purge modes at a real memory store.

## Architecture

- src/: native engine, policy, CLI, Unix-domain service and optional local connectors.
- tests/: synthetic engine, admission, policy and safety tests.
- scripts/: deterministic native builds, release packaging and safe installer lifecycle.
- integrations/sol/app/: optional client with explicitly configured credentials.
- assets/: freshly generated, synthetic mathematical tone with provenance notes.
- docs/: historical design and operations notes; some R14 references are older than R244.

The public example deliberately replaces operational migration receipt identifiers with generic EXAMPLE_NODE fixtures. This source is not authorized to import live memory or assert production writer authority.

## Security boundaries

The local service uses a private authenticated Unix socket. The local-model connector is loopback-only and cannot independently admit memories. The Sol client requires explicitly configured SOL_PCMF_CLIENT_KEY and SOL_PCMF_PROFILE. REVIEW_REQUIRED is a hard stop, not permission to retry.

Do not commit STORE, keys, config, state, backups, receipts, memory data, private logs, machine credentials or access tokens. Use invented synthetic fixtures. Contributions use issues, forks and reviewed pull requests; no production PCMF access is needed.

See CONTRIBUTING.md, SECURITY.md, CHANGELOG_PUBLIC.md and NOTICE. No warranty or claim of production suitability is made.
