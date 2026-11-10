# PCMF Standalone R16/R4 + Local llama.cpp

This release packages the verified R16 local/Sol-aware admission policy with the hardened R4 owner acceptance UX and a direct loopback-only llama.cpp connector.

The core protocol/version string remains PCMF_LIVING_MEMORY_R14 / PCMF_IPv1 for compatibility. R16 refers to the admission-policy revision; R4 refers to the owner-acceptance implementation.

Owner acceptance:
- native OS owner authentication through pkexec
- exact pending entry shown only in the local owner review window
- separate random 8-character single-use challenge
- native X11 challenge input with visible click focus and blinking caret
- accepted custom retro approval chime when paplay is available
- challenge is not passed through process argv/environment
- exact entry is not persisted by the reviewer before approval
- reviewer pins the packaged pcmf binary hash; MCP boundary pins the reviewer hash

Local llama.cpp:
- direct OpenAI-compatible loopback transport
- GET /v1/models model verification
- POST /v1/chat/completions chat path
- prompt is read from stdin, not process arguments
- only 127.0.0.1 / localhost HTTP endpoints are accepted
- model process receives no PCMF write authority
- memory transfer is disabled by default

Live Sol verification is separate from package verification. If no llama.cpp server is listening, package tests can pass using the deterministic local mock while the real Sol handshake remains BLOCKED until the server is started.


Uninstall contract:
- pcmf-uninstall removes the complete PCMF application footprint while preserving memory data/backups by default.
- Cleanup includes CLI links, installed release tree, user service, runtime socket, install config, PCMF desktop/home-screen launchers, application-menu entries, autostart entries, and PCMF-owned icon-cache files.
- pcmf-uninstall --purge-data additionally removes the configured memory root/backups only after exact confirmation.
- pcmf-uninstall --purge-all additionally removes the default isolated PCMF instance root after exact confirmation.
- install.sh --self-uninstall correctly forwards normal, purge-data, purge-all, and no-service modes to the packaged uninstaller.
- Release acceptance creates synthetic desktop/menu/icon artifacts in a disposable HOME and proves they are removed while memory is preserved; a separate guarded test proves full data/instance purge.
