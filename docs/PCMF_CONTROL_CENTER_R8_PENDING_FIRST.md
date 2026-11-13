# PCMF Control Center R8 — Pending-first approval dashboard
This additive GUI update adds a prominent MEMORIES NEEDING YOUR APPROVAL count, a large REVIEW NOW — OPEN APPROVAL PROMPT button, a NEEDS APPROVAL first tab, automatic selection of the first pending item, and double-click review opening.
The native owner-review binary and canonical PCMF engine are unchanged. Owner approval still requires exact original text and OS authentication. Hash-only records cannot reconstruct discarded notes. This UI does not add one-time rejection or automatic admission.
The passphrase setup/change controls from R7 remain available, with owner-selected six-character minimum. Longer passphrases are recommended.
Tested against synthetic pending data: 5/5 R8 UI tests passed. Live R8 read-only self-test and initial window launch passed.
This package is a complete native offline self-installer, but it must not overwrite the production engine without separate authorized release cutover. Install in isolated mode with sh scripts/install.sh --no-service; uninstall with sh scripts/install.sh --self-uninstall --no-service preserving data and encrypted owner notes.
The Sol router/runtime and independent inference lease remain unchanged.
