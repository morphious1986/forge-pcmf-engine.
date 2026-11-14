# PCMF Control Center R10 — actionable review queue
2026-11-13, owner-requested correction. Do NOT display a pending memory as ready if its exact original text is not retained by the Control Center.
The GUI partitions native canonical pending records into READY FOR REVIEW (a structurally valid, private, owner-opt-in encrypted note candidate exists) and NEEDS RESUBMISSION (no local recoverable encrypted note candidate). The latter never appears in the actionable approval list.
A structurally valid encrypted candidate is NOT proof of decryption or exact-note authenticity. Owner-passphrase unlock plus token/root identity and plaintext SHA256/length verification remain mandatory before native OS-authenticated review.
Default live state at rollout: 0 ready, 13 requiring original text. Their pending PCMF audit records are retained, NOT rejected or deleted. Other submitting clients may still recover exact originals; the GUI cannot establish permanent loss.
No existing native PCMF rejection command is invoked, as it can create a future broad denial rule. No memory admission, native engine cutover, Sol runtime or independent project authorization changes.
R10 targeted synthetic tests: 7/7 PASS. Existing R9 freeze fixes remain in application.
Complete native self-installer: verify manifest, isolated no-service install, R10 GTK tests, uninstall and memory preservation before production deployment. Uninstall does not purge memory or encrypted owner inbox.
Future submitting-client integration: owner-approved encrypted capture at submission time, no queue visibility as actionable without a verified original-note path. This future feature is NOT installed.
