# PCMF Control Center R9 — GTK freeze fixes
R9 keeps the pending-first dashboard but fixes UI thread blocking in canonical refresh, review verification, inspect, memory browsing, encrypted save/unlock and passphrase rotation.
Inline validation avoids nested modal error dialogs. The native OS reviewer is invoked only after an exact-note hash/size match and a fresh pending-state check. Old hash-only requests cannot recreate missing original note text; the original submitting client must resubmit it.
Targeted synthetic GTK freeze regression tests 7/7 PASS. Live canonical read-only health and startup PASS. No canonical PCMF engine, stored memory, reviewer binary, or Sol runtime is modified by the desktop-only live patch.
The native self-install package is for controlled, owner-authorized releases; test in a disposable HOME using sh scripts/install.sh --no-service; preserve memory on uninstall.
All previous USB releases remain untouched. Default passphrase minimum is 6 characters but longer is recommended.
