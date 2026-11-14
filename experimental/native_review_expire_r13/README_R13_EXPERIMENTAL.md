# PCMF R13 — Experimental exact-token 72-hour expiry engine + R10 Control Center

This complete native offline source/build/self-install package is NOT authorized
for production PCMF cutover. The owner-authenticated `review.expire_once` API
requires exact pending token and note SHA-256, an explicit 72-hour expiry,
and writes a durable metadata-only archive record. It creates NO global deny rule.
The `review.list` API separates actionable pending from expired_due and expired.
The `review.resolve` and `review.submit` paths refuse new TTL-expired stubs.

Legacy pending records without `expires_at` (including old hash-only requests)
remain unchanged and cannot be expired by the new operation.

A R12 timer and encrypted queue have NOT yet been connected to this native API.
The user-systemd timer template is NOT installed or enabled. The live system
still uses its existing authorized native engine, and this package has been
evaluated only in an isolated temp directory and disposable memory root.
Sol router, inference, and native canonical memory writer remain unchanged.

Build (native Linux): sh scripts/build.sh
Synthetic test: python3 -m unittest discover -s tests -p test_review_expire_once_r13.py
Full isolated install: sh scripts/install.sh --no-service
Uninstall without deleting memory: sh scripts/install.sh --self-uninstall --no-service

Keep the R10 source/recovery package and previous USB releases for rollback.
The desktop UI stays R10; it does not yet display the new native expired_due/expired
fields until a separate reviewed integration.
