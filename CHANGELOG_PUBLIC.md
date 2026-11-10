# PCMF R17/R244 community source — preparation notes

- Started from a separately verified native R17/R244 package, excluding private memory root, keys, backups, binaries, historical patches, and private Git history.
- Sol integration requires explicit client key path and profile, with no owner-specific fallback.
- Public synthetic migration receipt identifiers no longer reveal operational machine names.
- New strict installer/uninstaller path validation rejects dangerous roots, symlinks, arbitrary purge destinations, and false product markers.
- The --no-service path never invokes host systemctl or user systemd daemon-reload.
- The symlink-invoked installer/uninstaller resolves the original script path correctly.
- The Unix socket daemon refuses to unlink an unrelated file, symlink or live socket.
- Adversarial tests: 17 rejected unsafe installer paths and 3 socket guards.
- Historical unverified WAV was replaced with a freshly generated synthetic PCM tone.
- Apache License 2.0 and NOTICE added; compiled tools and personal operational data are not part of this source-only publication candidate.
- Latest isolated verification: 35/35 native tests, 45 context-policy tests, 8 admission tests, 11 connector tests, full isolated installation/uninstallation/purge suite. No host systemd calls.

No production writer cutover, restoration or migration is implied by publication. This is a source-review candidate until separately accepted for stable release.
