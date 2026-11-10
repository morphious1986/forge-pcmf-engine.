#!/bin/sh
# PCMF R244 native offline release packager.
set -eu
cd "$(dirname "$0")/.."

NAME=pcmf-living-memory-r17-r244-native-offline
mkdir -p dist
rm -f "dist/$NAME.tar.gz" "dist/$NAME.sha256" "dist/$NAME.contents"

for f in LICENSE manifest.json \
   scripts/public_safety_paths.py \
  bin/pcmf bin/pcmf-serve bin/pcmf-setup bin/pcmf-selftest \
  bin/forge-pcmf-owner-review-r4 bin/pcmf-local-model \
  connector/pcmf-mcp-review-r2 \
  assets/pcmf-approval-retro-chime-v2.wav \
  scripts/install.sh scripts/install_instance.sh scripts/uninstall.sh \
  scripts/configure_forge_gpt_r2.sh \
  scripts/build.sh scripts/test.sh scripts/usb_export.sh \
  integrations/sol/app/pcmf_client.py integrations/sol/app/pcmf_runtime.py integrations/sol/app/pcmf_binding.py; do
  test -f "$f" || { echo "BLOCKED MISSING_RELEASE_FILE $f" >&2; exit 2; }
done

# Development-only compiled test executables are reproducible and not shipped.
rm -f tests/test_policy_context_r16 tests/test_policy_sol_local_admission_r16

# Freeze checksums over the package payload. SHA256SUMS itself and dist are excluded.
find LICENSE manifest.json bin connector assets scripts systemd docs src tests integrations -type f -print0 \
  | sort -z | xargs -0 sha256sum > SHA256SUMS

tar -czf "dist/$NAME.tar.gz" --transform="s,^,$NAME/," \
  LICENSE manifest.json SHA256SUMS bin connector assets scripts systemd docs src tests integrations
sha256sum "dist/$NAME.tar.gz" > "dist/$NAME.sha256"
tar -tzf "dist/$NAME.tar.gz" > "dist/$NAME.contents"

TMP=$(mktemp -d /tmp/pcmf-r244-package-XXXXXX)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
tar -xzf "dist/$NAME.tar.gz" -C "$TMP"
( cd "$TMP/$NAME" && sha256sum -c SHA256SUMS >/dev/null )

grep -q "$NAME/LICENSE" "dist/$NAME.contents"
grep -q "$NAME/scripts/public_safety_paths.py" "dist/$NAME.contents"
grep -q "$NAME/manifest.json" "dist/$NAME.contents"
grep -q "$NAME/bin/pcmf-local-model" "dist/$NAME.contents"
grep -q "$NAME/bin/forge-pcmf-owner-review-r4" "dist/$NAME.contents"
grep -q "$NAME/connector/pcmf-mcp-review-r2" "dist/$NAME.contents"
grep -q "$NAME/scripts/configure_forge_gpt_r2.sh" "dist/$NAME.contents"
grep -q "$NAME/assets/pcmf-approval-retro-chime-v2.wav" "dist/$NAME.contents"
grep -q "$NAME/integrations/sol/app/pcmf_client.py" "dist/$NAME.contents"

echo "PASS_PCMF_R244_OFFLINE_PACKAGE dist/$NAME.tar.gz"
