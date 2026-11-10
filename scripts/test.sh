#!/bin/sh
# PCMF R244 standalone release verification.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)

echo "=== [0/8] public installer boundary adversarial checks ==="
python3 tests/test_public_safety_paths.py
echo PASS_PUBLIC_INSTALLER_BOUNDARY_PREFLIGHT
python3 tests/test_public_sol_config.py
echo PASS_PUBLIC_SOL_CONFIG_GUARD

echo "=== [1/8] build ==="
sh scripts/build.sh >/tmp/pcmf-r244-build.log
tail -n 1 /tmp/pcmf-r244-build.log | grep -q PASS_PCMF_R244_EXPLICIT_TIER_NATIVE_BUILD
echo PASS_RELEASE_BUILD
python3 tests/test_public_socket_boundary.py
echo PASS_PUBLIC_SOCKET_GUARD

echo "=== [2/8] native core and R16 policy ==="
./bin/pcmf-selftest "$ROOT/bin" > /tmp/pcmf-r244-selftest.log
grep -q 'SELFTEST_SUMMARY passed=35 failed=0' /tmp/pcmf-r244-selftest.log
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -I src \
  tests/test_policy_context_r16.c src/pcmf_policy.c -o tests/test_policy_context_r16
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -I src \
  tests/test_policy_sol_local_admission_r16.c src/pcmf_policy.c -o tests/test_policy_sol_local_admission_r16
./tests/test_policy_context_r16
./tests/test_policy_sol_local_admission_r16
echo PASS_RELEASE_POLICY

echo "=== [3/8] local llama.cpp connector ==="
python3 tests/test_local_model_connector.py
python3 tests/test_setup_local_llama.py
echo PASS_RELEASE_LOCAL_MODEL

echo "=== [4/8] dependency and portability audit ==="
! ldd bin/forge-pcmf-owner-review-r4 | grep -q 'not found'
! ldd connector/pcmf-mcp-review-r2 | grep -q 'not found'
! ldd bin/pcmf-local-model | grep -q 'not found'
! strings bin/forge-pcmf-owner-review-r4 | grep -Eq '/home/[A-Za-z0-9_-]+/'
! strings connector/pcmf-mcp-review-r2 | grep -Eq '/home/[A-Za-z0-9_-]+/'
echo PASS_RELEASE_PORTABILITY

echo "=== [5/8] package and extracted fresh install ==="
sh scripts/package_release.sh
NAME=pcmf-living-memory-r17-r244-native-offline
TMP=$(mktemp -d /tmp/pcmf-r244-install-XXXXXX)
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/pkg" "$TMP/home"
tar -xzf "dist/$NAME.tar.gz" -C "$TMP/pkg"
PKG="$TMP/pkg/$NAME"
HOME="$TMP/home" sh "$PKG/scripts/install.sh" --no-service > "$TMP/install.log"
grep -q 'PASS_INSTALL version=PCMF_LIVING_MEMORY_R17_R244' "$TMP/install.log"
test -x "$TMP/home/.local/bin/pcmf-local-model"
test -x "$TMP/home/.local/lib/pcmf/current/bin/forge-pcmf-owner-review-r4"
test -x "$TMP/home/.local/lib/pcmf/current/connector/pcmf-mcp-review-r2"
test -f "$TMP/home/.local/lib/pcmf/current/assets/pcmf-approval-retro-chime-v2.wav"
HOME="$TMP/home" "$TMP/home/.local/bin/pcmf-local-model" --help | grep -qi 'loopback'
HOME="$TMP/home" "$TMP/home/.local/lib/pcmf/current/bin/forge-pcmf-owner-review-r4"   selfcheck "$TMP/home/.local/share/pcmf" | grep -q PASS_R4_REVIEWER_SELFCHECK
echo PASS_RELEASE_FRESH_INSTALL

echo "=== [6/8] complete application uninstall + desktop cleanup ==="
mkdir -p "$TMP/home/Desktop"   "$TMP/home/.local/share/applications"   "$TMP/home/.config/autostart"   "$TMP/home/.local/share/icons/hicolor/48x48/apps"   "$TMP/home/.local/share/pixmaps"   "$TMP/home/.config/systemd/user"
: > "$TMP/home/Desktop/PCMF Living Memory.desktop"
: > "$TMP/home/.local/share/applications/pcmf.desktop"
: > "$TMP/home/.config/autostart/pcmf-living-memory.desktop"
: > "$TMP/home/.local/share/icons/hicolor/48x48/apps/pcmf.png"
: > "$TMP/home/.local/share/pixmaps/pcmf.svg"
: > "$TMP/home/.config/systemd/user/pcmf.service"

HOME="$TMP/home" "$TMP/home/.local/bin/pcmf-uninstall" --no-service > "$TMP/uninstall.log"
grep -q 'PASS_UNINSTALL_APPLICATION_COMPLETE data_preserved=true' "$TMP/uninstall.log"
test ! -e "$TMP/home/.local/lib/pcmf"
for l in pcmf pcmf-serve pcmf-setup pcmf-local-model pcmf-install pcmf-uninstall pcmf-usb-export; do
  test ! -e "$TMP/home/.local/bin/$l"
done
test ! -e "$TMP/home/.config/pcmf"
test ! -e "$TMP/home/Desktop/PCMF Living Memory.desktop"
test ! -e "$TMP/home/.local/share/applications/pcmf.desktop"
test ! -e "$TMP/home/.config/autostart/pcmf-living-memory.desktop"
test ! -e "$TMP/home/.local/share/icons/hicolor/48x48/apps/pcmf.png"
test ! -e "$TMP/home/.local/share/pixmaps/pcmf.svg"
test ! -e "$TMP/home/.config/systemd/user/pcmf.service"
test -f "$TMP/home/.local/share/pcmf/.pcmf_root"
echo PASS_RELEASE_COMPLETE_UNINSTALL_UI_CLEAN data_preserved=true

echo "=== [7/8] isolated local-llama instance ==="
HOME="$TMP/home" sh "$PKG/scripts/install_instance.sh" \
  local-llama --base "$TMP/instances" > "$TMP/instance.log"
INSTANCE="$TMP/instances/local-llama"
grep -q 'PASS_PCMF_INDEPENDENT_INSTANCE_STAGED' "$TMP/instance.log"
test -x "$INSTANCE/bin/pcmf-local-model"
test -x "$INSTANCE/local-model-health.sh"
test -x "$INSTANCE/local-model-chat.sh"
grep -q '^local_llama_model=sol$' "$INSTANCE/config/instance.conf"
grep -q '^local_llama_memory_transfer=false$' "$INSTANCE/config/instance.conf"
echo PASS_RELEASE_LOCAL_LLAMA_INSTANCE

echo "=== [8/8] guarded full purge + self-uninstall forwarding ==="
HOME="$TMP/home" sh "$PKG/scripts/install.sh" --no-service > "$TMP/reinstall.log"
grep -q 'PASS_INSTALL version=PCMF_LIVING_MEMORY_R17_R244' "$TMP/reinstall.log"
HOME="$TMP/home" sh "$PKG/scripts/install_instance.sh" local-llama > "$TMP/default-instance.log"
test -d "$TMP/home/.local/share/pcmf-instances/local-llama"
printf '%s\n' 'PURGE ALL PCMF DATA AND INSTANCES' |   HOME="$TMP/home" sh "$PKG/scripts/install.sh"   --self-uninstall --purge-all --no-service > "$TMP/purge-all.log"
grep -q 'PASS_UNINSTALL_COMPLETE_PURGE' "$TMP/purge-all.log"
test ! -e "$TMP/home/.local/lib/pcmf"
test ! -e "$TMP/home/.local/share/pcmf"
test ! -e "$TMP/home/.local/share/pcmf-instances"
test ! -e "$TMP/home/.local/bin/pcmf"
test ! -e "$TMP/home/.local/bin/pcmf-uninstall"
echo PASS_RELEASE_COMPLETE_PURGE

echo "PASS_PCMF_R244_STANDALONE_FULL_VERIFICATION"
