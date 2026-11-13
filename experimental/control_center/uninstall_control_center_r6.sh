#!/bin/sh
# Removes only R6 application files; encrypted owner inbox and memory data are preserved.
set -eu
HOME_DIR=${HOME:?}
rm -f "$HOME_DIR/.local/bin/forge-pcmf-control-center" \
  "$HOME_DIR/.local/libexec/pcmf_review_r2_policy.py" \
  "$HOME_DIR/.local/libexec/pending_review_bridge.py" \
  "$HOME_DIR/.local/libexec/deferred_escrow.py" \
  "$HOME_DIR/.local/share/icons/forge-custom-r1/forge-pcmf-control-center.svg" \
  "$HOME_DIR/.local/share/applications/forge-pcmf-control-center.desktop" \
  "$HOME_DIR/Desktop/Forge PCMF Control Center.desktop" \
  "$HOME_DIR/.config/pcmf/control-center-r6.json"
echo "PASS_PCMF_CONTROL_CENTER_R6_UNINSTALL_OWNER_ESCROW_PRESERVED"
