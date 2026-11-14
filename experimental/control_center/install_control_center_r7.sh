#!/bin/sh
# R6 owner-governed GUI addon; only called after verified native PCMF activation.
set -eu
STAGE_DIR=$1
HOME_DIR=$2
DATA_ROOT=$3
BIN_DIR="$HOME_DIR/.local/bin"
LIB_DIR="$HOME_DIR/.local/libexec"
ICON_DIR="$HOME_DIR/.local/share/icons/forge-custom-r1"
APP_DIR="$HOME_DIR/.local/share/applications"
CFG="$HOME_DIR/.config/pcmf"
mkdir -p "$BIN_DIR" "$LIB_DIR" "$ICON_DIR" "$APP_DIR" "$CFG"
install -m 0755 "$STAGE_DIR/control_center/forge-pcmf-control-center" "$BIN_DIR/forge-pcmf-control-center"
for module in pcmf_review_r2_policy.py pending_review_bridge.py deferred_escrow.py passphrase_manager.py; do
  install -m 0644 "$STAGE_DIR/control_center/$module" "$LIB_DIR/$module"
done
install -m 0644 "$STAGE_DIR/control_center/forge-pcmf-control-center.svg" "$ICON_DIR/forge-pcmf-control-center.svg"
python3 - "$STAGE_DIR/bin/pcmf" "$DATA_ROOT" "$CFG/control-center-r6.json" "$STAGE_DIR/bin/forge-pcmf-owner-review-r4" <<'PY'
import json,os,subprocess,sys,tempfile
binary,root,config,reviewer=sys.argv[1:]
if not all(os.path.isabs(p) for p in (binary,root,config,reviewer)):
    raise SystemExit("BLOCKED_R6_CONFIGURATION_PATH")
status=subprocess.run([binary,"status","--root",root],capture_output=True,text=True,timeout=12)
if status.returncode:
    raise SystemExit("BLOCKED_R6_CANONICAL_STATUS")
data=json.loads(status.stdout)
root_id=data.get("root_id")
if data.get("root")!=root or data.get("healthy") is not True or data.get("chain_ok") is not True or data.get("index_ok") is not True or not isinstance(root_id,str) or len(root_id)!=32:
    raise SystemExit("BLOCKED_R6_CANONICAL_IDENTITY")
settings={"root":root,"root_id":root_id,"binary":binary,"reviewer":reviewer}
fd,temp=tempfile.mkstemp(prefix="control-center-r6.",suffix=".tmp",dir=os.path.dirname(config))
try:
    os.fchmod(fd,0o600)
    with os.fdopen(fd,"w") as stream:
        json.dump(settings,stream,sort_keys=True)
        stream.write("\n")
        stream.flush();os.fsync(stream.fileno())
    os.replace(temp,config)
except Exception:
    if os.path.exists(temp):os.unlink(temp)
    raise
PY
for target in "$APP_DIR/forge-pcmf-control-center.desktop" "$HOME_DIR/Desktop/Forge PCMF Control Center.desktop"; do
  [ -d "$(dirname "$target")" ] || continue
  {
    printf '%s\n' '[Desktop Entry]' 'Version=1.0' 'Type=Application'
    printf '%s\n' 'Name=Forge PCMF Control Center' 'Comment=Owner-controlled PCMF approvals and encrypted deferred inbox'
    printf 'Exec=/usr/bin/python3 %s/forge-pcmf-control-center\n' "$BIN_DIR"
    printf 'Icon=%s/forge-pcmf-control-center.svg\n' "$ICON_DIR"
    printf '%s\n' 'Terminal=false' 'Categories=Development;Utility;' 'StartupNotify=true'
  } > "$target"
  chmod 755 "$target"
done
echo "PASS_PCMF_CONTROL_CENTER_R7_ADDON_INSTALL"
