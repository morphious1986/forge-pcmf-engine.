#!/bin/sh
# PCMF R16/R4 complete application uninstaller.
#
# Default removes the complete PCMF application footprint, including service,
# runtime socket, config, CLI links, menu/autostart launchers, and PCMF-owned
# desktop/home-screen icons. Memory data/backups are preserved.
#
# --purge-data additionally erases the configured memory root after exact confirmation.
# --purge-all additionally erases the default isolated PCMF instances.
set -eu

NO_SERVICE=0
PURGE_DATA=0
PURGE_ALL=0

usage(){
    cat <<'EOF'
Usage:
  pcmf-uninstall [--no-service]
  pcmf-uninstall --purge-data [--no-service]
  pcmf-uninstall --purge-all [--no-service]

Default removes the entire PCMF application footprint but preserves memory.
--purge-data also erases the configured PCMF memory root/backups.
--purge-all also erases default isolated PCMF instances.
EOF
}

for a in "$@"; do
    case "$a" in
        --no-service) NO_SERVICE=1 ;;
        --purge-data) PURGE_DATA=1 ;;
        --purge-all) PURGE_DATA=1; PURGE_ALL=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "BLOCKED_UNINSTALL_ARGS_NOT_ACCEPTED $a" >&2; exit 2 ;;
    esac
done

HOME_DIR=${HOME:-}
[ -n "$HOME_DIR" ] || { echo "BLOCKED_UNINSTALL_NO_HOME" >&2; exit 2; }

PREFIX=${PCMF_INSTALL_DIR:-$HOME_DIR/.local/lib/pcmf}
BIN_DIR=${PCMF_BIN_DIR:-$HOME_DIR/.local/bin}
CFG_DIR=$HOME_DIR/.config/pcmf
SYSTEMD_DIR=$HOME_DIR/.config/systemd/user
INSTALLED_JSON=$PREFIX/installed.json

# Capture protected-state locations BEFORE deleting install/config files.
DATA_ROOT=""
SOCKET_PATH=""
if [ -f "$INSTALLED_JSON" ]; then
    DATA_ROOT=$(sed -n 's/.*"data_root"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALLED_JSON" | head -n 1)
    SOCKET_PATH=$(sed -n 's/.*"socket"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALLED_JSON" | head -n 1)
fi
if [ -f "$CFG_DIR/pcmf.conf" ]; then
    [ -n "$DATA_ROOT" ] || DATA_ROOT=$(sed -n 's/^data_root=//p' "$CFG_DIR/pcmf.conf" | head -n 1)
    [ -n "$SOCKET_PATH" ] || SOCKET_PATH=$(sed -n 's/^socket=//p' "$CFG_DIR/pcmf.conf" | head -n 1)
fi
[ -n "$DATA_ROOT" ] || DATA_ROOT=${PCMF_DATA_ROOT:-$HOME_DIR/.local/share/pcmf}
if [ -z "$SOCKET_PATH" ]; then
    runtime_dir=${XDG_RUNTIME_DIR:-$HOME_DIR/.local/run}
    SOCKET_PATH=$runtime_dir/pcmf/pcmf.sock
fi

case "$DATA_ROOT" in
    /*) : ;;
    *) echo "BLOCKED_UNINSTALL_DATA_ROOT_NOT_ABSOLUTE" >&2; exit 2 ;;
esac
case "$SOCKET_PATH" in
    /*) : ;;
    *) echo "BLOCKED_UNINSTALL_SOCKET_NOT_ABSOLUTE" >&2; exit 2 ;;
esac

# Validate every deletion boundary BEFORE any cleanup. A custom installation
# directory cannot be interpreted as permission to delete an arbitrary tree.
SCRIPT_FILE=$(readlink -f -- "$0") || { echo "BLOCKED_UNINSTALL_SCRIPT_REALPATH" >&2; exit 2; }
VALIDATOR=$(CDPATH= cd -- "$(dirname -- "$SCRIPT_FILE")" && pwd)/public_safety_paths.py
command -v python3 >/dev/null 2>&1 || {
    echo "BLOCKED_UNINSTALL_PYTHON3_VALIDATOR_REQUIRED" >&2
    exit 2
}
MODE=uninstall
if [ "$PURGE_ALL" = "1" ]; then MODE=purge-all
elif [ "$PURGE_DATA" = "1" ]; then MODE=purge-data
fi
python3 "$VALIDATOR" "$MODE" "$HOME_DIR" "$PREFIX" "$BIN_DIR" "$CFG_DIR"     "$DATA_ROOT" "$SOCKET_PATH"     "${PCMF_INSTANCES_DIR:-$HOME_DIR/.local/share/pcmf-instances}" || {
    echo "BLOCKED_UNINSTALL_PATH_VALIDATION_FAILED" >&2
    exit 2
}

echo "PCMF complete application uninstall"

# 1. Stop and disable only the PCMF-owned user service.
if [ "$NO_SERVICE" != "1" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now pcmf.service >/dev/null 2>&1 \
        && echo "  service stopped and disabled" \
        || echo "  service already inactive or user systemd unavailable"
fi
rm -f "$SYSTEMD_DIR/pcmf.service" 2>/dev/null || :
if [ "$NO_SERVICE" != "1" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload >/dev/null 2>&1 || :
fi

# 2. Remove PCMF runtime socket and now-empty runtime directory only.
if [ -S "$SOCKET_PATH" ]; then
    rm -f "$SOCKET_PATH"
elif [ -e "$SOCKET_PATH" ]; then
    echo "BLOCKED_UNINSTALL_SOCKET_NOT_A_SOCKET" >&2
    exit 2
fi
SOCKET_DIR=$(dirname "$SOCKET_PATH")
case "$SOCKET_DIR" in
    "$HOME_DIR"/*|${XDG_RUNTIME_DIR:-/nonexistent}/*) rmdir "$SOCKET_DIR" 2>/dev/null || : ;;
esac

# 3. Remove exact PCMF CLI launchers.
for l in pcmf pcmf-serve pcmf-setup pcmf-local-model pcmf-forge-gpt-setup pcmf-install pcmf-uninstall pcmf-usb-export; do
    rm -f "$BIN_DIR/$l" 2>/dev/null || :
done

# 4. Remove exact PCMF-owned desktop/menu/autostart launchers and icons.
desktop_dir="$HOME_DIR/Desktop"
if command -v xdg-user-dir >/dev/null 2>&1; then
    candidate=$(xdg-user-dir DESKTOP 2>/dev/null || :)
    case "$candidate" in "$HOME_DIR"/*) desktop_dir=$candidate ;; esac
fi

for d in "$desktop_dir" "$HOME_DIR/.local/share/applications" "$HOME_DIR/.config/autostart"; do
    rm -f \
        "$d/pcmf.desktop" \
        "$d/pcmf-living-memory.desktop" \
        "$d/PCMF Living Memory.desktop" \
        2>/dev/null || :
done

for f in \
    "$HOME_DIR/.local/share/pixmaps/pcmf.png" \
    "$HOME_DIR/.local/share/pixmaps/pcmf.svg" \
    "$HOME_DIR/.icons/pcmf.png" \
    "$HOME_DIR/.icons/pcmf.svg"
do
    rm -f "$f" 2>/dev/null || :
done

for size in 16x16 22x22 24x24 32x32 48x48 64x64 128x128 256x256 512x512 scalable; do
    rm -f \
        "$HOME_DIR/.local/share/icons/hicolor/$size/apps/pcmf.png" \
        "$HOME_DIR/.local/share/icons/hicolor/$size/apps/pcmf.svg" \
        "$HOME_DIR/.local/share/icons/hicolor/$size/apps/pcmf-living-memory.png" \
        "$HOME_DIR/.local/share/icons/hicolor/$size/apps/pcmf-living-memory.svg" \
        2>/dev/null || :
done

if [ "$NO_SERVICE" != "1" ]; then
    command -v update-desktop-database >/dev/null 2>&1 \
        && update-desktop-database "$HOME_DIR/.local/share/applications" >/dev/null 2>&1 || :
    command -v gtk-update-icon-cache >/dev/null 2>&1 \
        && gtk-update-icon-cache -f -t "$HOME_DIR/.local/share/icons/hicolor" >/dev/null 2>&1 || :
fi

# 5. Remove the complete installed program tree and install-level config.
rm -rf "$PREFIX"
rm -rf "$CFG_DIR"
echo "  application files, launchers, service, config, and PCMF UI artifacts removed"

# 6. Optional guarded data purge.
if [ "$PURGE_DATA" = "1" ]; then
    if [ "$PURGE_ALL" = "1" ]; then
        expected="PURGE ALL PCMF DATA AND INSTANCES"
        printf "Type '%s' to erase PCMF memory/backups and isolated instances: " "$expected"
    else
        expected="PURGE ALL PCMF MEMORY DATA"
        printf "Type '%s' to erase the PCMF memory root and backups: " "$expected"
    fi
    read -r answer || answer=""
    if [ "$answer" != "$expected" ]; then
        echo "  confirmation mismatch - memory data was NOT purged"
        echo "PASS_UNINSTALL_APPLICATION_COMPLETE data_preserved=true"
        exit 0
    fi

    case "$DATA_ROOT" in
        /|"$HOME_DIR"|"$HOME_DIR/"|/home|/home/|/tmp|/tmp/)
            echo "BLOCKED_UNINSTALL_UNSAFE_DATA_ROOT $DATA_ROOT" >&2
            exit 2
            ;;
    esac
    rm -rf "$DATA_ROOT"
    echo "  memory data/backups purged: $DATA_ROOT"

    if [ "$PURGE_ALL" = "1" ]; then
        INSTANCES_DIR=${PCMF_INSTANCES_DIR:-$HOME_DIR/.local/share/pcmf-instances}
        case "$INSTANCES_DIR" in
            "$HOME_DIR"/*)
                rm -rf "$INSTANCES_DIR"
                echo "  isolated PCMF instances purged: $INSTANCES_DIR"
                ;;
            *)
                echo "BLOCKED_UNINSTALL_UNSAFE_INSTANCES_ROOT $INSTANCES_DIR" >&2
                exit 2
                ;;
        esac
        echo "PASS_UNINSTALL_COMPLETE_PURGE"
        exit 0
    fi
    echo "PASS_UNINSTALL_APPLICATION_AND_DATA_PURGE"
    exit 0
fi

echo "  preserved memory data/backups: $DATA_ROOT"
echo "PASS_UNINSTALL_APPLICATION_COMPLETE data_preserved=true"
exit 0
