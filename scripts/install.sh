#!/bin/sh
# ============================================================================
# PCMF Living Memory R14 - self-contained offline installer (POSIX sh).
#
#   install.sh                     install or update (auto-detected)
#   install.sh --no-service        install without touching any service
#   install.sh --authorize-cutover explicit owner authorization to replace
#                                  an existing ACTIVE service
#   install.sh --rollback          switch active release to previous version
#   install.sh --self-uninstall    complete application uninstall; memory KEPT
#   install.sh --self-uninstall --purge-data
#                                  also erase PCMF memory/backups after confirmation
#   install.sh --self-uninstall --purge-all
#                                  also erase default isolated PCMF instances
#
# Guarantees:
#   - package integrity is verified (SHA256SUMS) before anything is changed
#   - an existing ACTIVE service is never replaced without explicit owner
#     authorization
#   - the current working installation is never deleted before the
#     replacement is installed AND tested
#   - memory data (data root) and backups are never touched by program
#     installation
#   - exactly ONE active installed version remains after success
# ============================================================================
set -eu

SCRIPT_FILE=$(readlink -f -- "$0") || fail "SCRIPT_REALPATH_UNAVAILABLE"
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$SCRIPT_FILE")" && pwd)
# package root: this dir, or the parent when invoked as scripts/install.sh
if [ -f "$SELF_DIR/manifest.json" ]; then
    PKG_DIR=$SELF_DIR
elif [ -f "$SELF_DIR/../manifest.json" ]; then
    PKG_DIR=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)
else
    PKG_DIR=""
fi
HOLD="HOLD_R241_R242"

log(){ printf '%s\n' "$*"; }
fail(){ printf 'FAIL_INSTALL %s\n' "$*" >&2; exit 1; }

command_exists(){ command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- arguments
MODE="install"
NO_SERVICE=0
AUTH_CUTOVER=0
UNINSTALL_PURGE_DATA=0
UNINSTALL_PURGE_ALL=0
for a in "$@"; do
    case "$a" in
        --no-service) NO_SERVICE=1 ;;
        --authorize-cutover) AUTH_CUTOVER=1 ;;
        --rollback) MODE="rollback" ;;
        --self-uninstall) MODE="uninstall" ;;
        --purge-data) UNINSTALL_PURGE_DATA=1 ;;
        --purge-all) UNINSTALL_PURGE_DATA=1; UNINSTALL_PURGE_ALL=1 ;;
        --help|-h) sed -n '2,18p' "$0"; exit 0 ;;
        *) fail "ARGS_NOT_ACCEPTED $a" ;;
    esac
done

if [ "$MODE" != "uninstall" ] && { [ "$UNINSTALL_PURGE_DATA" = "1" ] || [ "$UNINSTALL_PURGE_ALL" = "1" ]; }; then
    fail "PURGE_FLAGS_REQUIRE_SELF_UNINSTALL"
fi

# ---------------------------------------------------------------- manifest
[ -f "$PKG_DIR/manifest.json" ] || fail "NO_MANIFEST"
VERSION=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PKG_DIR/manifest.json" | head -n 1)
BUILD_ID=$(sed -n 's/.*"build_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PKG_DIR/manifest.json" | head -n 1)
[ -n "$VERSION" ] || fail "MANIFEST_VERSION_UNREADABLE"

HOME_DIR=${HOME:-$(cd; pwd)}
[ -n "${HOME:-}" ] || fail "NO_HOME"

# ------------------------------------------------------- uninstall shortcut
if [ "$MODE" = "uninstall" ]; then
    UNINSTALLER="$PKG_DIR/scripts/uninstall.sh"
    [ -f "$UNINSTALLER" ] || fail "UNINSTALLER_MISSING"
    if [ "$UNINSTALL_PURGE_ALL" = "1" ]; then
        if [ "$NO_SERVICE" = "1" ]; then exec sh "$UNINSTALLER" --purge-all --no-service
        else exec sh "$UNINSTALLER" --purge-all
        fi
    elif [ "$UNINSTALL_PURGE_DATA" = "1" ]; then
        if [ "$NO_SERVICE" = "1" ]; then exec sh "$UNINSTALLER" --purge-data --no-service
        else exec sh "$UNINSTALLER" --purge-data
        fi
    else
        if [ "$NO_SERVICE" = "1" ]; then exec sh "$UNINSTALLER" --no-service
        else exec sh "$UNINSTALLER"
        fi
    fi
fi

# ---------------------------------------------------------------- integrity
log "[1/9] Verifying release package integrity (version $VERSION build $BUILD_ID)"
if command_exists sha256sum; then
    ( cd "$PKG_DIR" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) \
        || fail "PACKAGE_CHECKSUM_MISMATCH"
else
    fail "SHA256SUM_TOOL_MISSING"
fi
log "OK package checksums verified"

# ---------------------------------------------------------------- locations
PREFIX=${PCMF_INSTALL_DIR:-$HOME_DIR/.local/lib/pcmf}
BIN_DIR=${PCMF_BIN_DIR:-$HOME_DIR/.local/bin}
CFG_DIR=$HOME_DIR/.config/pcmf
SYSTEMD_DIR=$HOME_DIR/.config/systemd/user
VERSIONS_DIR=$PREFIX/versions
STAGE_NAME="$VERSION-$BUILD_ID"
STAGE_DIR=$VERSIONS_DIR/$STAGE_NAME
INSTALLED_JSON=$PREFIX/installed.json
UNIT_SRC=$PKG_DIR/systemd/pcmf.service

# data root: existing config > env > default
DATA_ROOT=""
if [ -f "$CFG_DIR/pcmf.conf" ]; then
    DATA_ROOT=$(sed -n 's/^data_root=//p' "$CFG_DIR/pcmf.conf" | head -n 1)
fi
[ -n "$DATA_ROOT" ] || DATA_ROOT=${PCMF_DATA_ROOT:-$HOME_DIR/.local/share/pcmf}

socket_dir=${XDG_RUNTIME_DIR:-$HOME_DIR/.local/run}
SOCKET_PATH="$socket_dir/pcmf/pcmf.sock"

# Fail closed before any staged write or service discovery.
command_exists python3 || fail "PUBLIC_PATH_VALIDATOR_PYTHON3_MISSING"
python3 "$PKG_DIR/scripts/public_safety_paths.py" install "$HOME_DIR" "$PREFIX"     "$BIN_DIR" "$CFG_DIR" "$DATA_ROOT" "$SOCKET_PATH"     "$HOME_DIR/.local/share/pcmf-instances" || fail "PUBLIC_INSTALL_PATH_BOUNDARY"

# ------------------------------------------------------- existing detection
log "[2/9] Detecting existing PCMF installations"
EXISTING_ACTIVE=""
EXISTING_RUNNING=0
if [ -L "$PREFIX/current" ]; then
    EXISTING_ACTIVE=$(basename "$(readlink "$PREFIX/current")")
    log "  existing active version: $EXISTING_ACTIVE"
fi
if [ -f "$INSTALLED_JSON" ]; then
    log "  existing install manifest found: $INSTALLED_JSON"
fi
if [ "$NO_SERVICE" != "1" ] && command_exists systemctl; then
    if systemctl --user is-active --quiet pcmf.service 2>/dev/null; then
        EXISTING_RUNNING=1
        log "  existing service: RUNNING (pcmf.service, systemd user scope)"
    else
        log "  existing service: not running or systemd user session unavailable"
    fi
else
    log "  systemctl not available on this system"
fi

if [ "$MODE" = "rollback" ]; then
    # ------------------------------------------------------------- rollback
    [ -f "$INSTALLED_JSON" ] || fail "NO_INSTALL_TO_ROLLBACK"
    PREV=$(sed -n 's/.*"previous_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INSTALLED_JSON" | head -n 1)
    [ -n "$PREV" ] || fail "NO_PREVIOUS_VERSION_RECORDED"
    PREV_DIR=""
    for d in "$VERSIONS_DIR/$PREV" "$VERSIONS_DIR"/"$PREV"-*; do
        [ -d "$d" ] && PREV_DIR=$d
    done
    [ -n "$PREV_DIR" ] || fail "PREVIOUS_VERSION_DIR_MISSING $PREV"
    log "[rollback] switching active release $EXISTING_ACTIVE -> $PREV"
    if [ "$EXISTING_RUNNING" = "1" ] && [ "$AUTH_CUTOVER" != "1" ]; then
        fail "SERVICE_CUTOVER_AUTHORIZATION_REQUIRED (--authorize-cutover)"
    fi
    if [ "$EXISTING_RUNNING" = "1" ]; then
        systemctl --user stop pcmf.service || true
    fi
    ln -sfn "$PREV_DIR" "$PREFIX/current"
    if [ "$EXISTING_RUNNING" = "1" ]; then
        systemctl --user start pcmf.service
    fi
    # update manifest
    ACTIVE_NOW=$PREV
    PREV_BACK=$EXISTING_ACTIVE
    TMP_JSON="$INSTALLED_JSON.tmp.$$"
    sed -e "s/\"active_version\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"active_version\": \"$ACTIVE_NOW\"/" \
        -e "s/\"previous_version\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/\"previous_version\": \"$PREV_BACK\"/" \
        "$INSTALLED_JSON" > "$TMP_JSON"
    mv "$TMP_JSON" "$INSTALLED_JSON"
    # health check
    if ! "$PREFIX/current/bin/pcmf" status >/dev/null 2>&1; then
        log "  WARNING: store status not OK after rollback (inspect with pcmf status)"
    fi
    log "PASS_ROLLBACK active=$ACTIVE_NOW restored_from=$PREV_BACK data_root=$DATA_ROOT"
    exit 0
fi

# ------------------------------------------------------------------- stage
log "[3/9] Staging release into $STAGE_DIR (current active stays untouched)"
[ ! -e "$STAGE_DIR" ] || fail "STAGE_ALREADY_EXISTS $STAGE_DIR"
mkdir -p "$VERSIONS_DIR"
cp -a "$PKG_DIR" "$STAGE_DIR"
rm -f "$STAGE_DIR"/pcmf-living-memory-*.tar.gz "$STAGE_DIR"/*.sha256 2>/dev/null || :
# verify the staged copy byte-for-byte against the package manifest
( cd "$STAGE_DIR" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) \
    || { rm -rf "$STAGE_DIR"; fail "STAGED_COPY_CHECKSUM_MISMATCH"; }
log "OK staged copy verified"

# -------------------------------------------------------- staged self test
log "[4/9] Running native selftest (quick subset) from the staged release"
if ! "$STAGE_DIR/bin/pcmf-selftest" quick "$STAGE_DIR/bin" >/dev/null 2>&1; then
    "$STAGE_DIR/bin/pcmf-selftest" quick "$STAGE_DIR/bin" | tail -n 8 || :
    rm -rf "$STAGE_DIR"
    fail "STAGED_SELFTEST_FAILED"
fi
log "OK staged selftest passed"

# --------------------------------------------------------------- data root
log "[5/9] Securing memory data root: $DATA_ROOT (protected; never replaced)"
if [ -f "$DATA_ROOT/.pcmf_root" ]; then
    log "  existing initialized data root detected - memory data PRESERVED"
else
    mkdir -p "$(dirname "$DATA_ROOT")" 2>/dev/null || :
    if ! "$STAGE_DIR/bin/pcmf" init --root "$DATA_ROOT" >/dev/null 2>&1; then
        log "  data root not initialized during install (init it later via"
        log "  'pcmf init --root $DATA_ROOT' or the setup menu, item 1)"
    else
        log "  fresh data root initialized at $DATA_ROOT"
    fi
fi
# pre-update protective backup of memory data when a root already exists
if [ -f "$DATA_ROOT/.pcmf_root" ] && [ -n "$EXISTING_ACTIVE" ]; then
    log "  creating protective pre-update backup of memory data"
    "$STAGE_DIR/bin/pcmf" backup create --name "preupdate-$BUILD_ID" \
        --root "$DATA_ROOT" >/dev/null 2>&1 \
        && log "  backup preupdate-$BUILD_ID created" \
        || log "  WARNING: pre-update backup failed (continuing; data root untouched)"
fi

# ------------------------------------------------------- cutover decision
CUTOVER=0
if [ -n "$EXISTING_ACTIVE" ] || [ "$EXISTING_RUNNING" = "1" ]; then
    log "[6/9] Existing installation present - replacement requires owner authorization"
    if [ "$AUTH_CUTOVER" = "1" ]; then
        CUTOVER=1
        log "  owner authorization provided (--authorize-cutover)"
    elif [ -t 0 ]; then
        printf "  Type 'I AUTHORIZE CUTOVER' to replace active version %s: " "$EXISTING_ACTIVE"
        read -r ANSWER || ANSWER=""
        [ "$ANSWER" = "I AUTHORIZE CUTOVER" ] && CUTOVER=1
    fi
    if [ "$CUTOVER" != "1" ]; then
        log "  NO AUTHORIZATION: staged at $STAGE_DIR; active release $EXISTING_ACTIVE"
        log "  remains untouched. Re-run with --authorize-cutover to complete."
        log "HOLD_SERVICE_CUTOVER_NOT_AUTHORIZED canonical_writer=$HOLD"
        log "PASS_INSTALL_STAGED version=$VERSION build=$BUILD_ID active=$EXISTING_ACTIVE"
        exit 0
    fi
fi

# --------------------------------------------------------------- activate
log "[7/9] Activating release $STAGE_NAME (previous kept as recovery)"
mkdir -p "$BIN_DIR" "$CFG_DIR"
ln -sfn "$STAGE_DIR" "$PREFIX/current"
ln -sf "$PREFIX/current/bin/pcmf"        "$BIN_DIR/pcmf"
ln -sf "$PREFIX/current/bin/pcmf-serve"  "$BIN_DIR/pcmf-serve"
ln -sf "$PREFIX/current/bin/pcmf-setup"  "$BIN_DIR/pcmf-setup"
ln -sf "$PREFIX/current/bin/pcmf-local-model" "$BIN_DIR/pcmf-local-model"
ln -sf "$PREFIX/current/scripts/install.sh"   "$BIN_DIR/pcmf-install"
ln -sf "$PREFIX/current/scripts/uninstall.sh" "$BIN_DIR/pcmf-uninstall"
ln -sf "$PREFIX/current/scripts/usb_export.sh" "$BIN_DIR/pcmf-usb-export"
ln -sf "$PREFIX/current/scripts/configure_forge_gpt_r2.sh" "$BIN_DIR/pcmf-forge-gpt-setup"

# install-level config
CONF_TMP="$CFG_DIR/pcmf.conf.tmp.$$"
{
    [ -f "$CFG_DIR/pcmf.conf" ] && grep -v '^install_version=' "$CFG_DIR/pcmf.conf" || :
    echo "data_root=$DATA_ROOT"
    echo "install_version=$VERSION"
    echo "socket=$SOCKET_PATH"
} > "$CONF_TMP"
mv "$CONF_TMP" "$CFG_DIR/pcmf.conf"
chmod 600 "$CFG_DIR/pcmf.conf" 2>/dev/null || :

# --------------------------------------------------------------- service
log "[8/9] Service integration (systemd user scope)"
SERVICE_STARTED=0
if [ "$NO_SERVICE" = "1" ]; then
    log "  --no-service: skipping service activation (owner-requested)"
elif ! command_exists systemctl; then
    log "  HOLD: systemctl not available; run the daemon manually:"
    log "    $PREFIX/current/bin/pcmf-serve --root $DATA_ROOT"
elif ! mkdir -p "$SYSTEMD_DIR" 2>/dev/null; then
    log "  HOLD: cannot create $SYSTEMD_DIR"
else
    {
        sed -e "s|@DATA_ROOT@|$DATA_ROOT|g"             -e "s|@SOCKET_PATH@|$SOCKET_PATH|g" "$UNIT_SRC"
    } > "$SYSTEMD_DIR/pcmf.service"
    if systemctl --user daemon-reload 2>/dev/null \
       && systemctl --user enable --now pcmf.service 2>/dev/null; then
        SERVICE_STARTED=1
        log "  service enabled and started (pcmf.service)"
    else
        log "  HOLD: systemd user session unavailable (linger/logind). Unit"
        log "  installed at $SYSTEMD_DIR/pcmf.service - it starts on next"
        log "  login, or run: systemctl --user enable --now pcmf.service"
    fi
fi

# ------------------------------------------------------------ verification
log "[9/9] Post-install verification"
"$PREFIX/current/bin/pcmf" version >/dev/null || { rm -f "$PREFIX/current"; fail "POST_INSTALL_VERIFY_FAILED"; }
HEALTH_OK=0
if "$PREFIX/current/bin/pcmf" status --root "$DATA_ROOT" >/dev/null 2>&1; then
    HEALTH_OK=1
    log "  memory store status: reachable"
else
    log "  memory store status: not initialized yet (use setup menu item 1)"
fi
if [ "$SERVICE_STARTED" = "1" ]; then
    WAIT=0
    while [ $WAIT -lt 20 ]; do
        if [ -S "$SOCKET_PATH" ]; then break; fi
        WAIT=$((WAIT+1)); sleep 1
    done
    if [ -S "$SOCKET_PATH" ]; then
        log "  daemon socket: $SOCKET_PATH"
    else
        log "  WARNING: service active but socket not observed yet"
    fi
fi

# ------------------------------------------------- cleanup obsolete versions
PREV_KEPT=""
if [ -n "$EXISTING_ACTIVE" ] && [ "$EXISTING_ACTIVE" != "$VERSION" ]; then
    for d in "$VERSIONS_DIR"/*; do
        [ -d "$d" ] || continue
        name=$(basename "$d")
        case "$name" in
            "$STAGE_NAME") : ;;
            "$EXISTING_ACTIVE"*) PREV_KEPT=$name ;;
            *) rm -rf "$d" ;;
        esac
    done
fi

# manifest
MAN_TMP="$INSTALLED_JSON.tmp.$$"
{
    echo "{"
    echo "  \"active_version\": \"$VERSION\","
    echo "  \"previous_version\": \"$EXISTING_ACTIVE\","
    echo "  \"updated_at\": \"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\","
    echo "  \"data_root\": \"$DATA_ROOT\","
    echo "  \"socket\": \"$SOCKET_PATH\","
    echo "  \"service_started\": $SERVICE_STARTED,"
    echo "  \"canonical_writer\": \"$HOLD\""
    echo "}"
} > "$MAN_TMP"
mv "$MAN_TMP" "$INSTALLED_JSON"
chmod 600 "$INSTALLED_JSON" 2>/dev/null || :

log ""
log "PASS_INSTALL version=$VERSION build=$BUILD_ID active=$STAGE_NAME"
log "  data_root=$DATA_ROOT (protected)"
log "  binaries: $BIN_DIR/{pcmf,pcmf-serve,pcmf-setup,pcmf-local-model,pcmf-forge-gpt-setup}"
log "  setup menu: pcmf-setup"
[ -n "$PREV_KEPT" ] && log "  recovery release kept: $PREV_KEPT"
[ "$SERVICE_STARTED" = "0" ] && [ "$NO_SERVICE" = "0" ] \
    && log "  HOLD: SERVICE_NOT_ACTIVATED (systemd user session unavailable)"
log "  canonical_writer=$HOLD (never bypassed)"
exit 0
