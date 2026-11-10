#!/bin/sh
# Configure packaged R16/R4 Forge-GPT local MCP endpoint.
# External tunnel credentials are never created or stored here.
set -eu
umask 077

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PKG_DIR=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)
PCMF="$PKG_DIR/bin/pcmf"
REVIEWER="$PKG_DIR/bin/forge-pcmf-owner-review-r4"
CONNECTOR="$PKG_DIR/connector/pcmf-mcp-review-r2"

ROOT=""
SOCKET=""
PROFILE="personal"
PROJECT="general"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) [ "$#" -ge 2 ] || exit 2; ROOT=$2; shift 2 ;;
    --socket) [ "$#" -ge 2 ] || exit 2; SOCKET=$2; shift 2 ;;
    --profile) [ "$#" -ge 2 ] || exit 2; PROFILE=$2; shift 2 ;;
    --project) [ "$#" -ge 2 ] || exit 2; PROJECT=$2; shift 2 ;;
    --help|-h)
      echo "Usage: configure_forge_gpt_r2.sh --root ROOT [--socket PATH] [--profile personal] [--project general]"
      exit 0 ;;
    *) echo "BLOCKED_FORGE_GPT_SETUP_BAD_ARGUMENT $1" >&2; exit 2 ;;
  esac
done

[ -n "$ROOT" ] || { echo "BLOCKED_FORGE_GPT_SETUP_ROOT_REQUIRED" >&2; exit 2; }
case "$ROOT" in /*) : ;; *) echo "BLOCKED_FORGE_GPT_SETUP_ROOT_NOT_ABSOLUTE" >&2; exit 2 ;; esac
[ -f "$ROOT/.pcmf_root" ] || { echo "BLOCKED_FORGE_GPT_SETUP_ROOT_NOT_INITIALIZED" >&2; exit 2; }
[ -x "$PCMF" ] && [ -x "$REVIEWER" ] && [ -x "$CONNECTOR" ] || {
  echo "BLOCKED_FORGE_GPT_SETUP_PACKAGE_INCOMPLETE" >&2; exit 2;
}

if [ -z "$SOCKET" ]; then
  RUNTIME_DIR=${XDG_RUNTIME_DIR:-${HOME:?}/.local/run}
  SOCKET="$RUNTIME_DIR/pcmf/pcmf.sock"
fi
case "$SOCKET" in /*) : ;; *) echo "BLOCKED_FORGE_GPT_SETUP_SOCKET_NOT_ABSOLUTE" >&2; exit 2 ;; esac

CLIENT=forge_gpt_mcp
CLIENT_KEY="$ROOT/keys/clients/$CLIENT.key"
CFG_DIR=${XDG_CONFIG_HOME:-${HOME:?}/.config}/pcmf
CFG="$CFG_DIR/forge-gpt-r2.json"
mkdir -p "$CFG_DIR"
chmod 700 "$CFG_DIR"

if [ ! -f "$CLIENT_KEY" ]; then
  SCOPES="$CFG_DIR/.forge-gpt-r2-scopes.$$"
  cat > "$SCOPES" <<'EOF'
{"profiles":["personal"],"projects":["general"],"subjects":["*"],"event_classes":["PREFERENCE","PROJECT_STATE","WORKFLOW_STATE","FAILURE_GOTCHA","OBSERVATION","ROUTINE_STATE","COMMITMENT","CORRECTION","REVOCATION"],"max_privacy":"INTERNAL_PROJECT"}
EOF
  chmod 600 "$SCOPES"
  OUT=$("$PCMF" clients register --id "$CLIENT" --role forge --scopes-file "$SCOPES" --root "$ROOT") || {
    rm -f "$SCOPES"
    echo "BLOCKED_FORGE_GPT_CLIENT_REGISTRATION" >&2
    exit 2
  }
  rm -f "$SCOPES"
  printf '%s\n' "$OUT" | grep -q '"status":"OK"' || {
    echo "BLOCKED_FORGE_GPT_CLIENT_REGISTRATION" >&2
    exit 2
  }
fi

[ -f "$CLIENT_KEY" ] || { echo "BLOCKED_FORGE_GPT_CLIENT_KEY_MISSING" >&2; exit 2; }
chmod 600 "$CLIENT_KEY"

ROOT_ID=$(sed -n 's/.*"root_id":"\([0-9a-fA-F]*\)".*/\1/p' "$ROOT/.pcmf_root" | head -n 1)
[ "${#ROOT_ID}" -eq 32 ] || { echo "BLOCKED_FORGE_GPT_ROOT_ID_INVALID" >&2; exit 2; }
case "$ROOT_ID" in *[!0-9a-fA-F]*) echo "BLOCKED_FORGE_GPT_ROOT_ID_INVALID" >&2; exit 2 ;; esac

case "$PROFILE" in *[!A-Za-z0-9_.-]*|"") echo "BLOCKED_FORGE_GPT_PROFILE_INVALID" >&2; exit 2 ;; esac
case "$PROJECT" in *[!A-Za-z0-9_.-]*|"") echo "BLOCKED_FORGE_GPT_PROJECT_INVALID" >&2; exit 2 ;; esac

cat > "$CFG" <<EOF
{"socket":"$SOCKET","root":"$ROOT","root_id":"$ROOT_ID","key_file":"$CLIENT_KEY","client_id":"$CLIENT","profile":"$PROFILE","project":"$PROJECT"}
EOF
chmod 600 "$CFG"

"$REVIEWER" selfcheck "$ROOT" | grep -q PASS_R4_REVIEWER_SELFCHECK || {
  echo "BLOCKED_FORGE_GPT_R4_SELFCHECK" >&2
  exit 2
}

MCP_COMMAND="$CONNECTOR --config $CFG"

if [ -S "$SOCKET" ]; then
  CHECK="$CFG_DIR/.forge-gpt-r2-selfcheck.$$"
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"pcmf-package-selfcheck","version":"1"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pcmf_health","arguments":{}}}'
  } | "$CONNECTOR" --config "$CFG" > "$CHECK" 2>/dev/null || {
    rm -f "$CHECK"
    echo "BLOCKED_FORGE_GPT_R2_HANDSHAKE" >&2
    exit 2
  }
  grep -q '"status":"OK"' "$CHECK" || {
    rm -f "$CHECK"
    echo "BLOCKED_FORGE_GPT_R2_HEALTH" >&2
    exit 2
  }
  rm -f "$CHECK"
  echo "PASS_FORGE_GPT_R16_R4_LOCAL_ENDPOINT"
else
  echo "BLOCKED_FORGE_GPT_SERVICE_NOT_RUNNING local_config_ready=true"
fi

echo "R2_CONFIG=$CFG"
echo "MCP_COMMAND=$MCP_COMMAND"
echo "EXTERNAL_TUNNEL_CREDENTIAL=NOT_STORED_BY_PCMF_PACKAGE"
