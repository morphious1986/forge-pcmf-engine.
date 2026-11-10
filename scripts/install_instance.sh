#!/bin/sh
# PCMF R16/R4: isolated installations from one package.
# Each owns its own independent PCMF writer and local ledger.
set -eu
case "${1:-}" in
 forge-gpt) INSTANCE=forge-gpt; MODEL_PROVIDER=openai; MODEL_ENDPOINT=https://api.openai.com/v1 ;;
 local-llama) INSTANCE=local-llama; MODEL_PROVIDER=llama_cpp; MODEL_ENDPOINT=http://127.0.0.1:8080/v1 ;;
 *) printf '%s\n' "Usage: sh scripts/install_instance.sh forge-gpt|local-llama" >&2; exit 2 ;;
esac
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PKG_DIR=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)
[ -f "$PKG_DIR/manifest.json" ] || { echo "BLOCKED_NO_PACKAGE_MANIFEST" >&2; exit 2; }
[ -x "$PKG_DIR/bin/pcmf-setup" ] || { echo "BLOCKED_UNBUILT_PACKAGE" >&2; exit 2; }
if [ "${2:-}" = "--base" ] && [ "$#" -eq 3 ]; then
 BASE=$3
else
 [ "$#" -eq 1 ] || { echo BLOCKED_BAD_ARGUMENTS >&2; exit 2; }
 BASE=${PCMF_INSTANCES_DIR:-${HOME:?}/.local/share/pcmf-instances}
fi
case "$BASE" in /*) : ;; *) echo BLOCKED_BASE_MUST_BE_ABSOLUTE >&2; exit 2 ;; esac
DEST=$BASE/$INSTANCE
if [ -e "$DEST" ] || [ -L "$DEST" ]; then
 echo "BLOCKED_INSTANCE_ALREADY_EXISTS $DEST (no implicit overwrite)" >&2
 exit 3
fi
# Each installation has its own independent PCMF writer and isolated ledger.
# Never implicitly activate either writer or modify the legacy service.
mkdir -p "$DEST/bin" "$DEST/config" "$DEST/data" "$DEST/run"
chmod 700 "$DEST" "$DEST/config" "$DEST/data" "$DEST/run"
cp "$PKG_DIR/bin/pcmf" "$DEST/bin/pcmf"
cp "$PKG_DIR/bin/pcmf-serve" "$DEST/bin/pcmf-serve"
cp "$PKG_DIR/bin/pcmf-setup" "$DEST/bin/pcmf-setup"
cp "$PKG_DIR/bin/pcmf-local-model" "$DEST/bin/pcmf-local-model"
cp "$PKG_DIR/manifest.json" "$DEST/manifest.json"
{
 printf '%s\n' "instance=$INSTANCE" "edition=$INSTANCE" "provider=$MODEL_PROVIDER"
 printf '%s\n' "endpoint=$MODEL_ENDPOINT" "enabled=false"
 if [ "$INSTANCE" = "local-llama" ]; then
   printf '%s\n' "local_llama_provider=llama_cpp" "local_llama_endpoint=$MODEL_ENDPOINT"
   printf '%s\n' "local_llama_model=sol" "local_llama_enabled=false" "local_llama_memory_transfer=false"
 fi
 printf '%s\n' "memory_transfer=false" "role=independent_pcmf_writer"
 printf '%s\n' "data_root=$DEST/data" "writer_socket=$DEST/run/pcmf.sock" "service_name=pcmf-$INSTANCE"
} > "$DEST/config/instance.conf"
chmod 600 "$DEST/config/instance.conf"
cat > "$DEST/start-local-writer.sh" <<EOF
#!/bin/sh
set -eu
exec "$DEST/bin/pcmf-serve" --root "$DEST/data" --socket "$DEST/run/pcmf.sock" --foreground
EOF
chmod 700 "$DEST/start-local-writer.sh"
cat > "$DEST/pcmf-local.sh" <<EOF
#!/bin/sh
set -eu
exec "$DEST/bin/pcmf" "\$@" --root "$DEST/data"
EOF
chmod 700 "$DEST/pcmf-local.sh"
cat > "$DEST/setup.sh" <<EOF
#!/bin/sh
set -eu
export PCMF_INSTANCE_CONFIG="$DEST/config/instance.conf"
exec "$DEST/bin/pcmf-setup" "\$@"
EOF
chmod 700 "$DEST/setup.sh"
if [ "$INSTANCE" = "local-llama" ]; then
cat > "$DEST/local-model-health.sh" <<EOF
#!/bin/sh
set -eu
CONF="$DEST/config/instance.conf"
ENDPOINT=\$(sed -n 's/^local_llama_endpoint=//p' "\$CONF" | head -n 1)
MODEL=\$(sed -n 's/^local_llama_model=//p' "\$CONF" | head -n 1)
[ -n "\$ENDPOINT" ] && [ -n "\$MODEL" ] || { echo "BLOCKED local llama configuration incomplete" >&2; exit 2; }
exec "$DEST/bin/pcmf-local-model" health --endpoint "\$ENDPOINT" --model "\$MODEL"
EOF
chmod 700 "$DEST/local-model-health.sh"
cat > "$DEST/local-model-chat.sh" <<EOF
#!/bin/sh
set -eu
CONF="$DEST/config/instance.conf"
ENDPOINT=\$(sed -n 's/^local_llama_endpoint=//p' "\$CONF" | head -n 1)
MODEL=\$(sed -n 's/^local_llama_model=//p' "\$CONF" | head -n 1)
[ -n "\$ENDPOINT" ] && [ -n "\$MODEL" ] || { echo "BLOCKED local llama configuration incomplete" >&2; exit 2; }
exec "$DEST/bin/pcmf-local-model" chat --endpoint "\$ENDPOINT" --model "\$MODEL"
EOF
chmod 700 "$DEST/local-model-chat.sh"
fi
printf 'PASS_PCMF_INDEPENDENT_INSTANCE_STAGED instance=%s path=%s writer=independent_not_activated\n' "$INSTANCE" "$DEST"
