#!/bin/sh
# PCMF Living Memory R14 - USB export procedure.
#
# Exports a complete versioned release to a mounted USB destination:
#   - detects the mounted removable USB destination (or accepts --dest)
#   - copies the full release tree
#   - writes manifest + SHA256SUMS on the destination
#   - verifies archive/file integrity and byte-for-byte equality (cmp)
#   - preserves previous recovery releases already on the USB device
#
# usage: usb_export.sh [--src RELEASE_DIR] [--dest /mount/point] [--verify-only]
set -eu

HOLD="HOLD_R241_R242"
SRC=""
DEST=""
VERIFY_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --src) SRC=${2:-}; shift 2 ;;
        --dest) DEST=${2:-}; shift 2 ;;
        --verify-only) VERIFY_ONLY=1; shift ;;
        *) echo "FAIL_USB_EXPORT ARGS $1"; exit 1 ;;
    esac
done

# resolve source: default = this release package
if [ -z "$SRC" ]; then
    SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    if [ -f "$SELF_DIR/../manifest.json" ]; then
        SRC=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)
    elif [ -f "$SELF_DIR/manifest.json" ]; then
        SRC=$SELF_DIR
    else
        echo "FAIL_USB_EXPORT NO_SOURCE (pass --src with a release package dir)"
        exit 1
    fi
fi
[ -f "$SRC/manifest.json" ] || { echo "FAIL_USB_EXPORT SRC_NOT_RELEASE"; exit 1; }
VERSION=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$SRC/manifest.json" | head -n 1)
BUILD_ID=$(sed -n 's/.*"build_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$SRC/manifest.json" | head -n 1)
[ -n "$VERSION" ] || { echo "FAIL_USB_EXPORT MANIFEST_UNREADABLE"; exit 1; }
NAME="$VERSION-$BUILD_ID"

# source self-check first
( cd "$SRC" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) \
    || { echo "FAIL_USB_EXPORT SOURCE_CHECKSUM_MISMATCH"; exit 1; }
echo "[usb] source verified: $SRC ($NAME)"

# destination detection: mounted removable devices via /proc/mounts + /sys
detect_usb(){
    lsblk -d -n -o NAME,TRAN,RM 2>/dev/null | awk '$2=="usb"||$3==1{print $1}' |
    while read -r dev; do
        [ -n "$dev" ] || continue
        grep " /dev/$dev" /proc/mounts 2>/dev/null | awk '$3!~/(squashfs|iso9660)/{print $2}' || :
    done
}

if [ -z "$DEST" ]; then
    echo "[usb] scanning for mounted removable destinations..."
    CANDIDATES=$(detect_usb || :)
    if [ -z "$CANDIDATES" ]; then
        echo "FAIL_USB_EXPORT NO_USB_MOUNTED (mount the device and retry, or pass --dest)"
        exit 1
    fi
    i=0
    for c in $CANDIDATES; do
        i=$((i+1)); echo "  [$i] $c"
    done
    if [ ! -t 0 ]; then
        DEST=$(printf '%s\n' $CANDIDATES | head -n 1)
        echo "[usb] non-interactive: selecting first candidate $DEST"
    else
        printf "Select destination [1]: "
        read -r SEL || SEL=""
        [ -n "$SEL" ] || SEL=1
        DEST=$(printf '%s\n' $CANDIDATES | sed -n "${SEL}p")
    fi
fi
[ -n "$DEST" ] && [ -d "$DEST" ] || { echo "FAIL_USB_EXPORT DEST_NOT_DIR"; exit 1; }
if ! touch "$DEST/.pcmf_write_test" 2>/dev/null; then
    echo "FAIL_USB_EXPORT DEST_NOT_WRITABLE"; exit 1
fi
rm -f "$DEST/.pcmf_write_test"

TARGET="$DEST/PCMF_RELEASES/$NAME"
if [ "$VERIFY_ONLY" = "1" ]; then
    [ -d "$TARGET" ] || { echo "FAIL_USB_EXPORT TARGET_MISSING $TARGET"; exit 1; }
    ( cd "$TARGET" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) \
        || { echo "FAIL_USB_EXPORT TARGET_CHECKSUM_MISMATCH"; exit 1; }
    echo "PASS_USB_VERIFY target=$TARGET"
    exit 0
fi

echo "[usb] exporting $NAME -> $TARGET"
if [ -d "$TARGET" ]; then
    echo "  target release already present - refreshing in place (previous recovery releases preserved)"
fi
mkdir -p "$TARGET"
# copy everything except previous tarballs, then re-write checksums
( cd "$SRC" && tar -cf - --exclude='SHA256SUMS' --exclude='*.tar.gz' --exclude='*.sha256' . ) \
    | ( cd "$TARGET" && tar -xf - )
( cd "$TARGET" && find . -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )

# also copy the install tarball when present (for fully offline transfer)
for tb in "$SRC"/*.tar.gz; do
    [ -f "$tb" ] && cp -f "$tb" "$TARGET/" || :
done
[ -f "$SRC/../$NAME-ubuntu-amd64.tar.gz" ] && cp -f "$SRC/../$NAME-ubuntu-amd64.tar.gz" "$TARGET/" 2>/dev/null || :

# verification: checksum pass + byte-for-byte cmp of every original file
FAILS=0
( cd "$TARGET" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) || FAILS=1
( cd "$SRC" && find . -type f ! -name SHA256SUMS -print0 | sort -z ) > /tmp/pcmf-usb-files.$$
while IFS= read -r f; do
    [ -f "$SRC/$f" ] && [ -f "$TARGET/$f" ] || continue
    cmp -s "$SRC/$f" "$TARGET/$f" || { echo "  BYTE_MISMATCH: $f"; FAILS=1; }
done < /tmp/pcmf-usb-files.$$
rm -f /tmp/pcmf-usb-files.$$
[ "$FAILS" = "0" ] || { echo "FAIL_USB_EXPORT VERIFICATION"; exit 1; }

# preserve previous recovery releases: list what remains on the device
echo "[usb] releases now on device ($DEST/PCMF_RELEASES):"
for d in "$DEST"/PCMF_RELEASES/*/; do
    [ -d "$d" ] && echo "  - $(basename "$d")"
done

echo "PASS_USB_EXPORT target=$TARGET name=$NAME"
echo "  previous recovery releases preserved; package is fully offline-installable"
echo "  transport note: safe to carry to the ExampleNode system"
echo "  canonical_writer=$HOLD"
