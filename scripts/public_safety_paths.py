#!/usr/bin/env python3
"""Fail-closed path boundary check for PCMF package install/uninstall.

Stdlib-only. Called BEFORE any destructive action. Refuses symlinks,
dot/dotdot components, out-of-home installation roots, invalid product
manifest, and unsafe purge roots. Never accesses the user's memory contents.
"""
import json
import os
from pathlib import Path
import stat
import sys


def deny(message):
    raise ValueError("BLOCKED_PCMF_PATH_BOUNDARY_" + message)


def path(raw, name):
    if not raw or not raw.startswith("/") or "\\x00" in raw:
        deny(name + "_NOT_ABSOLUTE")
    if raw != os.path.normpath(raw) or "//" in raw:
        deny(name + "_NONCANONICAL")
    parts = Path(raw).parts
    if any(part in (".", "..") for part in raw.split("/")):
        deny(name + "_DOT_COMPONENT")
    p = Path(raw)
    # Every path element that exists must be a physical, non-symlink entry.
    for part in (p, *p.parents):
        if part.is_symlink():
            deny(name + "_SYMLINK_COMPONENT")
    if str(p.resolve(strict=False)) != raw:
        deny(name + "_REALPATH_CHANGED")
    return p


def within(child, parent):
    return child != parent and parent in child.parents


def owned_regular(p, name):
    try:
        info = p.lstat()
    except FileNotFoundError:
        deny(name + "_MISSING")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        deny(name + "_INVALID_TYPE_OR_OWNER")
    if info.st_mode & stat.S_IWOTH:
        deny(name + "_WORLD_WRITABLE")


def check_install(mode, h, prefix, bindir, cfg, data, sock, instances):
    home = path(h, "HOME")
    # Confirm home has a real directory and is not itself a symlink.
    if not home.is_dir() or home == Path("/"):
        deny("HOME_INVALID")
    app = path(prefix, "APP_ROOT")
    b = path(bindir, "BIN_ROOT")
    config = path(cfg, "CONFIG_ROOT")
    d = path(data, "DATA_ROOT")
    sk = path(sock, "SOCKET")
    ins = path(instances, "INSTANCES")
    if not within(app, home) or app.name != "pcmf" or len(app.parts) < len(home.parts) + 3:
        deny("APP_ROOT_UNSAFE")
    if not within(b, home) or b.name != "bin" or len(b.parts) < len(home.parts) + 2:
        deny("BIN_ROOT_UNSAFE")
    if config != home / ".config" / "pcmf":
        deny("CONFIG_ROOT_UNSAFE")
    if not str(sk).endswith("/pcmf/pcmf.sock") or sk.parent.name != "pcmf":
        deny("SOCKET_UNEXPECTED")
    if not (within(sk, home) or
            (os.environ.get("XDG_RUNTIME_DIR") and
             within(sk, path(os.environ["XDG_RUNTIME_DIR"], "RUNTIME")))):
        deny("SOCKET_OUTSIDE_USER_RUNTIME")
    if not within(d, home) and not os.environ.get("PCMF_ALLOW_EXTERNAL_DATA_ROOT") == "1":
        deny("DATA_ROOT_EXTERNAL_REQUIRES_EXPLICIT_CONFIG")
    if d in (home, app, config, Path("/")) or within(d, app) or within(app, d):
        deny("DATA_ROOT_OVERLAPS_INSTALL")
    if ins != home / ".local" / "share" / "pcmf-instances":
        deny("INSTANCES_ROOT_UNSAFE")
    marker = app / "installed.json"
    if mode in ("uninstall", "purge-data", "purge-all"):
        owned_regular(marker, "INSTALL_MARKER")
        if not (app / "versions").is_dir() or not (app / "current").is_symlink():
            # current is deliberately an installed version link, but do not
            # allow it to escape the validated installation directory.
            deny("INSTALL_LAYOUT_INVALID")
        current = app / "current"
        real_current = current.resolve(strict=True)
        if not within(real_current, app / "versions") or not real_current.is_dir():
            deny("ACTIVE_VERSION_OUTSIDE_APP")
        try:
            info = json.loads(marker.read_text())
        except (ValueError, OSError):
            deny("INSTALL_MARKER_INVALID_JSON")
        if not isinstance(info, dict):
            deny("INSTALL_MARKER_BAD_SCHEMA")
        version = info.get("active_version")
        if (not isinstance(version, str) or
            not version.startswith("PCMF_LIVING_MEMORY_R") or
            info.get("data_root") != str(d) or
            info.get("socket") != str(sk)):
            deny("INSTALL_MARKER_MISMATCH")
    if mode in ("purge-data", "purge-all"):
        if not within(d, home) or not within(d, home / ".local" / "share"):
            deny("PURGE_OUTSIDE_HOME_DATA")
        if d.name != "pcmf":
            deny("PURGE_NOT_EXPECTED_MEMORY_FOLDER")
        marker = d / ".pcmf_root"
        owned_regular(marker, "MEMORY_MARKER")
        try:
            head = json.loads(marker.read_text())
        except (OSError, ValueError):
            deny("MEMORY_MARKER_INVALID")
        if head.get("kind") != "PCMF_LIVING_MEMORY_ROOT":
            deny("MEMORY_MARKER_MISMATCH")
        if mode == "purge-all" and ins.is_symlink():
            deny("INSTANCE_SYMLINK")
    print("PASS_PCMF_PATH_BOUNDARY_" + mode.upper().replace("-", "_"))


def main():
    if len(sys.argv) != 9 or sys.argv[1] not in (
            "install", "uninstall", "purge-data", "purge-all"):
        deny("INVALID_ARGUMENTS")
    check_install(*sys.argv[1:])


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)
