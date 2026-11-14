#!/usr/bin/env python3
"""Offline preflight for an explicit list of public candidate text files.

No live access. No file content is printed. Manual security and history review
are still required; this is a limited heuristic scanner, not certification.
"""
from __future__ import annotations

import argparse
import re
import stat
import sys
from pathlib import Path

MAX_BYTES = 512_000
TEXT_TYPES = {".md", ".txt", ".py", ".sh", ".json", ".jsonl",
              ".yaml", ".yml", ".toml", ".c", ".h", ".cpp", ".hpp"}
PRIVATE_PARTS = {".env", ".git", ".ssh", ".aws", ".kube", ".gnupg",
                 "id_rsa", "id_ed25519", "credentials", "secrets"}
PRIVATE_TYPES = {".pem", ".key", ".p12", ".pfx", ".sqlite", ".db",
                 ".zip", ".tar", ".gz", ".bin", ".gguf"}
RULES = (
    ("PRIVATE_KEY_MATERIAL",
     re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("TOKEN_SIGNATURE",
     re.compile(r"(?<![\w-])(?:ghp_|github_pat_|sk-[A-Za-z0-9]+-|xox[baprs]-)[A-Za-z0-9_-]{16,}")),
    ("HOST_HOME_PATH",
     re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/")),
    ("HOST_MEDIA_PATH",
     re.compile(r"/(?:run/)?media/[A-Za-z0-9._-]+/")),
    ("PRIVATE_IPV4",
     re.compile(r"(?<!\d)(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)")),
    ("POSSIBLE_CREDENTIAL_ASSIGNMENT",
     re.compile(r"""(?im)^\s*(?:api[_-]?key|password|secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][^'"\r\n]{10,}['"]""")),
)


def check_one(root: Path, name: str) -> list[str]:
    """Report only issue identifiers. Never expose matched text."""
    relative = Path(name)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        return ["UNSAFE_RELATIVE_PATH"]
    if any(part.lower() in PRIVATE_PARTS for part in relative.parts):
        return ["PRIVATE_PATH_COMPONENT"]
    if relative.suffix.lower() in PRIVATE_TYPES or relative.suffix.lower() not in TEXT_TYPES:
        return ["UNSUPPORTED_FILE_TYPE"]
    path = root / relative
    try:
        if any(root.joinpath(*relative.parts[:i]).is_symlink()
               for i in range(1, len(relative.parts) + 1)):
            return ["SYMLINK_NOT_ALLOWED"]
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return ["NOT_REGULAR_FILE"]
        if metadata.st_size > MAX_BYTES:
            return ["FILE_TOO_LARGE"]
        source = path.read_bytes()
        if b"\x00" in source:
            return ["BINARY_CONTENT"]
        content = source.decode("utf-8")
    except (OSError, ValueError, UnicodeError):
        return ["UNREADABLE_OR_OUTSIDE_ROOT"]
    return [label for label, rule in RULES if rule.search(content)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Isolated candidate directory")
    parser.add_argument("files", nargs="+", help="Explicit relative candidate paths")
    args = parser.parse_args(argv)
    findings = [(name, label)
                for name in args.files
                for label in check_one(args.root, name)]
    if findings:
        for name, label in findings:
            print(f"REVIEW_REQUIRED {name}: {label}")
        return 1
    print(f"PASS: {len(args.files)} selected text files; independent review required")
    return 0


if __name__ == "__main__":
    sys.exit(main())
