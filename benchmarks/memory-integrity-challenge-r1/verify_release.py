#!/usr/bin/env python3
"""Verify the portable SHA256SUMS manifest without external dependencies."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "SHA256SUMS"


def verify():
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError("empty manifest")
    seen = set()
    for line in lines:
        if "  " not in line:
            raise ValueError("invalid checksum entry")
        digest, name = line.split("  ", 1)
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts or str(rel) in {".", ""}:
            raise ValueError("invalid manifest path")
        if name in seen or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("duplicate/invalid hash")
        seen.add(name)
        candidate = ROOT / rel
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"missing/nonregular file: {name}")
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"hash mismatch: {name}")
    current = {str(path.relative_to(ROOT)) for path in ROOT.rglob("*")
               if path.is_file() and path.name != MANIFEST.name}
    if current != seen:
        raise ValueError(f"unlisted/removed files: {sorted(current ^ seen)}")
    return len(seen)


if __name__ == "__main__":
    print(f"MANIFEST_PASS: {verify()} files")
