"""Experimental owner-only deferred-review encrypted inbox.

Not integrated with canonical PCMF. No automatic admission, classification,
decryption or background unlock. The caller MUST verify the token against
the canonical pending queue before storing or opening content.
"""
import base64
import json
import os
import re
import stat
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAX_NOTE_BYTES = 65536
MAX_RECORD_BYTES = 131072
TOKEN_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
ROOT_PATTERN = re.compile(r"[a-f0-9]{32}\Z")
VERSION = "PCMF_DEFERRED_OWNER_ESCROW_V1"

class EscrowError(Exception):
    pass

def _validate(token, root_id):
    if not TOKEN_PATTERN.fullmatch(token):
        raise EscrowError("INVALID_TOKEN")
    if not ROOT_PATTERN.fullmatch(root_id):
        raise EscrowError("INVALID_ROOT_ID")

def _dir(root, create=False):
    d = Path(root)
    if not d.is_absolute():
        raise EscrowError("ROOT_NOT_ABSOLUTE")
    if create and not d.exists():
        d.mkdir(mode=0o700, parents=True)
    if d.is_symlink() or not d.is_dir():
        raise EscrowError("ROOT_NOT_PRIVATE_DIRECTORY")
    if (d.stat().st_mode & 0o077) != 0:
        raise EscrowError("DIRECTORY_PERMISSIONS_NOT_PRIVATE")
    return d

def _derive(password, salt):
    if not isinstance(password, str) or len(password) < 6:
        raise EscrowError("OWNER_PASSPHRASE_TOO_SHORT")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))

def _aad(token, root_id):
    return (VERSION + ":" + root_id + ":" + token).encode("ascii")

def _encode(b):
    return base64.b64encode(b).decode("ascii")

def _decode(s):
    try:
        return base64.b64decode(s, validate=True)
    except Exception as exc:
        raise EscrowError("INVALID_ENCRYPTED_RECORD") from exc

def store(root, token, root_id, note, owner_passphrase):
    """Opt-in encrypted storage, only for a verified pending review token.

    This module deliberately cannot establish pending-token status itself.
    Caller must confirm authenticity via PCMF and obtain explicit owner consent.
    """
    _validate(token, root_id)
    if not isinstance(note, str) or not note:
        raise EscrowError("EMPTY_NOTE")
    data = note.encode("utf-8")
    if len(data) > MAX_NOTE_BYTES:
        raise EscrowError("NOTE_TOO_LARGE")
    d = _dir(root, create=True)
    target = d / (token + ".json")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ciphertext = AESGCM(_derive(owner_passphrase, salt)).encrypt(
        nonce, data, _aad(token, root_id)
    )
    record = json.dumps({
        "version": VERSION, "root_id": root_id, "token": token,
        "salt": _encode(salt), "nonce": _encode(nonce),
        "ciphertext": _encode(ciphertext)
    }, separators=(",", ":"), sort_keys=True).encode("ascii")
    # O_EXCL prevents overwriting existing evidence, and O_NOFOLLOW refuses links.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    try:
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(record)
            stream.flush()
            os.fsync(stream.fileno())
        dir_fd = os.open(d, os.O_RDONLY)
        try: os.fsync(dir_fd)
        finally: os.close(dir_fd)
    except FileExistsError as exc:
        raise EscrowError("ENTRY_ALREADY_EXISTS") from exc
    except Exception:
        if fd is not None:
            os.close(fd)
        # Existing evidence is never removed by a failed write.
        raise
    return {"status": "ENCRYPTED", "token": token, "bytes": len(record)}

def retrieve(root, token, root_id, owner_passphrase):
    """Returns plaintext only after authenticated owner-passphrase decryption."""
    _validate(token, root_id)
    d = _dir(root)
    path = d / (token + ".json")
    if path.is_symlink():
        raise EscrowError("SYMLINK_REFUSED")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
                raise EscrowError("RECORD_PERMISSIONS_NOT_PRIVATE")
            if st.st_size > MAX_RECORD_BYTES:
                raise EscrowError("RECORD_TOO_LARGE")
            raw = stream.read(MAX_RECORD_BYTES + 1)
    except FileNotFoundError as exc:
        raise EscrowError("ENTRY_NOT_FOUND") from exc
    try:
        rec = json.loads(raw)
        if rec["version"] != VERSION or rec["token"] != token or rec["root_id"] != root_id:
            raise EscrowError("RECORD_BINDING_MISMATCH")
        salt = _decode(rec["salt"])
        nonce = _decode(rec["nonce"])
        ct = _decode(rec["ciphertext"])
        if len(salt) != 16 or len(nonce) != 12 or len(ct) > MAX_NOTE_BYTES + 16:
            raise EscrowError("INVALID_ENCRYPTED_RECORD")
        return AESGCM(_derive(owner_passphrase, salt)).decrypt(
            nonce, ct, _aad(token, root_id)
        ).decode("utf-8")
    except (ValueError, TypeError, KeyError, InvalidTag, UnicodeDecodeError) as exc:
        raise EscrowError("UNLOCK_FAILED_OR_RECORD_TAMPERED") from exc

def discard(root, token, root_id):
    """Explicit owner-invoked file removal; no claim of secure physical erasure."""
    _validate(token, root_id)
    d = _dir(root)
    path = d / (token + ".json")
    if path.is_symlink():
        raise EscrowError("SYMLINK_REFUSED")
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
            raise EscrowError("RECORD_PERMISSIONS_NOT_PRIVATE")
        # Verify the record binding even for removal (without decrypting).
        rec = json.loads(path.read_text(encoding="ascii"))
        if rec.get("token") != token or rec.get("root_id") != root_id:
            raise EscrowError("RECORD_BINDING_MISMATCH")
        path.unlink()
    except FileNotFoundError as exc:
        raise EscrowError("ENTRY_NOT_FOUND") from exc
    return {"status": "DISCARDED", "token": token}
