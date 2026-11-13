"""Experimental 72-hour encrypted missed-proposal queue.

Not wired to canonical PCMF. No broad rejection / owner approval.
Only an authenticated native submitting adapter can supply the required pending
metadata callback. Private key is encrypted with an owner-controlled passphrase.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

TTL_SECONDS = 72 * 60 * 60
MAX_NOTE_BYTES = 8192
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
KEY_VERSION = "PCMF_R12_OWNER_KEY_V1"
NOTE_VERSION = "PCMF_R12_DEFERRED_NOTE_V1"
TOMBSTONE = "EXPIRED_DENIED_THIS_PROPOSAL_LOCAL_ONLY"

class QueueError(ValueError):
    pass

def encode(data):
    return base64.b64encode(data).decode("ascii")

def decode(value):
    if not isinstance(value, str):
        raise QueueError("INVALID_BASE64")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise QueueError("INVALID_BASE64") from exc

def packed(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()

def folder_private(folder):
    folder = Path(folder)
    if not folder.exists():
        folder.mkdir(mode=0o700,parents=True)
    st = folder.lstat()
    if not stat.S_ISDIR(st.st_mode) or (st.st_mode & 0o077):
        raise QueueError("FOLDER_PERMISSIONS_INSECURE")
    return folder

def file_private(path):
    st = Path(path).lstat()
    if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o077):
        raise QueueError("UNSAFE_FILE")

def atomic(path, data):
    path = Path(path)
    if path.is_symlink():
        raise QueueError("SYMLINK_REFUSED")
    if path.exists():
        file_private(path)
    name = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name,path)
        dfd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        if name.exists():name.unlink()

def readjson(path):
    file_private(path)
    if path.stat().st_size > 32768:
        raise QueueError("OVERSIZED_ENCRYPTED_RECORD")
    try:
        return json.loads(path.read_bytes())
    except (UnicodeDecodeError, ValueError) as exc:
        raise QueueError("INVALID_RECORD") from exc

def hkdf(secret, root_id, token):
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=bytes.fromhex(root_id),
                info=("pcmf-r12-note:"+token).encode()).derive(secret)

def passkey(password, salt):
    if len(password)<6:
        raise QueueError("PASSPHRASE_TOO_SHORT")
    return Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(password.encode("utf-8"))

class DeferredQueue:
    def __init__(self, directory, root_id, *, now=None):
        if not isinstance(root_id,str) or not HEX32.fullmatch(root_id):
            raise QueueError("INVALID_ROOT_ID")
        self.root = Path(directory)
        self.root_id=root_id
        self.now=now or time.time
        self.keys=self.root/"owner_keys.json"
        self.notes=self.root/"notes"
        self.expired=self.root/"expired"

    def _dirs(self):
        folder_private(self.root)
        folder_private(self.notes)
        folder_private(self.expired)

    def create_owner_keys(self, password, confirm):
        if password!=confirm:
            raise QueueError("PASSPHRASE_CONFIRMATION_MISMATCH")
        self._dirs()
        if self.keys.exists() or self.keys.is_symlink():
            raise QueueError("KEYS_ALREADY_CREATED")
        if any(self.notes.iterdir()):
            raise QueueError("ORPHAN_NOTES_EXIST")
        key=X25519PrivateKey.generate()
        private=key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,serialization.NoEncryption())
        pub=key.public_key().public_bytes(serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        salt=os.urandom(16)
        nonce=os.urandom(12)
        ciphertext=AESGCM(passkey(password,salt)).encrypt(nonce,private,
            (KEY_VERSION+":"+self.root_id).encode())
        record={"version":KEY_VERSION,"root_id":self.root_id,
                "public":encode(pub),"salt":encode(salt),
                "nonce":encode(nonce),"encrypted_private":encode(ciphertext)}
        atomic(self.keys,packed(record))
        return {"status":"OWNER_KEY_CREATED","public_key":encode(pub)}

    def owner_public_key(self):
        if not self.keys.exists() or self.keys.is_symlink():
            raise QueueError("OWNER_KEY_NOT_CONFIGURED")
        record=readjson(self.keys)
        if record.get("version")!=KEY_VERSION or record.get("root_id")!=self.root_id:
            raise QueueError("OWNER_KEY_IDENTITY_MISMATCH")
        pub=decode(record["public"])
        if len(pub)!=32:raise QueueError("BAD_OWNER_PUBLIC_KEY")
        return pub

    def _owner_private(self,password):
        record=readjson(self.keys)
        if record.get("version")!=KEY_VERSION or record.get("root_id")!=self.root_id:
            raise QueueError("OWNER_KEY_IDENTITY_MISMATCH")
        try:
            priv=AESGCM(passkey(password,decode(record["salt"]))).decrypt(
                decode(record["nonce"]),decode(record["encrypted_private"]),
                (KEY_VERSION+":"+self.root_id).encode())
            key=X25519PrivateKey.from_private_bytes(priv)
            if key.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw)!=decode(record["public"]):
                raise QueueError("OWNER_PUBLIC_KEY_MISMATCH")
            return key
        except (InvalidTag, ValueError) as exc:
            raise QueueError("PASSPHRASE_INVALID_OR_KEY_CORRUPTED") from exc

    def _path(self,token):
        if not isinstance(token,str) or not HEX64.fullmatch(token):
            raise QueueError("INVALID_PENDING_TOKEN")
        return self.notes/(token+".json")

    def enqueue(self, token, original_note, pending_lookup, *, owner_capture_enabled=False):
        """Authoritative pending_lookup(token) must be an authenticated client callback.

        Returns metadata: token, note_hash, note_bytes, root_id, status='pending'.
        The caller, not this class, establishes the client authentication.
        """
        if not owner_capture_enabled:
            raise QueueError("OWNER_CAPTURE_NOT_ENABLED")
        if not isinstance(original_note,str):
            raise QueueError("ORIGINAL_TEXT_REQUIRED")
        payload=original_note.encode("utf-8")
        if len(payload)<1 or len(payload)>MAX_NOTE_BYTES:
            raise QueueError("ORIGINAL_SIZE_INVALID")
        self._dirs()
        tokenpath=self._path(token)
        meta=pending_lookup(token)
        if not isinstance(meta,dict) or meta.get("status")!="pending" or meta.get("token")!=token or meta.get("root_id")!=self.root_id:
            raise QueueError("CANONICAL_PENDING_NOT_VERIFIED")
        if meta.get("note_bytes")!=len(payload) or meta.get("note_hash")!=hashlib.sha256(payload).hexdigest():
            raise QueueError("ORIGINAL_HASH_MISMATCH")
        if tokenpath.exists() or tokenpath.is_symlink() or (self.expired/(token+".json")).exists():
            raise QueueError("DUPLICATE_OR_EXPIRED_PENDING")
        public=X25519PublicKey.from_public_bytes(self.owner_public_key())
        eph=X25519PrivateKey.generate()
        shared=eph.exchange(public)
        aad=packed({"version":NOTE_VERSION,"root_id":self.root_id,"token":token,
                   "note_hash":meta["note_hash"],"note_bytes":len(payload)})
        nonce=os.urandom(12)
        cipher=AESGCM(hkdf(shared,self.root_id,token)).encrypt(nonce,payload,aad)
        now=int(self.now())
        rec={"version":NOTE_VERSION,"root_id":self.root_id,"token":token,
             "created_at":now,"expires_at":now+TTL_SECONDS,
             "note_hash":meta["note_hash"],"note_bytes":len(payload),
             "ephemeral_public":encode(eph.public_key().public_bytes(
                 serialization.Encoding.Raw,serialization.PublicFormat.Raw)),
             "nonce":encode(nonce),"ciphertext":encode(cipher)}
        atomic(tokenpath,packed(rec))
        # Fail closed if underlying pending state changes during capture.
        try:
            check=pending_lookup(token)
            if not isinstance(check,dict) or any(check.get(k)!=meta.get(k) for k in
                ("status","token","root_id","note_hash","note_bytes")):
                raise QueueError("STALE_PENDING_AFTER_CAPTURE")
        except Exception:
            tokenpath.unlink(missing_ok=True)
            raise
        return {"status":"ENCRYPTED_PENDING","token":token,"expires_at":now+TTL_SECONDS}

    def _record(self,token):
        self._dirs()
        path=self._path(token)
        if not path.exists():
            raise QueueError("NO_RETAINED_ORIGINAL")
        record=readjson(path)
        if not isinstance(record,dict) or record.get("version")!=NOTE_VERSION or record.get("token")!=token or record.get("root_id")!=self.root_id:
            raise QueueError("RECORD_IDENTITY_MISMATCH")
        born=record.get("created_at")
        expires=record.get("expires_at")
        if type(born) is not int or type(expires) is not int or expires-born!=TTL_SECONDS:
            raise QueueError("INVALID_DEADLINE")
        if int(self.now())>=expires:
            self.expire_token(token,reason="TTL_EXPIRED")
            raise QueueError("EXPIRED_DENIED_THIS_PROPOSAL")
        return record

    def unlock(self,token,password,pending_lookup):
        record=self._record(token)
        pending=pending_lookup(token)
        if not isinstance(pending,dict) or any(pending.get(k)!=record.get(k) for k in
            ("token","root_id","note_hash","note_bytes")) or pending.get("status")!="pending":
            raise QueueError("REVIEW_NOT_CURRENT")
        owner=self._owner_private(password)
        remote=X25519PublicKey.from_public_bytes(decode(record["ephemeral_public"]))
        shared=owner.exchange(remote)
        aad=packed({k:record[k] for k in ("version","root_id","token","note_hash","note_bytes")})
        try:
            plain=AESGCM(hkdf(shared,self.root_id,token)).decrypt(
                decode(record["nonce"]),decode(record["ciphertext"]),aad)
        except (InvalidTag,ValueError) as exc:
            raise QueueError("CIPHERTEXT_AUTH_FAILED") from exc
        if len(plain)!=record["note_bytes"] or hashlib.sha256(plain).hexdigest()!=record["note_hash"]:
            raise QueueError("ORIGINAL_VERIFICATION_FAILED")
        if int(self.now())>=record["expires_at"]:
            self.expire_token(token,reason="TTL_EXPIRED")
            raise QueueError("EXPIRED_DENIED_THIS_PROPOSAL")
        return plain.decode("utf-8")

    def expire_token(self,token,reason="TTL_EXPIRED"):
        """Local exact-item tombstone only. NEVER calls native pcmf reject."""
        if reason!="TTL_EXPIRED":
            raise QueueError("UNAUTHORIZED_EXPIRE_REASON")
        self._dirs()
        path=self._path(token)
        if not path.exists():
            return {"status":"ALREADY_REMOVED"}
        record=readjson(path)
        expires=record.get("expires_at")
        if type(expires) is not int or int(self.now())<expires:
            raise QueueError("NOT_YET_EXPIRED")
        # Remove encrypted original before recording a metadata-only tombstone.
        path.unlink()
        marker=self.expired/(token+".json")
        if not marker.exists():
            atomic(marker,packed({"token":token,"expires_at":expires,"status":TOMBSTONE}))
        return {"status":TOMBSTONE,"token":token}

    def sweep(self):
        self._dirs()
        deleted=0
        errors=0
        for path in self.notes.iterdir():
            if path.is_symlink() or not path.is_file() or not HEX64.fullmatch(path.stem):
                errors+=1
                continue
            try:
                rec=readjson(path)
                if type(rec.get("expires_at")) is int and int(self.now())>=rec["expires_at"]:
                    if self.expire_token(path.stem)["status"]==TOMBSTONE:
                        deleted+=1
            except (QueueError,OSError):
                errors+=1
        return {"expired_local_only":deleted,"errors":errors}

    def list_available(self):
        self.sweep()  # enforce time cutoff on every read
        records=[]
        for path in self.notes.iterdir():
            if path.is_symlink() or not HEX64.fullmatch(path.stem):
                continue
            try:
                rec=self._record(path.stem)
                records.append({"token":path.stem,"expires_at":rec["expires_at"]})
            except QueueError:
                pass
        return records
