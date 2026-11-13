"""Owner-controlled deferred inbox passphrase lifecycle.

No passphrase stored. Each encrypted note remains individually authenticated.
Rotation preserves a private encrypted backup and fails closed on interruption.
"""
import json, os, secrets, base64, stat, fcntl
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from deferred_escrow import _derive, retrieve, store, EscrowError

MARKER=b"PCMF_OWNER_ESCROW_PASSPHRASE_V1"
VERSION="PCMF_ESCROW_PASSPHRASE_V1"

class PassphraseError(Exception):
    pass

def _private_dir(path):
    d=Path(path)
    if d.is_symlink():raise PassphraseError("DIRECTORY_SYMLINK_REFUSED")
    d.mkdir(parents=True,exist_ok=True,mode=0o700)
    if d.stat().st_mode & 0o077:raise PassphraseError("DIRECTORY_NOT_PRIVATE")
    return d

def _atomic(path,data):
    path=Path(path)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_mode & 0o077:
            raise PassphraseError("UNSAFE_EXISTING_PASSPHRASE_FILE")
    temp=path.with_name(path.name+"."+secrets.token_hex(8)+".tmp")
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(data);out.flush();os.fsync(out.fileno())
        os.replace(temp,path)
        dfd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        if temp.exists():temp.unlink()

def _wrap(passphrase):
    salt=os.urandom(16);nonce=os.urandom(12)
    encrypted=AESGCM(_derive(passphrase,salt)).encrypt(nonce,MARKER,VERSION.encode())
    return json.dumps({"version":VERSION,"salt":base64.b64encode(salt).decode(),
                       "nonce":base64.b64encode(nonce).decode(),
                       "encrypted_verifier":base64.b64encode(encrypted).decode()},
                      sort_keys=True).encode()

def _unlock(data,password):
    try:
        rec=json.loads(data)
        if rec["version"]!=VERSION:raise PassphraseError("UNSUPPORTED_MARKER")
        salt=base64.b64decode(rec["salt"],validate=True)
        nonce=base64.b64decode(rec["nonce"],validate=True)
        encrypted=base64.b64decode(rec["encrypted_verifier"],validate=True)
        if len(salt)!=16 or len(nonce)!=12:raise ValueError("invalid")
        plain=AESGCM(_derive(password,salt)).decrypt(nonce,encrypted,VERSION.encode())
        if plain!=MARKER:raise PassphraseError("VERIFIER_MISMATCH")
        return True
    except (InvalidTag,KeyError,ValueError,TypeError,UnicodeError) as exc:
        raise PassphraseError("PASSPHRASE_INVALID_OR_VERIFIER_CORRUPT") from exc

class OwnerPassphrase:
    def __init__(self,config_dir,inbox,root_id):
        self.config_dir=Path(config_dir)
        self.inbox=Path(inbox)
        self.root_id=root_id
        self.marker=self.config_dir/"owner-escrow-passphrase.json"
        self.lockpath=self.config_dir/"owner-escrow-passphrase.lock"
    def configured(self):
        return self.marker.is_file() and not self.marker.is_symlink()
    def _ensure_safe(self):
        _private_dir(self.config_dir)
        if self.marker.is_symlink():raise PassphraseError("PASSPHRASE_FILE_SYMLINK")
        if self.marker.exists() and self.marker.stat().st_mode & 0o077:
            raise PassphraseError("PASSPHRASE_FILE_NOT_PRIVATE")
    def _lock(self):
        self._ensure_safe()
        fd=os.open(self.lockpath,os.O_CREAT|os.O_RDWR|getattr(os,"O_NOFOLLOW",0),0o600)
        if os.fstat(fd).st_mode & 0o077:
            os.close(fd);raise PassphraseError("LOCK_NOT_PRIVATE")
        fcntl.flock(fd,fcntl.LOCK_EX)
        return fd
    def _check(self,password):
        self._ensure_safe()
        if not self.configured():raise PassphraseError("PASSPHRASE_NOT_CONFIGURED")
        _unlock(self.marker.read_bytes(),password)
    def verify(self,password):
        self._check(password);return True
    def setup(self,new,confirmation):
        if new!=confirmation:raise PassphraseError("CONFIRMATION_MISMATCH")
        if len(new)<12:raise PassphraseError("PASSPHRASE_TOO_SHORT")
        fd=self._lock()
        try:
            if self.marker.exists():raise PassphraseError("ALREADY_CONFIGURED")
            if self.inbox.is_dir() and any(self.inbox.iterdir()):
                raise PassphraseError("EXISTING_ESCROW_NEEDS_MIGRATION")
            _atomic(self.marker,_wrap(new))
            return {"status":"SETUP_COMPLETE"}
        finally:os.close(fd)
    def change(self,current,new,confirmation):
        if new!=confirmation:raise PassphraseError("CONFIRMATION_MISMATCH")
        if len(new)<12:raise PassphraseError("PASSPHRASE_TOO_SHORT")
        fd=self._lock()
        try:
            self._check(current)
            if current==new:raise PassphraseError("NEW_EQUALS_OLD")
            if not self.inbox.exists() or not any(self.inbox.iterdir()):
                _atomic(self.marker,_wrap(new))
                return {"status":"CHANGED","entries":0}
            if self.inbox.is_symlink() or self.inbox.stat().st_mode & 0o077:
                raise PassphraseError("INBOX_NOT_PRIVATE")
            paths=list(self.inbox.iterdir())
            if any(p.is_symlink() or not p.is_file() or p.suffix!=".json" for p in paths):
                raise PassphraseError("UNKNOWN_INBOX_ENTRY")
            stage=self.inbox.with_name(self.inbox.name+"-rotation-stage")
            if stage.exists():raise PassphraseError("PREVIOUS_ROTATION_STAGE_EXISTS")
            stage.mkdir(mode=0o700)
            suffix=secrets.token_hex(8)
            backup=self.inbox.with_name(self.inbox.name+"-before-change-"+suffix)
            try:
                for p in paths:
                    token=p.stem
                    plaintext=retrieve(self.inbox,token,self.root_id,current)
                    store(stage,token,self.root_id,plaintext,new)
                    if retrieve(stage,token,self.root_id,new)!=plaintext:
                        raise PassphraseError("ROTATION_READBACK_FAILED")
                # Keep encrypted backup so interrupted transitions remain recoverable.
                os.replace(self.inbox,backup)
                try:
                    os.replace(stage,self.inbox)
                    _atomic(self.marker,_wrap(new))
                except Exception:
                    if self.inbox.exists():os.replace(self.inbox,stage)
                    os.replace(backup,self.inbox)
                    raise
                return {"status":"CHANGED","entries":len(paths),"encrypted_backup":str(backup)}
            except Exception:
                if stage.exists():
                    for p in stage.iterdir():p.unlink()
                    stage.rmdir()
                raise
        finally:os.close(fd)
