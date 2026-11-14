"""Experimental integration bridge: pending PCMF review -> opt-in encrypted inbox.

Read-only PCMF validation only. This module NEVER submits memory, resolves a
review token, changes classifier policy, or starts a project process.
"""
import hashlib
import json
import subprocess
from pathlib import Path

from deferred_escrow import EscrowError, store, retrieve

class BridgeError(EscrowError):
    pass

class PendingReviewBridge:
    def __init__(self, *, pcmf_binary, pcmf_root, inbox_root, expected_root_id):
        self.binary = Path(pcmf_binary)
        self.root = Path(pcmf_root)
        self.inbox = Path(inbox_root)
        self.root_id = expected_root_id
        if not self.binary.is_absolute() or not self.binary.is_file() or self.binary.is_symlink():
            raise BridgeError("PCMF_CLI_UNAVAILABLE")
        if not self.root.is_absolute() or not self.root.is_dir() or self.root.is_symlink():
            raise BridgeError("PCMF_ROOT_UNAVAILABLE")

    def _call(self, verb):
        command = [str(self.binary), *verb, "--root", str(self.root)]
        try:
            result = subprocess.run(command, text=True, capture_output=True,
                                    timeout=12, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BridgeError("PCMF_READ_ONLY_QUERY_FAILED") from exc
        if result.returncode != 0:
            raise BridgeError("PCMF_READ_ONLY_QUERY_BLOCKED")
        try:
            data = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise BridgeError("PCMF_RESPONSE_INVALID") from exc
        if verb == ["status"]:
            # Native `pcmf status` returns a *flat* health object. Review.list
            # returns the PCMF_IPv1 envelope with status/data fields.
            if data.get("healthy") is not True:
                raise BridgeError("PCMF_HEALTH_NOT_OK")
            return data
        if data.get("status") != "OK":
            raise BridgeError("PCMF_READ_ONLY_QUERY_NOT_OK")
        return data.get("data", {})

    def _review_snapshot(self):
        state = self._call(["status"])
        if state.get("root") != str(self.root) or state.get("root_id") != self.root_id:
            raise BridgeError("CANONICAL_ROOT_ID_MISMATCH")
        if state.get("chain_ok") is not True or state.get("index_ok") is not True:
            raise BridgeError("CANONICAL_STORE_INTEGRITY_FAILURE")
        data = self._call(["review", "list"])
        pending = data.get("pending")
        if not isinstance(pending, list):
            raise BridgeError("PENDING_QUEUE_INVALID")
        return pending

    def pending_metadata(self, token):
        if not isinstance(token, str) or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
            raise BridgeError("TOKEN_FORMAT_INVALID")
        matches = [p for p in self._review_snapshot() if p.get("token") == token]
        if len(matches) != 1:
            raise BridgeError("TOKEN_NOT_PENDING_OR_AMBIGUOUS")
        item = matches[0]
        digest, count = item.get("note_hash"), item.get("note_bytes")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise BridgeError("PENDING_NOTE_HASH_INVALID")
        if type(count) is not int or not 0 < count <= 65536:
            raise BridgeError("PENDING_NOTE_SIZE_INVALID")
        return {"token": token, "subject": item.get("subject"),
                "note_hash": digest, "note_bytes": count, "root_id": self.root_id}

    @staticmethod
    def _verify_original(metadata, note):
        if not isinstance(note, str) or (len(raw := note.encode("utf-8")) != metadata["note_bytes"] or
                                         hashlib.sha256(raw).hexdigest() != metadata["note_hash"]):
            raise BridgeError("ORIGINAL_NOTE_DOES_NOT_MATCH_PENDING_REVIEW")

    def capture_if_owner_consents(self, *, token, original_note, owner_passphrase,
                                  owner_opted_in=False):
        """Requires positive owner opt-in and exact original text from submitter.

        This call does not grant review approval or change the pending queue.
        """
        if owner_opted_in is not True:
            raise BridgeError("EXPLICIT_OWNER_OPT_IN_REQUIRED")
        meta = self.pending_metadata(token)
        self._verify_original(meta, original_note)
        receipt = store(self.inbox, token, self.root_id, original_note, owner_passphrase)
        try:
            second = self.pending_metadata(token)
            if second != meta:
                raise BridgeError("PENDING_REVIEW_CHANGED_DURING_CAPTURE")
        except Exception:
            # A stale or resolved token must not leave a newly captured note
            # in deferred storage. This cleanup affects only the newly
            # created experimental inbox item, never canonical PCMF.
            from deferred_escrow import discard
            try:
                discard(self.inbox, token, self.root_id)
            except Exception as cleanup_exc:
                raise BridgeError("CAPTURE_REVALIDATION_FAILED_MANUAL_ESCROW_CLEANUP_REQUIRED") from cleanup_exc
            raise
        return receipt

    def unlock_if_still_pending(self, *, token, owner_passphrase):
        meta = self.pending_metadata(token)
        note = retrieve(self.inbox, token, self.root_id, owner_passphrase)
        self._verify_original(meta, note)
        # Refuse to disclose an entry that was resolved or replaced during unlock.
        second = self.pending_metadata(token)
        if second != meta:
            raise BridgeError("PENDING_REVIEW_CHANGED_DURING_UNLOCK")
        return note
