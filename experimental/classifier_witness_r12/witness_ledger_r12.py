"""PCMF R12 isolated witness ledger — no canonical PCMF or policy mutation.

Only Ed25519 owner-signed, narrowly typed evidence may enter the log. The
operator must pin an independently authenticated owner public key explicitly.
Neither this module nor its CLI provisions production trust or approval.
"""
import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION = "PCMF_WITNESS_R12"
ZERO = "0" * 64
KEYS = frozenset({
    "schema", "root_id", "policy_sha256", "case_digest", "case_id",
    "rule_id", "context", "classification", "owner_review_id",
})
RULES = frozenset({"TECH_BUILD_ID", "TECH_CI_RUN_ID", "TECH_BUILD_TIMESTAMP"})
CONTEXTS = frozenset({"BUILD_PROJECT", "OPERATIONAL_CONTROL", "MEMORY_SYSTEM"})
LABELS = frozenset({"FALSE_POSITIVE_TECHNICAL", "TRUE_POSITIVE_SENSITIVE", "UNKNOWN"})
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
CASE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,63}\Z")

class WitnessError(ValueError):
    pass

def json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")

def parse_line(b):
    def unique(pairs):
        out = {}
        for key, val in pairs:
            if key in out:
                raise WitnessError("DUPLICATE_JSON_KEY")
            out[key] = val
        return out
    try:
        return json.loads(b, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError) as exc:
        raise WitnessError("INVALID_JSON") from exc

def regular_private(path):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or (s.st_mode & 0o077):
        raise WitnessError("UNSAFE_WITNESS_FILE")

def private_dir(path):
    path = Path(path)
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
        raise WitnessError("UNSAFE_WITNESS_DIRECTORY")
    return path

def validate_receipt(r, root_id, policy_sha):
    if not isinstance(r, dict) or frozenset(r) != KEYS:
        raise WitnessError("INVALID_RECEIPT_FIELDS")
    if any(not isinstance(v, str) for v in r.values()):
        raise WitnessError("NONSTRING_FIELD")
    if r["schema"] != VERSION or r["root_id"] != root_id or r["policy_sha256"] != policy_sha:
        raise WitnessError("ROOT_OR_POLICY_MISMATCH")
    if not HEX32.fullmatch(r["root_id"]) or any(not HEX64.fullmatch(r[k]) for k in ("policy_sha256", "case_digest", "owner_review_id")):
        raise WitnessError("BAD_DIGEST")
    if not CASE.fullmatch(r["case_id"]) or r["rule_id"] not in RULES or r["context"] not in CONTEXTS or r["classification"] not in LABELS:
        raise WitnessError("INVALID_EVIDENCE_CLASS")

class Ledger:
    def __init__(self, directory, owner_public_key, root_id, policy_sha):
        if len(owner_public_key) != 32 or not HEX32.fullmatch(root_id) or not HEX64.fullmatch(policy_sha):
            raise WitnessError("INVALID_TRUST_PIN")
        self.verify_key = Ed25519PublicKey.from_public_bytes(owner_public_key)
        self.directory = Path(directory)
        self.root_id = root_id
        self.policy_sha = policy_sha
        self.pin_sha = hashlib.sha256(owner_public_key).hexdigest()
        self.journal = self.directory / "witnesses.jsonl"
        self.lockfile = self.directory / "witnesses.lock"

    def _lock(self):
        private_dir(self.directory)
        fd = os.open(self.lockfile, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if os.fstat(fd).st_mode & 0o077:
                raise WitnessError("LOCKFILE_NOT_PRIVATE")
            fcntl.flock(fd, fcntl.LOCK_EX)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _load(self):
        if self.journal.is_symlink():
            raise WitnessError("SYMLINK_WITNESS_LEDGER")
        if not self.journal.exists():
            return []
        regular_private(self.journal)
        raw = self.journal.read_bytes()
        if len(raw) > 8_000_000 or (raw and not raw.endswith(b"\n")):
            raise WitnessError("TRUNCATED_OR_OVERSIZED_LEDGER")
        records = []
        prev = ZERO
        seen_reviews = set()
        seen_cases = set()
        for number, line in enumerate(raw.splitlines(), 1):
            obj = parse_line(line)
            if not isinstance(obj, dict) or set(obj) != {"sequence", "previous_hash", "receipt", "signature_hex", "event_hash", "owner_key_sha256"}:
                raise WitnessError("INVALID_EVENT_SHAPE")
            receipt = obj["receipt"]
            validate_receipt(receipt, self.root_id, self.policy_sha)
            if type(obj["sequence"]) is not int or obj["sequence"] != number or obj["previous_hash"] != prev or obj["owner_key_sha256"] != self.pin_sha:
                raise WitnessError("BROKEN_WITNESS_CHAIN")
            try:
                signature = bytes.fromhex(obj["signature_hex"])
                self.verify_key.verify(signature, json_bytes(receipt))
            except (InvalidSignature, ValueError) as exc:
                raise WitnessError("INVALID_OWNER_SIGNATURE") from exc
            if len(signature) != 64:
                raise WitnessError("INVALID_SIGNATURE_SIZE")
            body = {k: v for k, v in obj.items() if k != "event_hash"}
            digest = hashlib.sha256(json_bytes(body)).hexdigest()
            if digest != obj["event_hash"]:
                raise WitnessError("EVENT_HASH_MISMATCH")
            if receipt["owner_review_id"] in seen_reviews or (receipt["rule_id"], receipt["case_digest"]) in seen_cases:
                raise WitnessError("DUPLICATE_REVIEW_OR_CASE")
            seen_reviews.add(receipt["owner_review_id"])
            seen_cases.add((receipt["rule_id"], receipt["case_digest"]))
            prev = digest
            records.append(obj)
        return records

    def verify(self):
        fd = self._lock()
        try:
            events = self._load()
            return {"status": "PASS", "events": len(events), "head": events[-1]["event_hash"] if events else ZERO}
        finally:
            os.close(fd)

    def append(self, receipt, signature_hex):
        validate_receipt(receipt, self.root_id, self.policy_sha)
        try:
            sig = bytes.fromhex(signature_hex)
            if len(sig) != 64:
                raise ValueError("signature size")
            self.verify_key.verify(sig, json_bytes(receipt))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise WitnessError("OWNER_SIGNATURE_REQUIRED") from exc
        fd = self._lock()
        try:
            records = self._load()  # Tamper detection before every mutation
            for event in records:
                prior = event["receipt"]
                if prior["owner_review_id"] == receipt["owner_review_id"]:
                    if prior == receipt and event["signature_hex"] == signature_hex:
                        return {"status": "IDEMPOTENT_NOOP", "events": len(records)}
                    raise WitnessError("REVIEW_NONCE_CONFLICT")
                if prior["case_digest"] == receipt["case_digest"] and prior["rule_id"] == receipt["rule_id"]:
                    raise WitnessError("CASE_ALREADY_LABELED")
            body = {
                "sequence": len(records) + 1,
                "previous_hash": records[-1]["event_hash"] if records else ZERO,
                "receipt": receipt,
                "signature_hex": signature_hex,
                "owner_key_sha256": self.pin_sha,
            }
            body["event_hash"] = hashlib.sha256(json_bytes(body)).hexdigest()
            blob = json_bytes(body) + b"\n"
            if self.journal.exists():
                regular_private(self.journal)
            file_fd = os.open(self.journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(file_fd, "ab") as file:
                file.write(blob)
                file.flush()
                os.fsync(file.fileno())
            dfd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            return {"status": "EVIDENCE_ADMITTED_NOT_POLICY_APPROVED", "events": len(records) + 1, "head": body["event_hash"]}
        finally:
            os.close(fd)

    def propose(self, min_false_positive=5, min_contexts=2):
        """Untrusted suggestion only; never changes admission policy."""
        fd = self._lock()
        try:
            events = self._load()
        finally:
            os.close(fd)
        proposals = []
        for rule in sorted(RULES):
            selected = [v["receipt"] for v in events if v["receipt"]["rule_id"] == rule]
            positives = [r for r in selected if r["classification"] == "FALSE_POSITIVE_TECHNICAL"]
            true_positives = sum(r["classification"] == "TRUE_POSITIVE_SENSITIVE" for r in selected)
            unknowns = sum(r["classification"] == "UNKNOWN" for r in selected)
            contexts = sorted({r["context"] for r in positives})
            enough = len(positives) >= min_false_positive and len(contexts) >= min_contexts and true_positives == 0 and unknowns == 0
            proposals.append({
                "rule_id": rule, "owner_reviewed_false_positives": len(positives),
                "owner_reviewed_true_positives": true_positives,
                "unknowns": unknowns, "observed_contexts": contexts,
                "candidate_for_owner_review": enough,
                "deployment": "NEVER_AUTOMATIC",
                "owner_policy_promotion": "REQUIRED",
            })
        return {"schema": VERSION, "policy_sha256": self.policy_sha,
                "owner_key_sha256": self.pin_sha, "events": len(events),
                "proposals": proposals, "canonical_writer_modified": False}
