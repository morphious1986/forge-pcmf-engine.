"""Owner-receipt and deterministic rule-proposal synthetic acceptance."""
import json
import os
import tempfile
import unittest
import hashlib
import stat
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from witness_ledger_r12 import Ledger,WitnessError,VERSION,json_bytes

ROOT="a"*32
POLICY="b"*64

class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="pcmf-r12-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.dir=Path(self.temp.name)/"evidence"
        self.owner=Ed25519PrivateKey.generate()
        self.public=self.owner.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.ledger=Ledger(self.dir,self.public,ROOT,POLICY)

    def receipt(self,n=1,rule="TECH_BUILD_ID",context="BUILD_PROJECT",label="FALSE_POSITIVE_TECHNICAL"):
        return {
            "schema":VERSION,"root_id":ROOT,"policy_sha256":POLICY,
            "case_digest":hashlib.sha256(("synthetic-case-"+str(n)).encode()).hexdigest(),
            "case_id":"synthetic_case_"+str(n),
            "rule_id":rule,"context":context,"classification":label,
            "owner_review_id":hashlib.sha256(("owner-review-"+str(n)).encode()).hexdigest(),
        }
    def sign(self,receipt,owner=None):
        return (owner or self.owner).sign(json_bytes(receipt)).hex()
    def add(self,n,**kwargs):
        receipt=self.receipt(n,**kwargs)
        return self.ledger.append(receipt,self.sign(receipt))

    def test_empty_store(self):
        state=self.ledger.verify()
        self.assertEqual((state["status"],state["events"]),("PASS",0))
        self.assertEqual(state["head"],"0"*64)

    def test_authorized_append_and_replay(self):
        r=self.receipt()
        sig=self.sign(r)
        self.assertEqual(self.ledger.append(r,sig)["events"],1)
        self.assertEqual(self.ledger.verify()["events"],1)
        self.assertEqual(self.ledger.append(r,sig)["status"],"IDEMPOTENT_NOOP")
        self.assertEqual(self.ledger.verify()["events"],1)
        self.assertEqual(self.ledger.journal.stat().st_mode&0o777,0o600)
        self.assertEqual(self.ledger.directory.stat().st_mode&0o777,0o700)

    def test_wrong_signer_rejected(self):
        receipt=self.receipt()
        other=Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(WitnessError,"OWNER_SIGNATURE_REQUIRED"):
            self.ledger.append(receipt,self.sign(receipt,other))
        self.assertEqual(self.ledger.verify()["events"],0)

    def test_owner_signature_must_match_classification(self):
        original=self.receipt()
        modified=dict(original,classification="TRUE_POSITIVE_SENSITIVE")
        with self.assertRaises(WitnessError):
            self.ledger.append(modified,self.sign(original))

    def test_invalid_rule_context_and_root(self):
        for change in ({"rule_id":"ANYTHING_SAFE"},{"context":"PERSONAL_PRIVATE"},
                       {"root_id":"c"*32},{"policy_sha256":"d"*64},
                       {"case_id":"-bad-name"}, {"note":"secret_string"}):
            receipt=self.receipt()
            receipt.update(change)
            with self.assertRaises(WitnessError):
                self.ledger.append(receipt,self.sign(receipt))

    def test_replay_review_nonce_conflict(self):
        self.add(1)
        altered=self.receipt(2)
        altered["owner_review_id"]=self.receipt(1)["owner_review_id"]
        with self.assertRaisesRegex(WitnessError,"REVIEW_NONCE_CONFLICT"):
            self.ledger.append(altered,self.sign(altered))

    def test_duplicate_case_digest_rejected(self):
        self.add(1)
        r=self.receipt(2)
        r["case_digest"]=self.receipt(1)["case_digest"]
        with self.assertRaisesRegex(WitnessError,"CASE_ALREADY_LABELED"):
            self.ledger.append(r,self.sign(r))

    def test_tampered_signed_evidence_blocks_future_append(self):
        self.add(1)
        raw=self.ledger.journal.read_bytes()
        self.ledger.journal.write_bytes(raw.replace(b"FALSE_POSITIVE_TECHNICAL",b"TRUE_POSITIVE_SENSITIVE"))
        with self.assertRaises(WitnessError):
            self.ledger.verify()
        with self.assertRaises(WitnessError):
            self.add(2)

    def test_truncated_ledger_fails_closed(self):
        self.add(1)
        raw=self.ledger.journal.read_bytes()
        self.ledger.journal.write_bytes(raw[:-1])
        with self.assertRaisesRegex(WitnessError,"TRUNCATED"):
            self.ledger.propose()
        with self.assertRaises(WitnessError):
            self.add(2)

    def test_symlink_ledger_refused(self):
        self.dir.mkdir(mode=0o700)
        self.ledger.journal.symlink_to(Path(self.temp.name)/"other")
        with self.assertRaises(WitnessError):
            self.ledger.verify()

    def test_too_open_permissions_refused(self):
        self.add(1)
        self.ledger.journal.chmod(0o644)
        with self.assertRaises(WitnessError):
            self.ledger.verify()

    def test_no_uncontrolled_policy_promotion(self):
        for n in range(1,5):
            self.add(n,context="BUILD_PROJECT" if n%2 else "OPERATIONAL_CONTROL")
        data=self.ledger.propose()
        p=next(x for x in data["proposals"] if x["rule_id"]=="TECH_BUILD_ID")
        self.assertFalse(p["candidate_for_owner_review"])
        self.add(5,context="OPERATIONAL_CONTROL")
        p=next(x for x in self.ledger.propose()["proposals"] if x["rule_id"]=="TECH_BUILD_ID")
        self.assertTrue(p["candidate_for_owner_review"])
        self.assertEqual(p["deployment"],"NEVER_AUTOMATIC")
        self.assertEqual(p["owner_policy_promotion"],"REQUIRED")

    def test_owner_confirmed_sensitive_blocks_promotion(self):
        for n in range(1,7):
            self.add(n,context="BUILD_PROJECT" if n%2 else "OPERATIONAL_CONTROL")
        self.add(7,label="TRUE_POSITIVE_SENSITIVE")
        result=self.ledger.propose()
        p=next(x for x in result["proposals"] if x["rule_id"]=="TECH_BUILD_ID")
        self.assertFalse(p["candidate_for_owner_review"])
        self.assertEqual(p["owner_reviewed_true_positives"],1)

    def test_unknown_case_blocks_promotion(self):
        for n in range(1,7):
            self.add(n,context="BUILD_PROJECT" if n%2 else "OPERATIONAL_CONTROL")
        self.add(7,label="UNKNOWN")
        p=next(x for x in self.ledger.propose()["proposals"] if x["rule_id"]=="TECH_BUILD_ID")
        self.assertFalse(p["candidate_for_owner_review"])

    def test_single_context_insufficient(self):
        for n in range(1,7):
            self.add(n,context="BUILD_PROJECT")
        p=next(x for x in self.ledger.propose()["proposals"] if x["rule_id"]=="TECH_BUILD_ID")
        self.assertFalse(p["candidate_for_owner_review"])

    def test_receipts_are_metadata_only(self):
        self.add(1)
        line=self.ledger.journal.read_text()
        self.assertNotIn("raw_note",line)
        self.assertNotIn("password",line)
        self.assertNotIn("synthetic-case-",line)
        self.assertNotIn("sk-proj",line)
        obj=json.loads(line)
        self.assertEqual(set(obj["receipt"]),{
            "schema","root_id","policy_sha256","case_digest","case_id",
            "rule_id","context","classification","owner_review_id"})

if __name__=="__main__":
    unittest.main()
