"""Disposable-root integration test of native C++ owner-only expiry API.

Never reads or changes the canonical PCMF root. Native expiry does not install
any future deny rule, and cannot authorize older hash-only proposals.
"""
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

BINARY = (Path(os.environ["PCMF_R13_TEST_BIN"]) if "PCMF_R13_TEST_BIN" in os.environ
          else (Path(__file__).parent / "pcmf-r13-test" if
                (Path(__file__).parent / "pcmf-r13-test").exists()
                else Path(__file__).parent.parent / "bin" / "pcmf"))
NOTE = "Account number: 1234567890123456."
NOTE2 = "Account number: 9876543210987654."

class NativeExpiryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pcmf-r13-native-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "root"
        r=self.run_cli("init", "--profile","personal","--project","general")
        self.assertEqual(r["status"],"OK")

    def run_cli(self,*args):
        cmd=[str(BINARY),str(args[0]),*args[1:],"--root",str(self.root)]
        run=subprocess.run(cmd,capture_output=True,text=True,timeout=12)
        self.assertEqual(run.returncode,0,msg=run.stdout+" / "+run.stderr)
        return json.loads(run.stdout)

    def prepare(self,note=NOTE,subject="TEST_EXPIRE"):
        r=self.run_cli("observe","--project","general","--subject",subject,
                 "--domain","BUILD_PROJECT","--class","PROJECT_STATE",
                 "--note",note)
        self.assertEqual(r["status"],"REVIEW_REQUIRED")
        token=r["data"]["review_token"]
        stubpath=self.root/"review"/"pending"/(token+".json")
        stub=json.loads(stubpath.read_text())
        self.assertEqual(stub["note_hash"],hashlib.sha256(note.encode()).hexdigest())
        self.assertIn("expires_at",stub)
        return token,stub,stubpath

    def expire(self,token,digest):
        return self.run_cli("review","expire-once","--token",token,"--note-hash",digest)

    @staticmethod
    def past_due(stub,stubpath):
        # Deliberately simulate time passage IN THE DISPOSABLE TEST ROOT only.
        stub["expires_at"]="2001-01-01T00:00:00+00:00"
        stubpath.write_text(json.dumps(stub,sort_keys=True)+"\n")
        stubpath.chmod(0o600)

    def test_early_expiry_denied_without_mutation(self):
        token,stub,path=self.prepare()
        before=path.read_bytes()
        r=self.expire(token,stub["note_hash"])
        self.assertEqual((r["status"],r["reason"]),("DENIED","EXPIRE_TOO_EARLY"))
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(list((self.root/"review"/"expired").glob("*.json")),[])

    def test_wrong_hash_denied(self):
        token,stub,path=self.prepare()
        self.past_due(stub,path)
        r=self.expire(token,"f"*64)
        self.assertEqual((r["status"],r["reason"]),("DENIED","EXPIRE_HASH_MISMATCH"))
        self.assertTrue(path.exists())

    def test_valid_expiry_archives_only_exact_token_and_preserves_rules(self):
        token,stub,path=self.prepare()
        rules_file=self.root/"review"/"rules.json"
        before=rules_file.read_bytes() if rules_file.exists() else None
        self.past_due(stub,path)
        result=self.expire(token,stub["note_hash"])
        self.assertEqual(result["status"],"OK")
        self.assertTrue(result["data"]["expired"])
        self.assertFalse(result["data"]["future_rule_created"])
        self.assertEqual(result["data"]["future_matching_submissions"],"UNAFFECTED")
        self.assertFalse(path.exists())
        archived=self.root/"review"/"expired"/(token+".json")
        self.assertTrue(archived.is_file())
        rec=json.loads(archived.read_text())
        self.assertEqual(rec["resolution"],"DENY_THIS_PROPOSAL_ONLY")
        self.assertEqual(rec["note_hash"],stub["note_hash"])
        self.assertNotIn("note",rec)
        self.assertEqual(rules_file.read_bytes() if rules_file.exists() else None,before)
        r=self.run_cli("review","resolve","--token",token,"--decision","authorize_once")
        self.assertEqual(r["status"],"HOLD_INTEGRITY_OR_AUTHORITY")
        # Similar future content may still enter the review queue; no broad deny.
        other=self.run_cli("observe","--project","general","--subject","TEST_EXPIRE",
             "--domain","BUILD_PROJECT","--class","PROJECT_STATE","--note",NOTE)
        self.assertEqual(other["status"],"REVIEW_REQUIRED")
        self.assertNotEqual(other["data"]["review_token"],token)

    def test_legacy_pending_without_ttl_is_not_expired(self):
        token,stub,path=self.prepare()
        stub.pop("expires_at")
        path.write_text(json.dumps(stub)+"\n")
        r=self.expire(token,stub["note_hash"])
        self.assertEqual((r["status"],r["reason"]),("DENIED","LEGACY_REQUEST_HAS_NO_TTL"))
        self.assertTrue(path.exists())

    def test_expired_request_cannot_be_authorized_even_before_cleanup(self):
        token,stub,path=self.prepare()
        self.past_due(stub,path)
        r=self.run_cli("review","resolve","--token",token,"--decision","authorize_once")
        self.assertEqual((r["status"],r["reason"]),("HOLD_INTEGRITY_OR_AUTHORITY","REVIEW_EXPIRED_MUST_USE_EXPIRE_ONCE"))
        self.assertFalse((self.root/"review"/"authorized"/(token+".json")).exists())

    def test_repeat_expiration_fails_closed(self):
        token,stub,path=self.prepare()
        self.past_due(stub,path)
        self.assertEqual(self.expire(token,stub["note_hash"])["status"],"OK")
        r=self.expire(token,stub["note_hash"])
        self.assertEqual((r["status"],r["reason"]),("DENIED","REVIEW_ALREADY_EXPIRED"))

    def test_due_tokens_do_not_remain_in_actionable_pending_list(self):
        token,stub,path=self.prepare()
        self.past_due(stub,path)
        view=self.run_cli("review","list")["data"]
        self.assertEqual(len(view["pending"]),0)
        self.assertEqual(len(view["expired_due"]),1)
        self.assertEqual(view["expired_due"][0]["token"],token)
        self.assertEqual(len(view["expired"]),0)
        self.assertEqual(self.expire(token,stub["note_hash"])["status"],"OK")
        after=self.run_cli("review","list")["data"]
        self.assertEqual(len(after["pending"]),0)
        self.assertEqual(len(after["expired_due"]),0)
        self.assertEqual(len(after["expired"]),1)
        self.assertEqual(after["expired"][0]["token"],token)

    def test_unrelated_pending_request_remains(self):
        token1,s1,p1=self.prepare(subject="TEST_FIRST")
        token2,s2,p2=self.prepare(NOTE2,subject="TEST_SECOND")
        self.past_due(s1,p1)
        self.assertEqual(self.expire(token1,s1["note_hash"])["status"],"OK")
        self.assertTrue(p2.exists())
        pending=self.run_cli("review","list")["data"]["pending"]
        self.assertEqual(len(pending),1)
        self.assertEqual(pending[0]["token"],token2)

    def test_non_owner_cannot_expire_pending_review(self):
        token,stub,path=self.prepare()
        self.past_due(stub,path)
        scope_file=Path(self.temp.name)/"scopes.json"
        scope_file.write_text(json.dumps({
            "profiles":["personal"],"projects":["general"],"subjects":["*"],
            "event_classes":["PROJECT_STATE"],"max_privacy":"INTERNAL_PROJECT"}))
        registration=self.run_cli("clients","register","--id","review_test_client",
            "--role","test","--scopes-file",str(scope_file))
        self.assertEqual(registration["status"],"OK")
        refused=self.run_cli("review","expire-once","--token",token,
            "--note-hash",stub["note_hash"],"--client","review_test_client")
        self.assertEqual(refused["status"],"DENIED")
        self.assertEqual(refused["reason"],"OWNER_AUTHORITY_REQUIRED")
        self.assertTrue(path.exists())

    def test_expiration_requires_explicit_hash_and_owner_authority(self):
        token,stub,path=self.prepare()
        self.past_due(stub,path)
        # The CLI routes wrong or absent hash through native validation.
        r=self.run_cli("review","expire-once","--token",token)
        self.assertEqual(r["status"],"DENIED")
        self.assertTrue(path.exists())
        # The dispatcher itself includes review.expire_once in OWNER_OPS
        source_root=(Path(__file__).parent if (Path(__file__).parent/"src").exists()
                     else Path(__file__).parent.parent)
        admin=(source_root/"src/pcmf_engine_admin.cpp").read_text()
        self.assertIn('"review.expire_once"',admin)
        self.assertIn('OWNER_AUTHORITY_REQUIRED',admin)

if __name__=="__main__":
    unittest.main()
