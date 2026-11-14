import json, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
BIN = ROOT / "bin" / "pcmf"

class StatusLanguageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="pcmf-lang-")
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/"root"
        self.run_cli("init","--profile","morphius","--project","test")
        marker=json.loads((self.root/".pcmf_root").read_text())
        conf=self.root/"config"/"pcmf.conf"
        text=conf.read_text()
        self.assertIn("writer_authority=hold\n",text)
        conf.write_text(text.replace("writer_authority=hold\n",
                                     "writer_authority=authorized_r243\n",1))
        conf.chmod(0o600)
        receipt={
            "schema":"forge.pcmf.techmagnet.legacy_to_r16_migration.v2",
            "new_root_id":marker["root_id"],
            "source_events":0,
            "source_media_modified":False,
            "acceptance":{"status_healthy":True,"store_verify":"PASS",
                          "store_replay":"PASS_READBACK_IDENTICAL"}}
        rp=self.root/"MIGRATION_RECEIPT_TECHMAGNET_20261102.json"
        rp.write_text(json.dumps(receipt,sort_keys=True)+"\n")
        rp.chmod(0o600)

    def run_cli(self,*args):
        p=subprocess.run([str(BIN),*args,"--root",str(self.root)],capture_output=True,text=True,timeout=12)
        self.assertEqual(p.returncode,0,msg=p.stdout+"\n"+p.stderr)
        return json.loads(p.stdout)

    def observe(self,note):
        return self.run_cli("observe","--profile","morphius","--project","test",
            "--subject","LANGUAGE_POLICY","--domain","MEMORY_SYSTEM",
            "--class","PROJECT_STATE","--note",note)

    def test_generic_hold_is_reword_not_review(self):
        out=self.observe("Project status: HOLD pending more coding.")
        self.assertEqual(out["status"],"REWORD_REQUIRED")
        self.assertEqual(out["reason"],"GENERIC_HOLD_LANGUAGE_NOT_ALLOWED")
        self.assertFalse(out["data"]["stored"])
        self.assertFalse(out["data"]["owner_acceptance_gate"])
        self.assertEqual(out["data"]["instruction"],"REWORD_AND_RESUBMIT_NO_OWNER_REVIEW_REQUIRED")
        self.assertNotIn("review_token",out["data"])
        self.assertEqual(list((self.root/"review"/"pending").glob("*.json")),[])
        self.assertEqual(self.run_cli("state")["data"]["events"],0)

    def test_old_hold_tag_is_reword(self):
        out=self.observe("status=HOLD_R241_R242")
        self.assertEqual(out["status"],"REWORD_REQUIRED")
        self.assertFalse(out["data"]["owner_acceptance_gate"])

    def test_case_insensitive_hold_is_reword(self):
        out=self.observe("Project is on hold until the next change.")
        self.assertEqual(out["status"],"REWORD_REQUIRED")

    def test_approved_reword_admits_without_review(self):
        out=self.observe("MORE_DEVELOPMENT_NEEDED: complete parser tests next.")
        self.assertEqual(out["status"],"OK")
        self.assertTrue(out["data"]["stored"])
        self.assertNotIn("review_token",out["data"])
        self.assertEqual(self.run_cli("state")["data"]["events"],1)

    def test_response_contains_accepted_terms(self):
        out=self.observe("HOLD")
        terms=set(out["data"]["accepted_terms"])
        required={"MORE_DEVELOPMENT_NEEDED","COMPLETION_NEEDED_FOR_NEXT_STEP",
                  "FIX_NEEDED_FOR_NEXT_STEP","TESTING_NEEDED_FOR_NEXT_STEP",
                  "VERIFICATION_NEEDED","OWNER_APPROVAL_REQUIRED",
                  "INTEGRITY_BLOCKED","AUTHORITY_BLOCKED"}
        self.assertTrue(required.issubset(terms))

if __name__=="__main__":
    unittest.main()
