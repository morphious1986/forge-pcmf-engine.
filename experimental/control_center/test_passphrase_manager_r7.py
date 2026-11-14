import tempfile,unittest
from pathlib import Path
from passphrase_manager import OwnerPassphrase,PassphraseError
from deferred_escrow import store,retrieve

R="b"*32
T="a"*64
P="synthetic old test passphrase 123"
NEW="synthetic new test passphrase 456"
NOTE="Synthetic review note for migration and recovery test."

class PasswordTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="pcmf-r7-passphrase-")
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.config=self.base/"config"
        self.inbox=self.base/"escrow"
        self.m=OwnerPassphrase(self.config,self.inbox,R)
    def test_setup_confirm_and_reuse(self):
        with self.assertRaises(PassphraseError):self.m.setup(P,"mismatch")
        self.assertFalse(self.m.configured())
        self.m.setup(P,P)
        self.assertTrue(self.m.verify(P))
        with self.assertRaises(PassphraseError):self.m.setup(NEW,NEW)
        with self.assertRaises(PassphraseError):self.m.verify("wrong password")
        self.assertEqual(self.m.marker.stat().st_mode&0o777,0o600)
    def test_change_without_entries(self):
        self.m.setup(P,P)
        with self.assertRaises(PassphraseError):self.m.change("wrong password",NEW,NEW)
        self.assertTrue(self.m.verify(P))
        self.assertEqual(self.m.change(P,NEW,NEW)["entries"],0)
        self.assertTrue(self.m.verify(NEW))
        with self.assertRaises(PassphraseError):self.m.verify(P)
    def test_change_saved_entry_preserves_plaintext_with_new_pass(self):
        self.m.setup(P,P)
        store(self.inbox,T,R,NOTE,P)
        result=self.m.change(P,NEW,NEW)
        self.assertEqual(result["entries"],1)
        self.assertEqual(retrieve(self.inbox,T,R,NEW),NOTE)
        self.assertTrue(Path(result["encrypted_backup"]).exists())
        self.assertEqual(retrieve(result["encrypted_backup"],T,R,P),NOTE)
        with self.assertRaises(Exception):retrieve(self.inbox,T,R,P)
        self.assertTrue(self.m.verify(NEW))
    def test_wrong_pass_no_mutation(self):
        self.m.setup(P,P)
        store(self.inbox,T,R,NOTE,P)
        with self.assertRaises(PassphraseError):self.m.change("incorrect password",NEW,NEW)
        self.assertEqual(retrieve(self.inbox,T,R,P),NOTE)
        self.assertTrue(self.m.verify(P))
    def test_no_legacy_migration_without_owner(self):
        store(self.inbox,T,R,NOTE,P)
        with self.assertRaisesRegex(PassphraseError,"MIGRATION"):
            self.m.setup(NEW,NEW)
        self.assertFalse(self.m.configured())
    def test_deny_insecure_configuration_dir(self):
        self.config.mkdir()
        self.config.chmod(0o755)
        with self.assertRaises(PassphraseError):self.m.setup(P,P)
    def test_deny_too_short_or_mismatch(self):
        with self.assertRaises(PassphraseError):self.m.setup("short","short")
        with self.assertRaises(PassphraseError):self.m.setup(P,NEW)
        self.assertFalse(self.m.configured())
if __name__=="__main__":unittest.main()
