"""Synthetic, disposable-only tests for encrypted PCMF deferred owner inbox."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
import deferred_escrow as e

T = "a" * 64
R = "b" * 32
P = "owner synthetic passphrase with adequate length"
NOTE = "Synthetic review content: test data, no personal information."


class EscrowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pcmf-r3-escrow-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "owner_private"

    def test_roundtrip_after_deferred_close(self):
        self.assertEqual(e.store(self.root,T,R,NOTE,P)["status"],"ENCRYPTED")
        self.assertEqual(e.retrieve(self.root,T,R,P),NOTE)

    def test_plaintext_never_in_record(self):
        e.store(self.root,T,R,NOTE,P)
        payload=(self.root/(T+".json")).read_bytes()
        self.assertNotIn(NOTE.encode(),payload)
        self.assertNotIn(P.encode(),payload)
        self.assertEqual(self.root.stat().st_mode & 0o777,0o700)
        self.assertEqual((self.root/(T+".json")).stat().st_mode & 0o777,0o600)

    def test_wrong_password_fails(self):
        e.store(self.root,T,R,NOTE,P)
        with self.assertRaises(e.EscrowError):
            e.retrieve(self.root,T,R,P+" wrong")

    def test_swapped_token_refused(self):
        e.store(self.root,T,R,NOTE,P)
        os.rename(self.root/(T+".json"),self.root/("c"*64+".json"))
        with self.assertRaises(e.EscrowError):
            e.retrieve(self.root,"c"*64,R,P)

    def test_root_identity_binding(self):
        e.store(self.root,T,R,NOTE,P)
        with self.assertRaises(e.EscrowError):
            e.retrieve(self.root,T,"d"*32,P)

    def test_ciphertext_tampering_fails_closed(self):
        e.store(self.root,T,R,NOTE,P)
        path=self.root/(T+".json")
        obj=json.loads(path.read_text())
        ciphertext=obj["ciphertext"]
        obj["ciphertext"]=("A" if ciphertext[0]!="A" else "B")+ciphertext[1:]
        path.write_text(json.dumps(obj))
        with self.assertRaises(e.EscrowError):
            e.retrieve(self.root,T,R,P)

    def test_duplicate_refused(self):
        e.store(self.root,T,R,NOTE,P)
        with self.assertRaisesRegex(e.EscrowError,"ALREADY_EXISTS"):
            e.store(self.root,T,R,"another",P)
        self.assertEqual(e.retrieve(self.root,T,R,P),NOTE)

    def test_symlink_root_refused(self):
        self.root.mkdir(mode=0o700)
        alias=Path(self.tmp.name)/"alias"
        alias.symlink_to(self.root)
        with self.assertRaises(e.EscrowError):
            e.store(alias,T,R,NOTE,P)

    def test_symlink_record_refused(self):
        self.root.mkdir(mode=0o700)
        (self.root/(T+".json")).symlink_to(Path(self.tmp.name)/"other")
        with self.assertRaises(e.EscrowError):
            e.store(self.root,T,R,NOTE,P)
        with self.assertRaises(e.EscrowError):
            e.retrieve(self.root,T,R,P)

    def test_insecure_root_refused(self):
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o755)
        with self.assertRaises(e.EscrowError):
            e.store(self.root,T,R,NOTE,P)

    def test_large_note_refused(self):
        with self.assertRaises(e.EscrowError):
            e.store(self.root,T,R,"x"*(e.MAX_NOTE_BYTES+1),P)

    def test_short_passphrase_refused(self):
        with self.assertRaises(e.EscrowError):
            e.store(self.root,T,R,NOTE,"too short")

    def test_bad_token_refused(self):
        with self.assertRaises(e.EscrowError):
            e.store(self.root,"invalid",R,NOTE,P)

    def test_explicit_discard_does_not_change_canonical_state(self):
        e.store(self.root,T,R,NOTE,P)
        self.assertEqual(e.discard(self.root,T,R)["status"],"DISCARDED")
        self.assertFalse((self.root/(T+".json")).exists())
        with self.assertRaises(e.EscrowError):
            e.retrieve(self.root,T,R,P)

    def test_discard_mismatched_root_refused(self):
        e.store(self.root,T,R,NOTE,P)
        with self.assertRaises(e.EscrowError):
            e.discard(self.root,T,"d"*32)
        self.assertTrue((self.root/(T+".json")).exists())


if __name__ == "__main__":
    unittest.main()
