"""R4 bridge acceptance tests. All requests are synthetic and isolated."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from pending_review_bridge import BridgeError, PendingReviewBridge

TOKEN = "a" * 64
ROOT_ID = "b" * 32
NOTE = "Synthetic owner-review text for deterministic test only."
PASSWORD = "synthetic owner passphrase for local tests"
DIGEST = hashlib.sha256(NOTE.encode()).hexdigest()

class FakeCLI:
    def __init__(self, root, *, status_ok=True, pending=True):
        self.root=root
        self.status_ok=status_ok
        self.pending=pending
        self.calls=[]
    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if command[1] == "status":
            data={"root":str(self.root),"root_id":ROOT_ID,
                  "chain_ok":self.status_ok,"index_ok":self.status_ok,"healthy":self.status_ok}
        else:
            assert command[1:3]==["review","list"]
            data={"pending":[{"token":TOKEN,"subject":"SYNTHETIC",
                    "note_bytes":len(NOTE.encode()),"note_hash":DIGEST,
                    "reason":"POTENTIALLY_SENSITIVE_CONTENT"}] if self.pending else []}
        class Result:
            returncode=0
            stdout=json.dumps(data if command[1] == "status"
                              else {"status":"OK","data":data})
        return Result()

class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="pcmf-r4-bridge-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.inbox=self.root/"inbox"
        self.binary=self.root/"pcmf"
        self.binary.write_text("synthetic fake binary")
        self.fake=FakeCLI(self.root)
        self.mock=patch("pending_review_bridge.subprocess.run",side_effect=self.fake)
        self.mock.start()
        self.addCleanup(self.mock.stop)
        self.bridge=PendingReviewBridge(pcmf_binary=self.binary,pcmf_root=self.root,
                            inbox_root=self.inbox,expected_root_id=ROOT_ID)
    def capture(self, **changes):
        return self.bridge.capture_if_owner_consents(**({
            "token":TOKEN,"original_note":NOTE,"owner_passphrase":PASSWORD,
            "owner_opted_in":True}|changes))
    def test_metadata_live_schema_shape(self):
        metadata=self.bridge.pending_metadata(TOKEN)
        self.assertEqual(metadata["note_hash"],DIGEST)
        self.assertEqual(metadata["note_bytes"],len(NOTE.encode()))
    def test_consent_required(self):
        with self.assertRaisesRegex(BridgeError,"OPT_IN"):
            self.capture(owner_opted_in=False)
        self.assertFalse(self.inbox.exists())
    def test_exact_note_required(self):
        with self.assertRaisesRegex(BridgeError,"ORIGINAL_NOTE"):
            self.capture(original_note=NOTE+" changed")
        self.assertFalse(self.inbox.exists())
    def test_roundtrip_and_read_only_bridge(self):
        self.assertEqual(self.capture()["status"],"ENCRYPTED")
        self.assertEqual(self.bridge.unlock_if_still_pending(token=TOKEN,
                                               owner_passphrase=PASSWORD),NOTE)
        self.assertTrue(all(c[1] in ("status","review") for c in self.fake.calls))
    def test_canonical_integrity_required(self):
        self.fake.status_ok=False
        with self.assertRaisesRegex(BridgeError,"HEALTH_NOT_OK"):
            self.capture()
        self.assertFalse(self.inbox.exists())
    def test_missing_token_fails_closed(self):
        self.fake.pending=False
        with self.assertRaisesRegex(BridgeError,"TOKEN_NOT_PENDING"):
            self.capture()
        self.assertFalse(self.inbox.exists())
    def test_stale_pending_token_blocks_unlock(self):
        self.capture()
        self.fake.pending=False
        with self.assertRaisesRegex(BridgeError,"TOKEN_NOT_PENDING"):
            self.bridge.unlock_if_still_pending(token=TOKEN,owner_passphrase=PASSWORD)
        self.assertTrue(self.inbox.exists())
    def test_wrong_password(self):
        self.capture()
        with self.assertRaises(Exception):
            self.bridge.unlock_if_still_pending(token=TOKEN,owner_passphrase=PASSWORD+" wrong")
    def test_changed_note_metadata_prevents_unlock(self):
        self.capture()
        self.fake.__call__=self.fake.__call__ # no mutation of production
        original=self.bridge.pending_metadata
        def altered(token):
            result=original(token);return dict(result,note_hash="f"*64)
        with patch.object(self.bridge,"pending_metadata",side_effect=altered):
            with self.assertRaisesRegex(BridgeError,"ORIGINAL_NOTE"):
                self.bridge.unlock_if_still_pending(token=TOKEN,owner_passphrase=PASSWORD)
    def test_short_invalid_token(self):
        with self.assertRaisesRegex(BridgeError,"TOKEN_FORMAT"):
            self.bridge.pending_metadata("a"*32)
    def test_root_id_mismatch(self):
        self.bridge.root_id="c"*32
        with self.assertRaisesRegex(BridgeError,"ROOT_ID"):
            self.capture()
    def test_duplicate_capture_is_denied(self):
        self.capture()
        with self.assertRaises(Exception):
            self.capture()
    def test_no_exposure_to_cli_arguments(self):
        self.capture()
        for args in self.fake.calls:
            serialized=" ".join(args)
            self.assertNotIn(NOTE,serialized)
            self.assertNotIn(PASSWORD,serialized)
    def test_no_implicit_authorization(self):
        self.capture()
        self.assertFalse(any("resolve" in c for args in self.fake.calls for c in args))
    def test_queue_client_status_only(self):
        self.bridge.pending_metadata(TOKEN)
        self.assertEqual([args[1] for args in self.fake.calls],["status","review"])

if __name__=="__main__": unittest.main()
