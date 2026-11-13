"""R12 encrypted 72-hour per-proposal retention test suite, synthetic only."""
import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from deferred_queue_r12 import DeferredQueue,QueueError,TTL_SECONDS,TOMBSTONE

TOKEN="a"*64
ROOT="b"*32
NOTE="Synthetic, private test note containing a build timestamp 20261113171530."
PASSWORD="Synthetic six character password"
class Clock:
    def __init__(self,at=1_800_000_000):self.value=at
    def __call__(self):return self.value
class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix="pcmf-r12-ttl-test-")
        self.addCleanup(t.cleanup)
        self.home=Path(t.name)/"queue"
        self.clock=Clock()
        self.q=DeferredQueue(self.home,ROOT,now=self.clock)
        self.q.create_owner_keys(PASSWORD,PASSWORD)
        self.meta={"status":"pending","token":TOKEN,"root_id":ROOT,
                   "note_hash":hashlib.sha256(NOTE.encode()).hexdigest(),
                   "note_bytes":len(NOTE.encode())}
        self.lookup=lambda token:dict(self.meta)
    def insert(self):
        return self.q.enqueue(TOKEN,NOTE,self.lookup,owner_capture_enabled=True)
    def test_exact_text_encrypted_round_trip(self):
        r=self.insert()
        self.assertEqual(r["expires_at"]-self.clock(),TTL_SECONDS)
        path=self.home/"notes"/(TOKEN+".json")
        self.assertNotIn(NOTE,path.read_text())
        self.assertEqual(self.q.unlock(TOKEN,PASSWORD,self.lookup),NOTE)
        self.assertEqual(path.stat().st_mode&0o777,0o600)
    def test_refuse_unconsented_capture(self):
        with self.assertRaisesRegex(QueueError,"NOT_ENABLED"):
            self.q.enqueue(TOKEN,NOTE,self.lookup)
        self.assertFalse((self.home/"notes"/(TOKEN+".json")).exists())
    def test_refuse_unmatched_note(self):
        with self.assertRaisesRegex(QueueError,"HASH_MISMATCH"):
            self.q.enqueue(TOKEN,NOTE+" different",self.lookup,owner_capture_enabled=True)
    def test_refuse_invalid_pending_state(self):
        self.meta["status"]="rejected"
        with self.assertRaisesRegex(QueueError,"NOT_VERIFIED"):
            self.insert()
    def test_capture_revalidates_pending(self):
        calls=[0]
        def changing(token):
            calls[0]+=1
            v=dict(self.meta)
            if calls[0]>1:v["status"]="approved"
            return v
        with self.assertRaisesRegex(QueueError,"STALE_PENDING"):
            self.q.enqueue(TOKEN,NOTE,changing,owner_capture_enabled=True)
        self.assertFalse((self.home/"notes"/(TOKEN+".json")).exists())
    def test_duplicate_not_overwritten(self):
        self.insert()
        with self.assertRaisesRegex(QueueError,"DUPLICATE"):
            self.insert()
    def test_wrong_password_does_not_expose_original(self):
        self.insert()
        with self.assertRaises(QueueError):
            self.q.unlock(TOKEN,"wrong password",self.lookup)
    def test_at_72_hours_expired_and_denied_local_only(self):
        self.insert()
        self.clock.value += TTL_SECONDS
        with self.assertRaisesRegex(QueueError,"EXPIRED_DENIED"):
            self.q.unlock(TOKEN,PASSWORD,self.lookup)
        self.assertEqual(self.q.list_available(),[])
        self.assertFalse((self.home/"notes"/(TOKEN+".json")).exists())
        obj=json.loads((self.home/"expired"/(TOKEN+".json")).read_text())
        self.assertEqual(obj["status"],TOMBSTONE)
        self.assertNotIn(NOTE,json.dumps(obj))
    def test_before_deadline_still_available(self):
        self.insert()
        self.clock.value += TTL_SECONDS-1
        self.assertEqual(self.q.unlock(TOKEN,PASSWORD,self.lookup),NOTE)
    def test_sweeper_removes_expired_without_unlock(self):
        self.insert()
        self.clock.value += TTL_SECONDS+20
        self.assertEqual(self.q.sweep()["expired_local_only"],1)
        self.assertEqual(self.q.sweep()["expired_local_only"],0)
    def test_expiry_not_premature_and_no_force_delete(self):
        self.insert()
        with self.assertRaisesRegex(QueueError,"NOT_YET_EXPIRED"):
            self.q.expire_token(TOKEN)
        with self.assertRaisesRegex(QueueError,"UNAUTHORIZED"):
            self.q.expire_token(TOKEN,reason="USER_WANTS_CLEANUP")
        self.assertEqual(self.q.unlock(TOKEN,PASSWORD,self.lookup),NOTE)
    def test_owner_key_private_and_setup_single_use(self):
        self.assertEqual((self.home/"owner_keys.json").stat().st_mode&0o777,0o600)
        self.assertEqual(self.home.stat().st_mode&0o777,0o700)
        with self.assertRaisesRegex(QueueError,"ALREADY_CREATED"):
            self.q.create_owner_keys(PASSWORD,PASSWORD)
    def test_broken_symlink_inbox_not_accepted(self):
        path=self.home/"notes"/(TOKEN+".json")
        path.symlink_to(self.home/"nonexistent")
        with self.assertRaisesRegex(QueueError,"DUPLICATE"):
            self.insert()
    def test_wrong_root_cannot_decrypt(self):
        self.insert()
        alternate=DeferredQueue(self.home,"c"*32,now=self.clock)
        with self.assertRaises(QueueError):
            alternate.unlock(TOKEN,PASSWORD,self.lookup)
    def test_changed_canonical_review_refuses_unlock(self):
        self.insert()
        self.meta["status"]="authorized"
        with self.assertRaisesRegex(QueueError,"NOT_CURRENT"):
            self.q.unlock(TOKEN,PASSWORD,self.lookup)
    def test_public_key_encrypts_without_private_key(self):
        pub=self.q.owner_public_key()
        self.assertEqual(len(pub),32)
        self.insert()
        self.assertNotIn(NOTE,(self.home/"owner_keys.json").read_text())
        self.assertNotIn(NOTE,(self.home/"notes"/(TOKEN+".json")).read_text())
if __name__=="__main__":unittest.main()
