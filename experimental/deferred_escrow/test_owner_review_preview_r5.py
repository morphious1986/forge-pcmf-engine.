"""Synthetic GUI integration of opt-in capture/unlock; no canonical PCMF writes."""
import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import gi
gi.require_version("Gtk","3.0")
from gi.repository import Gtk
from pending_review_bridge import PendingReviewBridge
from owner_review_preview_r5 import ReviewPreview

TOKEN="a"*64
ROOT_ID="b"*32
NOTE="Synthetic saved text for GUI testing, no real private information."
PWD="Synthetic test passphrase only - keep out of production"

class SyntheticConsole:
    def __init__(self,root):
        self.root=root
        self.pending=True
    def __call__(self,args,**kwargs):
        if args[1]=="status":
            payload={"root":str(self.root),"root_id":ROOT_ID,
                     "healthy":True,"chain_ok":True,"index_ok":True}
        elif args[1:3]==["review","list"]:
            items=[{"token":TOKEN,"note_hash":hashlib.sha256(NOTE.encode()).hexdigest(),
                    "note_bytes":len(NOTE.encode()),"subject":"FAKE"}] if self.pending else []
            payload={"status":"OK","data":{"pending":items}}
        else:raise AssertionError("Only read-only actions are accepted")
        class R:
            returncode=0
            stdout=json.dumps(payload)
        return R()

class PreviewTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="pcmf-r5-ui-")
        self.addCleanup(self.temp.cleanup)
        d=Path(self.temp.name)
        binary=d/"pcmf";binary.touch()
        self.fake=SyntheticConsole(d)
        self.mock=patch("pending_review_bridge.subprocess.run",side_effect=self.fake)
        self.mock.start()
        self.addCleanup(self.mock.stop)
        bridge=PendingReviewBridge(pcmf_binary=binary,pcmf_root=d,
                                   inbox_root=d/"inbox",expected_root_id=ROOT_ID)
        self.window=ReviewPreview(bridge)
        self.window._info=lambda *args: None
        self.window.token.set_text(TOKEN)
        self.window.show_all()
        while Gtk.events_pending():Gtk.main_iteration_do(False)
    def tearDown(self):
        self.window.disconnect_by_func(Gtk.main_quit)
        self.window.destroy()
    def text(self):
        b=self.window.note.get_buffer()
        return b.get_text(b.get_start_iter(),b.get_end_iter(),False)
    def test_owner_capture_then_deferred_unlock(self):
        self.window.note.get_buffer().set_text(NOTE)
        self.window.password.set_text(PWD)
        self.window.capture()
        self.assertFalse((Path(self.temp.name)/"inbox"/(TOKEN+".json")).exists())
        self.assertEqual(self.text(),NOTE)
        self.window.consent.set_active(True)
        self.window.password.set_text(PWD)
        self.window.capture()
        self.assertEqual(self.text(),"")
        self.assertEqual(self.window.password.get_text(),"")
        self.window.password.set_text(PWD)
        self.window.unlock()
        self.assertEqual(self.text(),NOTE)
        self.assertEqual(self.window.password.get_text(),"")
    def test_resolved_pending_review_cannot_be_unlocked(self):
        self.window.consent.set_active(True)
        self.window.note.get_buffer().set_text(NOTE)
        self.window.password.set_text(PWD)
        self.window.capture()
        self.fake.pending=False
        self.window.password.set_text(PWD)
        self.window.unlock()
        self.assertEqual(self.text(),"")
    def test_wrong_passphrase_no_disclosure(self):
        self.window.consent.set_active(True)
        self.window.note.get_buffer().set_text(NOTE)
        self.window.password.set_text(PWD)
        self.window.capture()
        self.window.password.set_text("intentionally wrong passphrase")
        self.window.unlock()
        self.assertEqual(self.text(),"")
if __name__=="__main__":unittest.main()
