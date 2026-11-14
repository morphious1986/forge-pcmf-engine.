"""R10 actionable-only queue classification and GTK regression tests."""
import os, stat, json, tempfile, unittest, importlib.machinery,importlib.util, hashlib,time
from pathlib import Path
from unittest.mock import patch
import gi
gi.require_version("Gtk","3.0")
from gi.repository import Gtk
L=importlib.machinery.SourceFileLoader("pcmf_r10_test",str(Path(__file__).parent.parent/"control_center"/"forge-pcmf-control-center"))
spec=importlib.util.spec_from_loader(L.name,L)
app=importlib.util.module_from_spec(spec);L.exec_module(app)

def row(n):
 return {"subject":f"TEST_{n}","token":f"{n:064x}","note_hash":"a"*64,"note_bytes":12,"reason":"OWNER_REVIEW_REQUIRED","event_class":"PROJECT_STATE","created_at":"2026-11-13T20:00:00Z"}
def fixture(ready,legacy):
 return {"events":3,"chain_ok":True,"index_ok":True,"root_id":app.ROOT_ID,"subjects_by_state":{}},{
  "pending":ready,"needs_original":legacy,"authorized":[],"approved":[],"rejected":[]}
def spin():
 end=time.monotonic()+.25
 while time.monotonic()<end:
  while Gtk.events_pending():Gtk.main_iteration_do(False)
  time.sleep(.01)
class QueueTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix="pcmf-r10-")
  self.addCleanup(self.temp.cleanup)
  self.inbox=Path(self.temp.name)/"inbox"
  self.inbox.mkdir(mode=0o700)
 def _record(self,x):
  d={"version":"PCMF_DEFERRED_OWNER_ESCROW_V1","root_id":app.ROOT_ID,"token":x["token"],
     "salt":"MTIzNDU2Nzg5MDEyMzQ1Ng==","nonce":"MTIzNDU2Nzg5MDEy","ciphertext":"YWJjZA=="}
  f=self.inbox/(x["token"]+".json")
  f.write_text(json.dumps(d));f.chmod(0o600);return f
 def test_no_encrypted_note_goes_to_resubmission(self):
  r=[row(i) for i in range(1,14)]
  ready,missing=app.classify_reviewability(r,self.inbox,app.ROOT_ID)
  self.assertEqual(len(ready),0);self.assertEqual(len(missing),13)
 def test_valid_escrow_candidate_shows_as_ready_not_admitted(self):
  records=[row(1),row(2)]
  self._record(records[1])
  ready,missing=app.classify_reviewability(records,self.inbox,app.ROOT_ID)
  self.assertEqual([x["token"] for x in ready],[records[1]["token"]])
  self.assertEqual([x["token"] for x in missing],[records[0]["token"]])
 def test_symlink_non_private_and_root_mismatch_never_ready(self):
  x=row(11);f=self._record(x)
  f.chmod(0o644)
  self.assertFalse(app.classify_reviewability([x],self.inbox,app.ROOT_ID)[0])
  f.chmod(0o600)
  d=json.loads(f.read_text());d["root_id"]="f"*32;f.write_text(json.dumps(d));f.chmod(0o600)
  self.assertFalse(app.classify_reviewability([x],self.inbox,app.ROOT_ID)[0])
  f.unlink();f.symlink_to("/etc/hosts")
  self.assertFalse(app.classify_reviewability([x],self.inbox,app.ROOT_ID)[0])
 def test_non_private_inbox_refused(self):
  x=row(3);self._record(x)
  self.inbox.chmod(0o755)
  self.assertFalse(app.classify_reviewability([x],self.inbox,app.ROOT_ID)[0])
 def _gui(self,ready,legacy):
  ctx=patch.object(app,"gather",return_value=fixture(ready,legacy));ctx.start();self.addCleanup(ctx.stop)
  w=app.Center();w.show_all();spin()
  self.addCleanup(lambda: (w.disconnect_by_func(Gtk.main_quit),w.destroy()))
  return w
 def test_gui_13_missing_zero_ready(self):
  w=self._gui([], [row(i) for i in range(1,14)])
  self.assertEqual(w.book.get_current_page(),0)
  self.assertEqual(len(w.rows["pending"]),0)
  self.assertEqual(len(w.rows["needs_original"]),13)
  self.assertFalse(w.review_now_button.get_sensitive())
  self.assertIn("READY FOR APPROVAL: 0",w.pending_count.get_text())
  self.assertIn("NEED ORIGINAL TEXT: 13",w.pending_count.get_text())
 def test_legacy_tab_cannot_trigger_unrelated_approval(self):
  w=self._gui([row(2)],[row(1)])
  self.assertEqual(len(w.rows["pending"]),1)
  w.book.set_current_page(1)
  w.views["needs_original"][0].get_selection().select_path(0)
  called=[]
  w.owner_review=lambda *args,**kw:called.append(1)
  w.review_now()
  self.assertEqual(called,[])
  self.assertEqual(w.book.get_current_page(),1)
 def test_ready_select_first_and_button(self):
  w=self._gui([row(2)],[row(1)])
  self.assertTrue(w.review_now_button.get_sensitive())
  self.assertEqual(w.current()[1]["token"],row(2)["token"])
if __name__=="__main__":unittest.main()
