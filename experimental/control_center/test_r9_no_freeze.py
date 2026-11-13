"""R9 freeze-regression tests: synthetic metadata, never write canonical memory."""
import importlib.machinery,importlib.util,hashlib,time,unittest
from pathlib import Path
from unittest.mock import patch
import gi
gi.require_version("Gtk","3.0")
from gi.repository import Gtk,GLib

loader=importlib.machinery.SourceFileLoader("pcmf_r9_test",str(Path(__file__).parent.parent/"control_center"/"forge-pcmf-control-center"))
spec=importlib.util.spec_from_loader(loader.name,loader)
app=importlib.util.module_from_spec(spec)
loader.exec_module(app)

NOTE="Synthetic metadata-only memory."
TOKEN="a"*64
def response():
    row={"subject":"SYNTHETIC","project":"test","reason":"OWNER_REVIEW_REQUIRED",
         "token":TOKEN,"note_hash":hashlib.sha256(NOTE.encode()).hexdigest(),
         "note_bytes":len(NOTE.encode()),"event_class":"PROJECT_STATE",
         "created_at":"2026-11-13T20:00:00"}
    h={"events":3,"chain_ok":True,"index_ok":True,"root_id":app.ROOT_ID,"subjects_by_state":{}}
    return h,{"pending":[row],"authorized":[],"approved":[],"rejected":[]}

def drain(seconds=0.1):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        while Gtk.events_pending():Gtk.main_iteration_do(False)
        time.sleep(.01)

class ReviewNoFreezeTests(unittest.TestCase):
    def setUp(self):
        self.fake=patch.object(app,"gather",side_effect=response)
        self.fake.start()
        self.addCleanup(self.fake.stop)
        self.win=app.Center()
        self.win.show_all()
        drain(.25)
        self.assertEqual(self.win.current()[0],"pending")
        self.assertIsNotNone(self.win.current()[1])
    def tearDown(self):
        self.win.disconnect_by_func(Gtk.main_quit)
        self.win.destroy()
        drain(.03)

    def test_refresh_does_not_block_gtk(self):
        def slow():
            time.sleep(.65)
            return response()
        ticks=[]
        with patch.object(app,"gather",side_effect=slow):
            GLib.timeout_add(60,lambda:(ticks.append(time.monotonic()),False)[1])
            begin=time.monotonic()
            self.win.refresh()
            drain(.23)
            self.assertGreater(len(ticks),0)
            self.assertLess(time.monotonic()-begin,.45)
            drain(.65)
            self.assertFalse(self.win._refresh_busy)

    def test_review_verify_does_not_block_gtk(self):
        class SlowBridge:
            def pending_metadata(self,token):
                time.sleep(.6)
                return {"token":token}
        events=[]
        self.win._pending_bridge=lambda:SlowBridge()
        self.win.owner_review=lambda verified=False:events.append(verified)
        with patch.object(app,"canonical_health",return_value={}):
            GLib.timeout_add(55,lambda:(events.append("tick"),False)[1])
            self.win.review_now()
            drain(.2)
            self.assertIn("tick",events)
            self.assertNotIn(True,events)
            drain(.65)
            self.assertIn(True,events)

    def test_empty_original_text_stays_in_same_dialog(self):
        history=[]
        messages=[]
        self.win.showmsg=lambda *args:messages.append(args)
        def fake_run(dialog):
            if not history:
                history.append("clicked")
                return Gtk.ResponseType.OK
            labels=[w.get_text() for w in dialog.get_content_area().get_children()
                    if isinstance(w,Gtk.Label)]
            history.append(" | ".join(labels))
            return Gtk.ResponseType.CANCEL
        with patch.object(Gtk.Dialog,"run",fake_run),patch.object(app.subprocess,"Popen") as native:
            self.win.owner_review(verified=True)
            native.assert_not_called()
        self.assertEqual(messages,[])
        self.assertTrue(any("CANNOT AUTHORIZE" in str(x) for x in history))

    def test_slow_inspect_does_not_block_gtk(self):
        from unittest.mock import Mock
        class Result:
            returncode=0
            stdout='{"review":{"subject":"SYNTHETIC","reason":"TEST","note_bytes":4}}'
        def slow(*args,**kwargs):
            time.sleep(.55)
            return Result()
        tick=[]
        with patch.object(app,"canonical_health",return_value={}),patch.object(app.subprocess,"run",side_effect=slow):
            GLib.timeout_add(55,lambda:(tick.append(1),False)[1])
            self.win.inspect()
            drain(.2)
            self.assertTrue(tick)
            drain(.55)
            text=self.win.views["pending"][1].get_buffer()
            content=text.get_text(text.get_start_iter(),text.get_end_iter(),False)
            self.assertIn("Verified pending review",content)

    def test_slow_escrow_does_not_block_gtk(self):
        class Manager:
            def verify(self,password):
                time.sleep(.3)
                return True
        class Bridge:
            def capture_if_owner_consents(self,**kwargs):
                time.sleep(.35)
                return {"status":"ENCRYPTED"}
        self.win._password_manager=lambda:Manager()
        self.win._pending_bridge=lambda:Bridge()
        dialog=Gtk.Dialog(title="Synthetic",transient_for=self.win)
        feedback=Gtk.Label(label="starting")
        area=Gtk.TextView()
        consent=Gtk.CheckButton()
        dialog.get_content_area().pack_start(feedback,False,False,0)
        dialog.get_content_area().pack_start(area,False,False,0)
        dialog.get_content_area().pack_start(consent,False,False,0)
        dialog.show_all()
        area.get_buffer().set_text(NOTE)
        tick=[]
        GLib.timeout_add(55,lambda:(tick.append(1),False)[1])
        self.win._escrow_operation("save",TOKEN,NOTE,"synthetic-password",dialog,feedback,area,consent)
        drain(.2)
        self.assertTrue(tick)
        self.assertTrue(self.win._escrow_busy)
        drain(.7)
        self.assertFalse(self.win._escrow_busy)
        self.assertIn("Saved encrypted",feedback.get_text())
        dialog.destroy()

    def test_slow_passphrase_rotation_does_not_block_gtk(self):
        class Manager:
            def configured(self):return True
            def change(self,*args):
                time.sleep(.7)
                return {"status":"CHANGED","entries":2}
        self.win._password_manager=lambda:Manager()
        self.win._password_fields=lambda *args:("oldtest","newtest","newtest")
        ticks=[]
        GLib.timeout_add(55,lambda:(ticks.append(1),False)[1])
        self.win.change_passphrase()
        drain(.2)
        self.assertTrue(ticks)
        self.assertTrue(self.win._rotation_busy)
        drain(.7)
        self.assertFalse(self.win._rotation_busy)
        self.assertIn("2 encrypted note",self.win.foot.get_text())

    def test_pending_counter_and_review_button(self):
        self.assertTrue(self.win.review_now_button.get_sensitive())
        self.assertIn("1",self.win.pending_count.get_text())
        self.assertIn("REVIEW NOW",self.win.review_now_button.get_label())

if __name__=="__main__":unittest.main()
