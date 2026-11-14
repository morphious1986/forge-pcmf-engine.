"""R8 synthetic GTK approval dashboard tests, no production review actions."""
import importlib.machinery,importlib.util,unittest
from pathlib import Path
from unittest.mock import patch
import gi
gi.require_version("Gtk","3.0")
from gi.repository import Gtk
L=importlib.machinery.SourceFileLoader("pcmf_r8_gui_test",str(Path(__file__).parent.parent/"control_center"/"forge-pcmf-control-center"))
S=importlib.util.spec_from_loader(L.name,L)
app=importlib.util.module_from_spec(S);L.exec_module(app)

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.pending=[
          {"subject":"SYNTHETIC_PROJECT","project":"synthetic","reason":"OWNER_REVIEW_REQUIRED",
           "token":"a"*64,"note_hash":"b"*64,"note_bytes":8,"event_class":"OBSERVATION","created_at":"2026-11-13T21:00:00"}
        ]
        status={"events":1,"root_id":app.ROOT_ID,"chain_ok":True,"index_ok":True,"subjects_by_state":{}}
        self.gather=patch.object(app,"gather",return_value=(status,{"pending":list(self.pending),"authorized":[],"approved":[],"rejected":[]}))
        self.gather.start();self.addCleanup(self.gather.stop)
        self.win=app.Center()
        self.win.show_all()
        while Gtk.events_pending():Gtk.main_iteration_do(False)
        self.win.refresh()
    def tearDown(self):
        self.win.disconnect_by_func(Gtk.main_quit)
        self.win.destroy()
    def test_pending_opens_first_and_selected(self):
        self.assertEqual(self.win.book.get_current_page(),0)
        self.assertEqual(self.win.current()[1]["subject"],"SYNTHETIC_PROJECT")
        self.assertTrue(self.win.review_now_button.get_sensitive())
    def test_pending_count_visible(self):
        self.assertIn("1",self.win.pending_count.get_text())
        self.assertIn("APPROVAL",self.win.pending_count.get_text())
        self.assertIn("REVIEW NOW",self.win.review_now_button.get_label())
    def test_click_routes_to_native_review_dialog_handler(self):
        calls=[]
        self.win.owner_review=lambda:calls.append("owner_review")
        self.win.review_now_button.clicked()
        self.assertEqual(calls,["owner_review"])
        self.win.pending_double_click()
        self.assertEqual(calls,["owner_review","owner_review"])
    def test_history_tab_recovery(self):
        self.win.book.set_current_page(2)
        self.win.show_pending()
        self.assertEqual(self.win.book.get_current_page(),0)
        self.assertEqual(self.win.current()[1]["subject"],"SYNTHETIC_PROJECT")
    def test_no_pending_disables_action(self):
        self.pending.clear()
        self.gather.stop()
        with patch.object(app,"gather",return_value=({"events":1,"root_id":app.ROOT_ID,"chain_ok":True,"index_ok":True,"subjects_by_state":{}},{"pending":[],"authorized":[],"approved":[],"rejected":[]})):
            self.win.refresh()
        self.assertFalse(self.win.review_now_button.get_sensitive())
        self.assertIn("0",self.win.pending_count.get_text())

if __name__=="__main__":unittest.main()
