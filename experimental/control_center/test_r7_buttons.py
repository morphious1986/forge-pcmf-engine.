"""Synthetic GTK R7 passphrase button tests; no canonical edits."""
import importlib.machinery,importlib.util,tempfile,unittest
from pathlib import Path
import gi
gi.require_version("Gtk","3.0")
from gi.repository import Gtk
from passphrase_manager import OwnerPassphrase

NAME="forge-pcmf-control-center"
L=importlib.machinery.SourceFileLoader("r7_control_center",str(Path(__file__).parent/NAME))
S=importlib.util.spec_from_loader(L.name,L)
app=importlib.util.module_from_spec(S);L.exec_module(app)

OLD="synthetic owner passphrase old"
NEW="synthetic owner passphrase new"

def all_children(widget):
    yield widget
    if isinstance(widget,Gtk.Container):
        for child in widget.get_children():yield from all_children(child)

class R7ButtonTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="pcmf-r7-gui-")
        self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)
        self.manager=OwnerPassphrase(self.home/"config",self.home/"escrow","b"*32)
        self.window=app.Center()
        self.window._password_manager=lambda:self.manager
        self.messages=[]
        self.window.showmsg=lambda message,*args:self.messages.append(message)
        while Gtk.events_pending():Gtk.main_iteration_do(False)
    def tearDown(self):
        self.window.disconnect_by_func(Gtk.main_quit)
        self.window.destroy()
    def test_visible_passphrase_buttons(self):
        labels=[w.get_label() for w in all_children(self.window) if isinstance(w,Gtk.Button)]
        self.assertIn("Set Up Passphrase",labels)
        self.assertIn("Change Passphrase",labels)
        self.assertIn("Close Window",labels)
    def test_setup_and_change_via_ui_action(self):
        self.window._password_fields=lambda *_:(OLD,OLD)
        self.window.setup_passphrase()
        self.assertTrue(self.manager.verify(OLD))
        self.window._password_fields=lambda *_:(OLD,NEW,NEW)
        self.window.change_passphrase()
        self.assertTrue(self.manager.verify(NEW))
        with self.assertRaises(Exception):self.manager.verify(OLD)
    def test_setup_confirmation_mismatch(self):
        self.window._password_fields=lambda *_:(OLD,NEW)
        self.window.setup_passphrase()
        self.assertFalse(self.manager.configured())
    def test_change_wrong_current_does_not_overwrite(self):
        self.manager.setup(OLD,OLD)
        self.window._password_fields=lambda *_:("wrong old passphrase",NEW,NEW)
        self.window.change_passphrase()
        self.assertTrue(self.manager.verify(OLD))
if __name__=="__main__":unittest.main()
