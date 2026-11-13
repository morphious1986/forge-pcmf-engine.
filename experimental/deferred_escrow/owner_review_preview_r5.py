#!/usr/bin/python3
"""PCMF deferred approval R5 owner UI preview.

Experimental: reads canonical pending metadata, encrypts manually supplied exact
text with explicit opt-in, and unlocks previously encrypted text. It CANNOT
approve/reject, write PCMF memories, or change any production PCMF state.
"""
import os
import sys
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk

from pending_review_bridge import PendingReviewBridge, BridgeError
from deferred_escrow import EscrowError

BANNER = "R5 DEVELOPMENT PREVIEW — no PCMF admission or review resolution"
TOKEN_NOTE = "Exact original text is required for capture. Previously discarded notes cannot be reconstructed."

class ReviewPreview(Gtk.Window):
    def __init__(self, bridge):
        super().__init__(title="Forge PCMF — Deferred Approval Preview R5")
        self.bridge=bridge
        self.set_default_size(900, 620)
        self.connect("destroy", Gtk.main_quit)
        frame=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=9)
        frame.set_border_width(16)
        self.add(frame)
        frame.pack_start(Gtk.Label(label=BANNER, xalign=0),False,False,0)
        frame.pack_start(Gtk.Label(label=TOKEN_NOTE, xalign=0),False,False,0)
        frame.pack_start(Gtk.Label(label="Pending review token (64 hexadecimal characters):",xalign=0),False,False,0)
        self.token=Gtk.Entry();self.token.set_max_length(64)
        frame.pack_start(self.token,False,False,0)
        actions=Gtk.Box(spacing=8);frame.pack_start(actions,False,False,0)
        for text,func in [("Verify pending",self.inspect_pending),
                          ("Capture encrypted (opt-in)",self.capture),
                          ("Unlock for review",self.unlock)]:
            button=Gtk.Button(label=text)
            button.connect("clicked",func)
            actions.pack_start(button,False,False,0)
        self.details=Gtk.Label(label="No review selected.",xalign=0)
        self.details.set_line_wrap(True)
        frame.pack_start(self.details,False,False,0)
        frame.pack_start(Gtk.Label(label="Owner-supplied exact original note (capture only):",xalign=0),False,False,0)
        self.note=Gtk.TextView()
        self.note.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        sw=Gtk.ScrolledWindow();sw.set_min_content_height(170);sw.add(self.note)
        frame.pack_start(sw,True,True,0)
        self.consent=Gtk.CheckButton(label="I explicitly authorize encrypted temporary local storage of this one exact note.")
        frame.pack_start(self.consent,False,False,0)
        frame.pack_start(Gtk.Label(label="Owner unlock passphrase (not stored):",xalign=0),False,False,0)
        self.password=Gtk.Entry();self.password.set_visibility(False)
        self.password.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        frame.pack_start(self.password,False,False,0)
        frame.pack_start(Gtk.Label(label="This preview cannot approve, reject or submit memory. Use the authenticated PCMF owner-review flow separately.",xalign=0),False,False,0)

    def _clear_password(self):
        self.password.set_text("")

    def _info(self,text,message_type=Gtk.MessageType.INFO):
        dialog=Gtk.MessageDialog(self,0,message_type,Gtk.ButtonsType.OK,text)
        dialog.run();dialog.destroy()

    def _read_note(self):
        buffer=self.note.get_buffer()
        return buffer.get_text(buffer.get_start_iter(),buffer.get_end_iter(),False)

    def inspect_pending(self,*_args):
        try:
            item=self.bridge.pending_metadata(self.token.get_text())
            self.details.set_text("Subject: %s  |  Review bytes: %s  |  Pending verified."%
                                  (item.get("subject"),item["note_bytes"]))
        except (BridgeError,EscrowError) as exc:
            self.details.set_text("Unavailable: "+str(exc))

    def capture(self,*_args):
        try:
            note=self._read_note()
            pwd=self.password.get_text()
            if not self.consent.get_active():
                raise BridgeError("EXPLICIT_OWNER_OPT_IN_REQUIRED")
            # Never log, print, or include plaintext or passphrase in a message.
            result=self.bridge.capture_if_owner_consents(
                token=self.token.get_text(), original_note=note,
                owner_passphrase=pwd, owner_opted_in=True)
            self.note.get_buffer().set_text("")
            self._info("Encrypted entry created. Current review remains PENDING.\n"
                       "No admission, approval, or execution authorization occurred.")
            self.inspect_pending()
        except (BridgeError,EscrowError,ValueError,OSError) as exc:
            self._info("Capture not completed: "+type(exc).__name__,
                       Gtk.MessageType.WARNING)
        finally:
            self._clear_password()

    def unlock(self,*_args):
        try:
            note=self.bridge.unlock_if_still_pending(
                token=self.token.get_text(),
                owner_passphrase=self.password.get_text())
            self.note.get_buffer().set_text(note)
            self._info("Exact note unlocked for inspection.\n"
                       "It remains PENDING, and the preview cannot approve it.")
        except (BridgeError,EscrowError,ValueError,OSError) as exc:
            self._info("Unlock refused: "+type(exc).__name__,
                       Gtk.MessageType.WARNING)
        finally:
            self._clear_password()

def launch(bridge):
    app=ReviewPreview(bridge);app.show_all();Gtk.main()

if __name__=="__main__":
    if sys.argv[1:]==["--ui-smoke"]:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="pcmf-ui-r5-") as d:
            p=Path(d)/"pcmf";p.touch()
            b=PendingReviewBridge(pcmf_binary=p,pcmf_root=d,
                inbox_root=Path(d)/"inbox",expected_root_id="0"*32)
            win=ReviewPreview(b);win.show_all()
            from gi.repository import GLib
            GLib.timeout_add(350, Gtk.main_quit)
            Gtk.main()
            win.hide()
        print("R5_UI_SMOKE_PASS")
    else:
        raise SystemExit("This experimental preview is not enabled for live PCMF. Use --ui-smoke for a synthetic window.")
