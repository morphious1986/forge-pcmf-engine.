#!/usr/bin/python3
"""Forge PCMF Control Center R7. Explicit owner passphrase setup and rotation."""
import os, sys, json, hashlib, subprocess, threading
from pathlib import Path
sys.path.insert(0, str(Path.home()/".local/libexec"))
from pcmf_review_r2_policy import review_advice, memory_vs_execution, verify_reject_once_semantics
from pending_review_bridge import PendingReviewBridge, BridgeError
from deferred_escrow import EscrowError
from passphrase_manager import OwnerPassphrase, PassphraseError
from pathlib import Path
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib

CONFIG=Path.home()/".config/pcmf/control-center-r6.json"
def _load_control_center_config():
    if CONFIG.is_symlink() or not CONFIG.is_file() or CONFIG.stat().st_mode & 0o077:
        raise RuntimeError("Owner-controlled R6 configuration missing or insecure")
    cfg=json.loads(CONFIG.read_text())
    for key in ("root","root_id","binary","reviewer"):
        if key not in cfg or not isinstance(cfg[key],str):
            raise RuntimeError("Invalid owner-controlled R6 configuration")
    for key in ("root","binary","reviewer"):
        if not Path(cfg[key]).is_absolute():
            raise RuntimeError("PCMF R6 configuration paths must be absolute")
    if len(cfg["root_id"])!=32 or any(c not in "0123456789abcdef" for c in cfg["root_id"]):
        raise RuntimeError("Invalid canonical PCMF root identity")
    return cfg
_SETTINGS=_load_control_center_config()
ROOT=Path(_SETTINGS["root"])
ROOT_ID=_SETTINGS["root_id"]
BIN=Path(_SETTINGS["binary"])
REVIEWER=Path(_SETTINGS["reviewer"])
ICON=Path.home()/".local/share/icons/forge-custom-r1/forge-pcmf-control-center.svg"
ESCROW=Path.home()/".local/share/pcmf-owner-review-escrow"
STATES=("pending","authorized","approved","rejected")
FIELDS=("subject","event_class","created_at","reason","domain","client","authorized_at","consumed_at","decision","event_id")
CSS=b"""
window, box, notebook, scrolledwindow, viewport, treeview, textview {background:#101b24;color:#edf3f5;}
#top {background:#1b2c39;padding:19px;}
#headline {color:#ffb75c;font-size:23px;font-weight:bold;}
#subline {color:#a6c2d0;font-size:12px;}
#health {padding:12px;color:#b2e1cb;}
#bottom {padding:10px;color:#a0b7c6;}
button {background:#273c4a;color:#f2f4f4;border:1px solid #536d7c;border-radius:7px;padding:8px 11px;}
button:hover {background:#375566;}
notebook tab {padding:8px;}
textview {font-family:monospace;font-size:12px;}
"""
def cmd(args,timeout=12):
    p=subprocess.run([str(BIN),*args],capture_output=True,text=True,timeout=timeout,check=False)
    if p.returncode or not p.stdout.strip():raise RuntimeError((p.stderr or p.stdout or "Command failed")[:350])
    data=json.loads(p.stdout)
    if data.get("status") not in ("OK",None):raise RuntimeError(str(data.get("reason") or data.get("status")))
    return data
def canonical_health():
    h=cmd(["status","--root",str(ROOT)])
    if h.get("root")!=str(ROOT) or h.get("root_id")!=ROOT_ID or not h.get("chain_ok") or not h.get("index_ok"):
        raise RuntimeError("Canonical root identity or integrity mismatch; data access blocked")
    return h
def safe_history(state):
    # These files contain hash-only metadata, not the original reviewed note.
    folder=ROOT/"review"/state
    if folder.is_symlink() or not folder.is_dir():raise RuntimeError("Review category unavailable")
    result=[]
    for f in folder.iterdir():
        if not f.name.endswith(".json") or f.is_symlink() or not f.is_file():continue
        if f.stat().st_size>65536:continue
        try:
            x=json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(x,dict) or "note" in x:continue
            result.append({k:x.get(k) for k in FIELDS+("token","note_hash","note_bytes")})
        except (OSError,ValueError):continue
    return sorted(result,key=lambda a:a.get("created_at") or "",reverse=True)
def gather():
    h=canonical_health()
    listed=cmd(["review","list","--root",str(ROOT)])
    # The native CLI is authoritative for pending review state.
    pending=listed.get("data",{}).get("pending",[])
    if not isinstance(pending,list):raise RuntimeError("Unrecognized PCMF review.list response")
    return h,{"pending":pending,"authorized":safe_history("authorized"),
              "approved":safe_history("approved"),"rejected":safe_history("rejected")}
class Center(Gtk.Window):
    def __init__(self):
        super().__init__(title="Forge PCMF — Control Center")
        self.set_default_size(1120,740)
        if ICON.is_file():self.set_icon_from_file(str(ICON))
        self.connect("destroy",Gtk.main_quit)
        provider=Gtk.CssProvider();provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(),provider,Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        base=Gtk.Box(orientation=Gtk.Orientation.VERTICAL);self.add(base)
        top=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=5);top.set_name("top");base.pack_start(top,False,False,0)
        name=Gtk.Label(label="FORGE  /  PCMF CONTROL CENTER",xalign=0);name.set_name("headline");top.pack_start(name,False,False,0)
        subtitle=Gtk.Label(label="TechMagnet canonical Living Memory  ·  Review workflow  ·  Local-only",xalign=0)
        subtitle.set_name("subline");top.pack_start(subtitle,False,False,0)
        self.health=Gtk.Label(label="Checking canonical memory integrity…",xalign=0);self.health.set_name("health")
        base.pack_start(self.health,False,False,0)
        passbar=Gtk.Box(spacing=10);passbar.set_border_width(9);base.pack_start(passbar,False,False,0)
        self.make_button(passbar,"Set Up Passphrase",self.setup_passphrase)
        self.make_button(passbar,"Change Passphrase",self.change_passphrase)
        self.make_button(passbar,"Close Window",self.close_window)
        toolbar=Gtk.Box(spacing=8);toolbar.set_border_width(9);base.pack_start(toolbar,False,False,0)
        self.make_button(toolbar,"Refresh",self.refresh)
        self.make_button(toolbar,"Inspect selected",self.inspect)
        self.make_button(toolbar,"Defer / Later",self.defer_selected)
        self.make_button(toolbar,"Do not save (explain)",self.no_save_info)
        self.make_button(toolbar,"Pattern advisor",self.pattern_advice)
        self.make_button(toolbar,"Owner review selected",self.owner_review)
        self.make_button(toolbar,"Browse canonical memories",self.browse_memories)
        self.make_button(toolbar,"Open existing memory viewer",self.memory_viewer)

        self.book=Gtk.Notebook();base.pack_start(self.book,True,True,0)
        self.models={};self.rows={};self.views={}
        self.history={state:[] for state in STATES}
        for state,title in (("pending","Pending"),("authorized","Authorized — awaiting submission"),
                            ("approved","Approved / consumed"),("rejected","Rejected")):
            pane=Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
            store=Gtk.ListStore(str,str,str)
            tree=Gtk.TreeView(model=store)
            for col,titlecol in enumerate(("Subject","Class","Created (UTC)")):
                renderer=Gtk.CellRendererText()
                column=Gtk.TreeViewColumn(titlecol,renderer,text=col)
                column.set_resizable(True)
                column.set_min_width((195,120,155)[col])
                column.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
                column.set_fixed_width((205,130,165)[col])
                tree.append_column(column)
            left=Gtk.ScrolledWindow();left.add(tree);pane.pack1(left,resize=True,shrink=False)
            details=Gtk.TextView();details.set_editable(False);details.set_cursor_visible(False)
            details.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            right=Gtk.ScrolledWindow();right.add(details);pane.pack2(right,resize=True,shrink=False)
            pane.set_position(520)
            tree.get_selection().connect("changed",self.selection_changed,state)
            self.book.append_page(pane,Gtk.Label(label=title))
            self.models[state]=store;self.rows[state]=[];self.views[state]=(tree,details)
        self.password_state=Gtk.Label(label="Encrypted inbox passphrase: checking…",xalign=0)
        base.pack_start(self.password_state,False,False,0)
        self.foot=Gtk.Label(label="R2: missed approvals remain in Pending; classifier suggestions never auto-approve.",xalign=0)
        self.foot.set_name("bottom");base.pack_start(self.foot,False,False,0)
        GLib.idle_add(self.refresh)
    def close_window(self):
        self.destroy()

    def make_button(self,bar,label,callback):
        b=Gtk.Button(label=label);b.connect("clicked",lambda _b:callback());bar.pack_start(b,False,False,0)
    def current(self):
        state=STATES[self.book.get_current_page()]
        model,itr=self.views[state][0].get_selection().get_selected()
        if itr is None:return state,None
        index=model.get_path(itr).get_indices()[0]
        return state,self.rows[state][index] if index<len(self.rows[state]) else None
    def showmsg(self,text,level=Gtk.MessageType.INFO):
        d=Gtk.MessageDialog(self,0,level,Gtk.ButtonsType.OK,text);d.run();d.destroy()
    def refresh(self):
        try:
            h,states=gather()
            self._refresh_password_status()
            self.history=states
            self.health.set_text("● CANONICAL HEALTHY  ·  Chain PASS  ·  Index PASS  ·  Events %s  ·  HOT %s / WARM %s" %
                (h.get("events"),h.get("subjects_by_state",{}).get("HOT"),h.get("subjects_by_state",{}).get("WARM")))
            for state in STATES:
                self.rows[state]=states[state];self.models[state].clear()
                for x in states[state]:
                    self.models[state].append([str(x.get("subject") or ""),str(x.get("event_class") or ""),
                                               str(x.get("created_at") or "")[:19].replace("T"," ")])
                self.views[state][1].get_buffer().set_text("Select a row for details.\n\nRaw reviewed notes are not stored in this queue.")
            self.foot.set_text("Pending %d   ·   Authorized %d   ·   Consumed %d   ·   Rejected %d   |   Read-only display; owner approval remains gated." %
                tuple(len(states[s]) for s in STATES))
        except Exception as exc:
            self.health.set_text("● UNAVAILABLE — canonical integrity/connection check failed")
            for s in STATES:self.models[s].clear();self.rows[s]=[]
            self.foot.set_text(str(exc)[:350])
        return False
    def selection_changed(self,selection,state):
        model,itr=selection.get_selected()
        if itr is None:return
        index=model.get_path(itr).get_indices()[0]
        if index>=len(self.rows[state]):return
        row=self.rows[state][index]
        data=[f"State: {state.upper()}"]
        for key in FIELDS:
            if row.get(key) is not None:data.append(f"{key.replace('_',' ').title()}: {row[key]}")
        data+=["","The original sensitive note is not stored in the review queue.",
               "Authorized does not mean admitted. Consumed means the approval was used.",
               "No entry here grants inference execution or an exclusive model lease."]
        self.views[state][1].get_buffer().set_text("\n".join(data))
    def inspect(self):
        state,row=self.current()
        if not row:self.showmsg("Select a review entry first.");return
        if state!="pending":self.showmsg("Inspect is available for pending entries only. Select a pending entry.");return
        try:
            h=canonical_health()
            p=subprocess.run([str(REVIEWER),"inspect",row["token"],str(ROOT)],
                             capture_output=True,text=True,timeout=8)
            if p.returncode:raise RuntimeError((p.stdout+p.stderr)[:300])
            metadata=json.loads(p.stdout).get("review",{})
            self.showmsg("Verified pending review:\n\nSubject: %s\nReason: %s\nNote bytes: %s\n\nExact original text is required for owner authorization."%
                (metadata.get("subject"),metadata.get("reason"),metadata.get("note_bytes")))
        except Exception as exc:self.showmsg("Inspection blocked: "+str(exc)[:300],Gtk.MessageType.WARNING)
    def defer_selected(self):
        state,row=self.current()
        if state!="pending" or not row:
            self.showmsg("Select a pending item to defer.");return
        self.showmsg("Deferred for later. This entry remains in the canonical Pending queue.\n\n"
                     "No storage approval has been given, no data changed, and other independently "
                     "authorized project work may continue.\n\n"
                     "The original note is not stored: approval still requires recovering it "
                     "from the submitting client, or entering the exact original text.")
    def no_save_info(self):
        state,row=self.current()
        if state!="pending" or not row:
            self.showmsg("Select a pending entry first.");return
        spec=verify_reject_once_semantics("do_not_save_once")
        assert not spec["implemented_in_canonical"]
        self.showmsg("Do not save this single memory: NOT YET IMPLEMENTED in the canonical engine.\n\n"
                     "The current PCMF 'reject' command also writes a broad future denial rule. "
                     "Using it for a single memory could block unrelated future memories, "
                     "so R2 deliberately does NOT call it.\n\n"
                     "This entry remains pending. This storage decision does not revoke "
                     "separate project execution authority.",
                     Gtk.MessageType.WARNING)
    def pattern_advice(self):
        state,row=self.current()
        if not row:
            self.showmsg("Select any review entry first.");return
        result=review_advice(row,self.history)
        self.showmsg("Metadata-only classifier advisor (NOT an approval):\n\n"
                     "Similar category admitted: %s\n"
                     "Similar category rejected: %s\n"
                     "Authorized but awaiting submission: %s\n"
                     "Protected reason: %s\n\n%s\n\n"
                     "Recommendation only. It cannot change policy, admit a memory, "
                     "or declassify sensitive information." %
                     (result["same_metadata_approved"],result["same_metadata_rejected"],
                      result["same_metadata_authorized_not_admitted"],
                      result["protected_reason"],result["advisory"]))
    def _password_manager(self):
        return OwnerPassphrase(
            config_dir=Path.home()/".config/pcmf",
            inbox=ESCROW,root_id=ROOT_ID)

    def _refresh_password_status(self):
        try:
            configured=self._password_manager().configured()
            self.password_state.set_text("Encrypted inbox passphrase: "+
                ("CONFIGURED (change requires current passphrase)" if configured else
                "NOT CONFIGURED — use Set Up Passphrase"))
        except Exception:
            self.password_state.set_text("Encrypted inbox passphrase: unavailable")

    def _password_fields(self,title,labels):
        dialog=Gtk.Dialog(title=title,transient_for=self,flags=0)
        dialog.set_modal(True)
        dialog.add_button("Cancel",Gtk.ResponseType.CANCEL)
        dialog.add_button("Confirm",Gtk.ResponseType.OK)
        container=dialog.get_content_area()
        container.set_border_width(14)
        container.set_spacing(8)
        inputs=[]
        for label_text in labels:
            label=Gtk.Label(label=label_text,xalign=0)
            container.pack_start(label,False,False,0)
            input_=Gtk.Entry()
            input_.set_visibility(False)
            input_.set_input_purpose(Gtk.InputPurpose.PASSWORD)
            container.pack_start(input_,False,False,0)
            inputs.append(input_)
        label=Gtk.Label(label="Use a memorable passphrase of at least 6 characters. It is not saved. "+
                        "A six-character passphrase is substantially easier to guess; a longer one is strongly recommended. Keep it somewhere secure; lost passphrases cannot decrypt saved notes.",xalign=0)
        label.set_line_wrap(True)
        container.pack_start(label,False,False,0)
        dialog.show_all()
        outcome=dialog.run()
        values=tuple(field.get_text() for field in inputs) if outcome==Gtk.ResponseType.OK else None
        for field in inputs:field.set_text("")
        dialog.destroy()
        return values

    def setup_passphrase(self):
        manager=self._password_manager()
        if manager.configured():
            self.showmsg("A passphrase is already configured. Use Change Passphrase to update it.")
            return
        values=self._password_fields("Set Up Encrypted Inbox Passphrase",
                                     ("New passphrase","Confirm new passphrase"))
        if values is None:return
        try:
            manager.setup(*values)
            self._refresh_password_status()
            self.showmsg("Passphrase setup complete. You can now save selected review notes encrypted.")
        except (PassphraseError,EscrowError,ValueError,OSError) as exc:
            self.showmsg("Setup blocked: "+str(exc),Gtk.MessageType.WARNING)
        finally:
            values=None

    def change_passphrase(self):
        manager=self._password_manager()
        if not manager.configured():
            self.showmsg("No passphrase is set. Choose Set Up Passphrase first.")
            return
        values=self._password_fields("Change Encrypted Inbox Passphrase",
             ("Current passphrase","New passphrase","Confirm new passphrase"))
        if values is None:return
        try:
            result=manager.change(*values)
            self._refresh_password_status()
            message="Passphrase changed. "+str(result["entries"])+" encrypted entries migrated."
            if result.get("encrypted_backup"):
                message+="\n\nA private encrypted backup using the previous passphrase is retained for recovery."
            self.showmsg(message)
        except (PassphraseError,EscrowError,ValueError,OSError) as exc:
            self.showmsg("Passphrase change blocked: "+str(exc),Gtk.MessageType.WARNING)
        finally:
            values=None

    def _pending_bridge(self):
        return PendingReviewBridge(pcmf_binary=BIN,pcmf_root=ROOT,
            inbox_root=ESCROW,expected_root_id=ROOT_ID)

    def _owner_passphrase(self, purpose):
        box=Gtk.Dialog(title=purpose,transient_for=self,flags=0)
        box.add_button("Cancel",Gtk.ResponseType.CANCEL)
        box.add_button("Confirm",Gtk.ResponseType.OK)
        content=box.get_content_area()
        content.set_border_width(12)
        content.set_spacing(8)
        content.pack_start(Gtk.Label(label="Owner passphrase (at least 6 characters). It is not saved."),False,False,0)
        entry=Gtk.Entry()
        entry.set_visibility(False)
        entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        content.pack_start(entry,False,False,0)
        box.show_all()
        result=box.run()
        secret=entry.get_text() if result==Gtk.ResponseType.OK else None
        entry.set_text("")
        box.destroy()
        return secret

    def owner_review(self):
        state,row=self.current()
        if state!="pending" or not row:self.showmsg("Select a pending entry first.");return
        try:
            canonical_health()
            self._pending_bridge().pending_metadata(row["token"])
        except Exception:
            self.showmsg("Canonical review token validation failed.",Gtk.MessageType.ERROR)
            return
        dialog=Gtk.Dialog(title="Owner review — exact entry required",transient_for=self,flags=0)
        dialog.add_button("Cancel",Gtk.ResponseType.CANCEL)
        dialog.add_button("Save encrypted for later",110)
        dialog.add_button("Unlock encrypted",111)
        dialog.add_button("Review with OS authentication",Gtk.ResponseType.OK)
        box=dialog.get_content_area()
        box.set_spacing(8)
        box.set_border_width(12)
        label=Gtk.Label(label=("Subject: %s\n"
            "The exact note is required. Before encrypted storage, you must explicitly opt in.\n"
            "Only the native reviewer can authorize the entry; authorization does not itself admit it.\n"
            "No note is captured automatically from existing hash-only reviews.")%row.get("subject"))
        label.set_xalign(0)
        box.pack_start(label,False,False,0)
        area=Gtk.TextView()
        area.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        sw=Gtk.ScrolledWindow()
        sw.set_size_request(680,180)
        sw.add(area)
        box.pack_start(sw,True,True,0)
        consent=Gtk.CheckButton(label="I explicitly authorize encrypted local storage of this one exact note.")
        box.pack_start(consent,False,False,0)
        dialog.show_all()
        outcome=None
        while True:
            result=dialog.run()
            if result in (Gtk.ResponseType.CANCEL,Gtk.ResponseType.DELETE_EVENT):
                break
            buff=area.get_buffer()
            note=buff.get_text(buff.get_start_iter(),buff.get_end_iter(),False)
            if result==110:
                if not consent.get_active():
                    self.showmsg("Check explicit encrypted-storage consent first.",Gtk.MessageType.WARNING)
                    continue
                password=self._owner_passphrase("Encrypt for deferred review")
                if password is None:continue
                try:
                    self._password_manager().verify(password)
                    self._pending_bridge().capture_if_owner_consents(
                        token=row["token"],original_note=note,
                        owner_passphrase=password,owner_opted_in=True)
                    buff.set_text("")
                    consent.set_active(False)
                    self.showmsg("Encrypted note saved for later. PCMF review remains pending. Nothing approved.")
                except (BridgeError,EscrowError,PassphraseError,ValueError,OSError):
                    self.showmsg("Capture blocked. Set up your passphrase first, then verify the exact note and review state.",
                                 Gtk.MessageType.WARNING)
                finally:
                    password=None
                continue
            if result==111:
                password=self._owner_passphrase("Unlock deferred review")
                if password is None:continue
                try:
                    self._password_manager().verify(password)
                    restored=self._pending_bridge().unlock_if_still_pending(
                        token=row["token"],owner_passphrase=password)
                    buff.set_text(restored)
                    self.showmsg("Exact note restored for owner inspection. Still PENDING until native reviewer confirms.")
                except (BridgeError,EscrowError,PassphraseError,ValueError,OSError):
                    self.showmsg("Unlock refused: wrong passphrase, stale review, or encrypted record unavailable.",
                                 Gtk.MessageType.WARNING)
                finally:
                    password=None
                continue
            if result==Gtk.ResponseType.OK:
                try:
                    metadata=self._pending_bridge().pending_metadata(row["token"])
                    data=note.encode("utf-8")
                    if (len(data)!=metadata["note_bytes"] or
                        hashlib.sha256(data).hexdigest()!=metadata["note_hash"]):
                        self.showmsg("Exact note does not match pending entry. No authorization.",
                                     Gtk.MessageType.WARNING)
                        continue
                    outcome=data
                    break
                except (BridgeError,EscrowError):
                    self.showmsg("Pending entry changed; no authorization.",Gtk.MessageType.WARNING)
                    break
        area.get_buffer().set_text("")
        dialog.destroy()
        if outcome is None:return
        self.foot.set_text("Native owner reviewer requested; OS authentication required.")
        def invoke(note):
            try:
                p=subprocess.Popen([str(REVIEWER),"prompt-exact",row["token"],str(ROOT)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                out,err=p.communicate(input=note,timeout=240)
                msg=(out+err).decode("utf-8","replace")[:450]
                GLib.idle_add(self.review_finished,p.returncode,msg)
            except Exception as exc:
                GLib.idle_add(self.review_finished,1,type(exc).__name__)
        threading.Thread(target=invoke,args=(outcome,),daemon=True).start()

    def review_finished(self,code,message):
        self.refresh()
        self.showmsg(("Owner-review utility returned:\n"+message+
              "\n\nFor an authorized review, the original submitting client still must resubmit the exact entry.")
              if code==0 else "Review not completed:\n"+message,
              Gtk.MessageType.INFO if code==0 else Gtk.MessageType.WARNING)
        return False
    def browse_memories(self):
        try:
            canonical_health()
            items=cmd(["hot","--root",str(ROOT),"--profile","morphius",
                       "--project","general","--include-warm","--limit","50"]).get("data",{}).get("items",[])
            dialog=Gtk.Dialog(title="Canonical PCMF — HOT / WARM Memories",transient_for=self,flags=0)
            dialog.add_button("Close",Gtk.ResponseType.CLOSE)
            area=dialog.get_content_area();area.set_border_width(12)
            info=Gtk.Label(label="Verified TechMagnet canonical memory. General project, latest 50 HOT/WARM subjects.",xalign=0)
            area.pack_start(info,False,False,5)
            display=Gtk.TextView();display.set_editable(False);display.set_cursor_visible(False)
            display.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            text="\n\n".join("%s  |  %s  |  %s\n%s" %
                (x.get("memory_state","?"),x.get("subject","?"),x.get("recorded_at","?"),
                 x.get("summary","")) for x in items)
            display.get_buffer().set_text(text or "No HOT/WARM records returned.")
            box=Gtk.ScrolledWindow();box.set_size_request(860,520);box.add(display)
            area.pack_start(box,True,True,0)
            dialog.show_all();dialog.run();dialog.destroy()
        except Exception as exc:self.showmsg("Canonical memory browse failed: "+str(exc)[:350],Gtk.MessageType.WARNING)
    def memory_viewer(self):
        viewer=Path.home()/".local/bin/forge-memory"
        if viewer.is_file():subprocess.Popen([str(viewer)],close_fds=True)
        else:self.showmsg("Existing memory viewer is unavailable.")
def self_test():
    h,states=gather()
    assert h["root_id"]==ROOT_ID
    assert set(STATES)==set(states)
    assert isinstance(states["pending"],list)
    print(json.dumps({"status":"PASS","root_id":h["root_id"],"chain":h["chain_ok"],
        "index":h["index_ok"],"review_counts":{s:len(states[s]) for s in STATES}}))
if __name__=="__main__":
    if sys.argv[1:]==["--self-test"]:self_test()
    elif len(sys.argv)==1:
        app=Center();app.show_all();Gtk.main()
    else:raise SystemExit("Usage: forge-pcmf-control-center [--self-test]")
