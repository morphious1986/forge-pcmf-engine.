#!/usr/bin/python3
"""Forge PCMF Control Center R8. Pending-first owner review dashboard."""
import os, sys, json, hashlib, subprocess, threading, stat, re
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
STATES=("pending","needs_original","authorized","approved","rejected")
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
    ready,needs_original=classify_reviewability(pending)
    return h,{"pending":ready,"needs_original":needs_original,
              "authorized":safe_history("authorized"),
              "approved":safe_history("approved"),"rejected":safe_history("rejected")}
def classify_reviewability(pending, inbox=ESCROW, root_id=ROOT_ID):
    """Partition canonical pending requests without changing the native ledger.

    An encrypted record is a *candidate*, not proof of decryptability. All
    authentication and hash checks still occur during owner unlock/review.
    """
    available=[]
    not_available=[]
    inbox=Path(inbox)
    private=False
    try:
        st=inbox.lstat()
        private=stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and (st.st_mode & 0o077)==0
    except FileNotFoundError:
        pass
    for request in pending:
        token=request.get("token")
        has_escrow=False
        if private and isinstance(token,str) and re.fullmatch(r"[0-9a-f]{64}",token):
            path=inbox/(token+".json")
            try:
                st=path.lstat()
                if stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) and (st.st_mode & 0o077)==0 and 0<st.st_size<=131072:
                    record=json.loads(path.read_text(encoding="ascii"))
                    has_escrow=(isinstance(record,dict) and
                        record.get("version")=="PCMF_DEFERRED_OWNER_ESCROW_V1" and
                        record.get("root_id")==root_id and record.get("token")==token and
                        all(isinstance(record.get(k),str) for k in ("salt","nonce","ciphertext")))
            except (OSError,ValueError,UnicodeError):
                pass
        if has_escrow:available.append(request)
        else:not_available.append(request)
    return available,not_available

class Center(Gtk.Window):
    def __init__(self):
        super().__init__(title="Forge PCMF — Control Center")
        self.set_default_size(1200,800)
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
        # Pending-review actions are intentionally above maintenance controls.
        reviewbar=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        reviewbar.set_border_width(14)
        reviewbar.set_name("pending_actions")
        base.pack_start(reviewbar,False,False,0)
        self.pending_count=Gtk.Label(label="READY FOR APPROVAL: checking…",xalign=0)
        self.pending_count.set_name("pending_count")
        reviewbar.pack_start(self.pending_count,False,False,0)
        self.pending_help=Gtk.Label(label="Only requests with a retained encrypted-note candidate appear here. Other requests require the original client to resubmit.",xalign=0)
        reviewbar.pack_start(self.pending_help,False,False,0)
        review_actions=Gtk.Box(spacing=12)
        reviewbar.pack_start(review_actions,False,False,0)
        self.review_now_button=self.make_button(review_actions,"REVIEW NOW — OPEN APPROVAL PROMPT",self.review_now)
        self.review_now_button.set_name("review_now")
        self.make_button(review_actions,"SHOW READY REVIEWS",self.show_pending)
        self.make_button(review_actions,"SHOW NEEDS RESUBMISSION",self.show_missing_original)
        self.make_button(review_actions,"REFRESH APPROVALS",self.refresh)
        passbar=Gtk.Box(spacing=10);passbar.set_border_width(9);base.pack_start(passbar,False,False,0)
        self.make_button(passbar,"Set Up Passphrase",self.setup_passphrase)
        self.make_button(passbar,"Change Passphrase",self.change_passphrase)
        self.make_button(passbar,"Close Window",self.close_window)
        toolbar=Gtk.Box(spacing=8);toolbar.set_border_width(9);base.pack_start(toolbar,False,False,0)
        self.make_button(toolbar,"Inspect selected",self.inspect)
        self.make_button(toolbar,"Defer / Later",self.defer_selected)
        self.make_button(toolbar,"Do not save (explain)",self.no_save_info)
        self.make_button(toolbar,"Pattern advisor",self.pattern_advice)
        self.make_button(toolbar,"Browse canonical memories",self.browse_memories)
        self.make_button(toolbar,"Open existing memory viewer",self.memory_viewer)

        self.book=Gtk.Notebook();base.pack_start(self.book,True,True,0)

        self.models={};self.rows={};self.views={}
        self.history={state:[] for state in STATES}
        for state,title in (("pending","READY FOR REVIEW"),("needs_original","NEEDS RESUBMISSION"),("authorized","Authorized — awaiting submission"),
                            ("approved","Approved / consumed"),("rejected","Rejected")):
            pane=Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
            store=Gtk.ListStore(str,str,str)
            tree=Gtk.TreeView(model=store)
            for col,titlecol in enumerate(("Memory / subject","Class","Created (UTC)")):
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
            if state=="pending":tree.connect("row-activated",self.pending_double_click)
            self.book.append_page(pane,Gtk.Label(label=title))
            self.models[state]=store;self.rows[state]=[];self.views[state]=(tree,details)
        self.password_state=Gtk.Label(label="Encrypted inbox passphrase: checking…",xalign=0)
        base.pack_start(self.password_state,False,False,0)
        self.foot=Gtk.Label(label="R2: missed approvals remain in Pending; classifier suggestions never auto-approve.",xalign=0)
        self.foot.set_name("bottom");base.pack_start(self.foot,False,False,0)
        self.book.set_current_page(0)
        self.book.connect("switch-page",self.page_switched)
        self.review_now_button.set_sensitive(False)
        GLib.idle_add(self.refresh)
    def close_window(self):
        self.destroy()

    def page_switched(self,*_args):
        if hasattr(self,"review_now_button") and hasattr(self,"views") and self.views.get("pending"):
            state,row=self.current()
            self.review_now_button.set_sensitive(state=="pending" and row is not None and not getattr(self,"_review_busy",False))

    def show_pending(self):
        self.book.set_current_page(0)
        if self.rows.get("pending") and self.current()[1] is None:
            self.views["pending"][0].get_selection().select_path(0)
        self.views["pending"][0].grab_focus()

    def show_missing_original(self):
        self.book.set_current_page(1)
        if self.rows.get("needs_original") and self.current()[1] is None:
            self.views["needs_original"][0].get_selection().select_path(0)
        self.views["needs_original"][0].grab_focus()
        self.foot.set_text("These requests lack a retained encrypted original. Recover/re-propose through the submitting client; no memory was rejected.")

    def pending_double_click(self,*_args):
        self.review_now()

    def review_now(self):
        state,row=self.current()
        if state!="pending":
            self.foot.set_text("Not an actionable item. Select READY FOR REVIEW. Legacy requests need original text from the submitting client.")
            return
        if row is None:
            self.foot.set_text("Only READY FOR REVIEW entries can be authorized; NEEDS RESUBMISSION entries lack a retained original note.")
            return
        if getattr(self,"_review_busy",False):return
        token=row["token"]
        self._review_busy=True
        self.review_now_button.set_sensitive(False)
        self.foot.set_text("Verifying selected review in background…")
        def verify():
            try:
                canonical_health()
                self._pending_bridge().pending_metadata(token)
                GLib.idle_add(self._review_verified,token,None)
            except Exception as exc:
                GLib.idle_add(self._review_verified,token,type(exc).__name__)
        threading.Thread(target=verify,daemon=True,name="pcmf-review-verify").start()

    def _review_verified(self,token,error):
        self._review_busy=False
        if not self.get_visible():return False
        state,row=self.current()
        if error:
            self.foot.set_text("Cannot verify selected review: "+error+". No memory changed.")
        elif state!="pending" or not row or row.get("token")!=token:
            self.foot.set_text("Selection changed during verification. Select the memory and retry.")
        else:
            self.owner_review(verified=True)
        state,row=self.current()
        self.review_now_button.set_sensitive(state=="pending" and row is not None)
        return False

    def make_button(self,bar,label,callback):
        b=Gtk.Button(label=label);b.connect("clicked",lambda _b:callback());bar.pack_start(b,False,False,0)
        return b
    def current(self):
        state=STATES[self.book.get_current_page()]
        model,itr=self.views[state][0].get_selection().get_selected()
        if itr is None:return state,None
        index=model.get_path(itr).get_indices()[0]
        return state,self.rows[state][index] if index<len(self.rows[state]) else None
    def showmsg(self,text,level=Gtk.MessageType.INFO):
        d=Gtk.MessageDialog(self,0,level,Gtk.ButtonsType.OK,text);d.run();d.destroy()
    def refresh(self):
        # Never run slow native PCMF checks in GTK's UI thread.
        if getattr(self,"_refresh_busy",False):return False
        self._refresh_busy=True
        self.foot.set_text("Checking approvals in background…")
        def work():
            try:
                h,states=gather()
                GLib.idle_add(self._refresh_done,h,states,None)
            except Exception as exc:
                GLib.idle_add(self._refresh_done,None,None,type(exc).__name__)
        threading.Thread(target=work,daemon=True,name="pcmf-readonly-refresh").start()
        return False

    def _refresh_done(self,h,states,error):
        self._refresh_busy=False
        if not self.get_visible():return False
        if error:
            self.health.set_text("● PCMF CONNECTION UNAVAILABLE")
            self.foot.set_text("Approval refresh failed: "+error+". Click REFRESH APPROVALS.")
            self.review_now_button.set_sensitive(False)
            return False
        self._refresh_password_status()
        self.history=states
        self.health.set_text("● CANONICAL HEALTHY · Chain PASS · Index PASS · Events %s" % h.get("events"))
        n=len(states["pending"])
        self.pending_count.set_text("READY FOR APPROVAL: %d  |  NEED ORIGINAL TEXT: %d"%(n,len(states["needs_original"])))
        self.pending_help.set_text("Select a ready review and click REVIEW NOW. Unlock its exact saved note before authorizing." if n else
            "No actionable approvals. Open NEEDS RESUBMISSION to see requests awaiting original notes.")
        previous_token=None
        if self.book.get_current_page()==0 and self.rows.get("pending"):
            previous=self.current()[1]
            if previous:previous_token=previous.get("token")
        for state in STATES:
            self.rows[state]=states[state]
            self.models[state].clear()
            for row in states[state]:
                self.models[state].append([str(row.get("subject") or ""),
                  str(row.get("event_class") or ""),
                  str(row.get("created_at") or "")[:19].replace("T"," ")])
            self.views[state][1].get_buffer().set_text(
                "Select an entry to inspect its metadata.\nRaw text of older pending notes was not retained.")
        if n:
            self.book.set_current_page(0)
            selected=next((i for i,row in enumerate(states["pending"]) if row.get("token")==previous_token),0)
            self.views["pending"][0].get_selection().select_path(selected)
        self.review_now_button.set_sensitive(n>0 and not getattr(self,"_review_busy",False))
        self.foot.set_text("Ready %d · Needs original %d · Authorized %d · Consumed %d · Rejected %d. Canonical records preserved."%
            tuple(len(states[k]) for k in STATES))
        return False

    def selection_changed(self,selection,state):
        model,itr=selection.get_selected()
        if itr is None:return
        index=model.get_path(itr).get_indices()[0]
        if index>=len(self.rows[state]):return
        row=self.rows[state][index]
        if state=="pending":self.review_now_button.set_sensitive(True)
        data=["READY FOR OWNER REVIEW" if state=="pending" else
              ("ORIGINAL TEXT NOT AVAILABLE IN CONTROL CENTER" if state=="needs_original" else "MEMORY REVIEW HISTORY"),
              f"State: {state.upper()}",
              "Subject: "+str(row.get("subject") or "Unknown"),
              "Project: "+str(row.get("project") or "Not specified"),
              "Reason owner review is needed: "+str(row.get("reason") or "Not specified"),
              ""]
        for key in FIELDS:
            if row.get(key) is not None:data.append(f"{key.replace('_',' ').title()}: {row[key]}")
        data+=["","ACTION: Click REVIEW NOW — OPEN APPROVAL PROMPT (or double-click this row)." if state=="pending" else
               ("This item is NOT ready for approval. Ask its submitting client to recover/re-propose the original text. It remains in canonical PCMF audit records." if state=="needs_original" else ""),
               "A retained encrypted note must still be decrypted and hash-checked before authorization.",
               "The native owner reviewer requires OS authentication. Authorization alone does not admit memory.",
               "No entry here grants inference execution or an exclusive model lease."]
        self.views[state][1].get_buffer().set_text("\n".join(data))
    def inspect(self):
        state,row=self.current()
        if state!="pending" or not row:
            self.foot.set_text("Select a pending memory before inspecting.")
            return
        token=row["token"]
        self.foot.set_text("Inspecting selected pending review in background…")
        def work():
            try:
                canonical_health()
                result=subprocess.run([str(REVIEWER),"inspect",token,str(ROOT)],
                    capture_output=True,text=True,timeout=8)
                if result.returncode:raise RuntimeError("Owner review inspect refused")
                metadata=json.loads(result.stdout).get("review",{})
                message=("Verified pending review:\n\nSubject: %s\nReason: %s\nNote bytes: %s\n\nOriginal text is not present in historic hash-only pending records."%
                         (metadata.get("subject"),metadata.get("reason"),metadata.get("note_bytes")))
                GLib.idle_add(self._inspect_done,token,message,False)
            except Exception as exc:
                GLib.idle_add(self._inspect_done,token,type(exc).__name__,True)
        threading.Thread(target=work,daemon=True,name="pcmf-review-inspect").start()

    def _inspect_done(self,token,message,failed):
        if not self.get_visible():return False
        state,row=self.current()
        if state!="pending" or not row or row.get("token")!=token:
            self.foot.set_text("Inspection finished; selected review changed.")
        elif failed:
            self.foot.set_text("Inspect unavailable: "+message)
        else:
            self.views["pending"][1].get_buffer().set_text(message)
            self.foot.set_text("Review inspected. Original note required before authorization.")
        return False

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
            self.foot.set_text("No passphrase configured. Use Set Up Passphrase first.")
            return
        if getattr(self,"_rotation_busy",False):
            self.foot.set_text("Passphrase change is already running.")
            return
        values=self._password_fields("Change Encrypted Inbox Passphrase",
            ("Current passphrase","New passphrase","Confirm new passphrase"))
        if values is None:return
        self._rotation_busy=True
        self.foot.set_text("Re-encrypting owner notes in background. Do not close the app until complete.")
        def work():
            try:
                result=manager.change(*values)
                GLib.idle_add(self._rotation_finished,result,None)
            except Exception as exc:
                GLib.idle_add(self._rotation_finished,None,type(exc).__name__)
        threading.Thread(target=work,daemon=True,name="pcmf-passphrase-rotation").start()

    def _rotation_finished(self,result,error):
        self._rotation_busy=False
        if not self.get_visible():return False
        self._refresh_password_status()
        if error:
            self.foot.set_text("Passphrase change failed or was blocked ("+error+"). Existing notes preserved.")
        else:
            self.foot.set_text("Passphrase changed. %s encrypted note(s) migrated; old encrypted recovery backup retained when applicable."%result["entries"])
        return False

    def _pending_bridge(self):
        return PendingReviewBridge(pcmf_binary=BIN,pcmf_root=ROOT,
            inbox_root=ESCROW,expected_root_id=ROOT_ID)

    def _owner_passphrase(self,purpose,parent=None):
        box=Gtk.Dialog(title=purpose,transient_for=parent or self,flags=0)
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

    def _escrow_operation(self,operation,token,note,password,dialog,feedback,area,consent):
        if getattr(self,"_escrow_busy",False):
            feedback.set_text("An encrypted-review operation is already running.")
            return
        self._escrow_busy=True
        feedback.set_text("Working in background. The Control Center remains responsive.")
        def work():
            try:
                self._password_manager().verify(password)
                if operation=="save":
                    self._pending_bridge().capture_if_owner_consents(
                        token=token,original_note=note,owner_passphrase=password,owner_opted_in=True)
                    restored=None
                else:
                    restored=self._pending_bridge().unlock_if_still_pending(
                        token=token,owner_passphrase=password)
                GLib.idle_add(self._escrow_operation_done,dialog,feedback,area,consent,operation,restored,None)
            except Exception as exc:
                GLib.idle_add(self._escrow_operation_done,dialog,feedback,area,consent,operation,None,type(exc).__name__)
        threading.Thread(target=work,daemon=True,name="pcmf-owner-escrow").start()

    def _escrow_operation_done(self,dialog,feedback,area,consent,operation,restored,error):
        self._escrow_busy=False
        if not dialog.get_visible():return False
        if error:
            feedback.set_text("Operation not completed ("+error+"). No memory approved.")
        elif operation=="save":
            area.get_buffer().set_text("")
            consent.set_active(False)
            feedback.set_text("Saved encrypted for later. Still pending. Nothing approved.")
        else:
            area.get_buffer().set_text(restored)
            feedback.set_text("Exact note unlocked. Still pending until OS authentication.")
        return False

    def owner_review(self,verified=False):
        state,row=self.current()
        if state!="pending" or row is None:return
        if not verified:
            self.foot.set_text("Click REVIEW NOW to validate the review without freezing the window.")
            return
        dialog=Gtk.Dialog(title="MEMORY NEEDS APPROVAL — Owner review",transient_for=self,flags=0)
        dialog.add_button("Cancel",Gtk.ResponseType.CANCEL)
        dialog.add_button("Save encrypted for later",110)
        dialog.add_button("Unlock encrypted",111)
        dialog.add_button("AUTHORIZE EXACT NOTE — OS AUTH",Gtk.ResponseType.OK)
        box=dialog.get_content_area()
        box.set_spacing(8)
        box.set_border_width(12)
        label=Gtk.Label(label=("Subject: %s\n"
            "The exact note is required. Before encrypted storage, you must explicitly opt in.\n"
            "Only the native reviewer can authorize the entry; authorization does not itself admit it.\n"
            "No note is captured automatically from existing hash-only reviews.")%row.get("subject"))
        label.set_xalign(0)
        label.set_line_wrap(True)
        box.pack_start(label,False,False,0)
        feedback=Gtk.Label(label="Old pending records contain hashes, not their original text. If that text was never saved, ask the submitting client to resend it.",xalign=0)
        feedback.set_line_wrap(True)
        box.pack_start(feedback,False,False,0)
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
                    feedback.set_text("Please check consent before encrypted storage.")
                    continue
                password=self._owner_passphrase("Encrypt for deferred review",dialog)
                if password is None:continue
                self._escrow_operation("save",row["token"],note,password,dialog,feedback,area,consent)
                password=None
                continue
            if result==111:
                password=self._owner_passphrase("Unlock deferred review",dialog)
                if password is None:continue
                self._escrow_operation("unlock",row["token"],None,password,dialog,feedback,area,consent)
                password=None
                continue
            if result==Gtk.ResponseType.OK:
                if getattr(self,"_escrow_busy",False):
                    feedback.set_text("Encrypted-note operation is still running. Complete it before authorization.")
                    continue
                try:
                    data=note.encode("utf-8")
                    if (len(data)!=row["note_bytes"] or
                        hashlib.sha256(data).hexdigest()!=row["note_hash"]):
                        feedback.set_text("CANNOT AUTHORIZE: the exact original text is missing or does not match this pending request. Re-submit it through the originating client.")
                        continue
                    outcome=data
                    break
                except (BridgeError,EscrowError):
                    feedback.set_text("Pending request changed; close and refresh. No authorization.")
                    break
        area.get_buffer().set_text("")
        dialog.destroy()
        if outcome is None:return
        self.foot.set_text("Native owner reviewer requested; OS authentication required.")
        def invoke(note):
            try:
                # Revalidate canonical pending metadata on worker thread immediately
                # before invoking OS-authenticated reviewer. Fail closed on changes.
                canonical_health()
                meta=self._pending_bridge().pending_metadata(row["token"])
                if len(note)!=meta["note_bytes"] or hashlib.sha256(note).hexdigest()!=meta["note_hash"]:
                    GLib.idle_add(self.review_finished,1,"Pending review changed or original note mismatch.")
                    return
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
        self.foot.set_text("Loading canonical memory list in background…")
        def work():
            try:
                canonical_health()
                items=cmd(["hot","--root",str(ROOT),"--profile","morphius",
                    "--project","general","--include-warm","--limit","50"]).get("data",{}).get("items",[])
                message="\n\n".join("%s | %s | %s\n%s" %
                    (item.get("memory_state","?"),item.get("subject","?"),
                     item.get("recorded_at","?"),item.get("summary","")) for item in items)
                GLib.idle_add(self._memories_loaded,message or "No HOT/WARM records returned.",None)
            except Exception as exc:
                GLib.idle_add(self._memories_loaded,None,type(exc).__name__)
        threading.Thread(target=work,daemon=True,name="pcmf-memory-browser").start()

    def _memories_loaded(self,content,error):
        if not self.get_visible():return False
        if error:
            self.foot.set_text("Memory browse unavailable: "+error)
            return False
        dialog=Gtk.Dialog(title="Canonical PCMF — HOT / WARM Memories",transient_for=self,flags=0)
        dialog.add_button("Close",Gtk.ResponseType.CLOSE)
        area=dialog.get_content_area();area.set_border_width(12)
        display=Gtk.TextView();display.set_editable(False);display.set_cursor_visible(False)
        display.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        display.get_buffer().set_text(content)
        box=Gtk.ScrolledWindow();box.set_size_request(860,520);box.add(display)
        area.pack_start(box,True,True,0)
        dialog.show_all()
        dialog.run();dialog.destroy()
        return False

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
