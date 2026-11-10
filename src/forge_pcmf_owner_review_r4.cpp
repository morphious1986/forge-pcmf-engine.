#include "pcmf_json.h"
#include "pcmf_sha256.h"
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <poll.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using pcmf::J;
using pcmf::parse;
using pcmf::dump;

#ifndef PCMF_OWNER_CLI_SHA256
#define PCMF_OWNER_CLI_SHA256 "UNSET"
#endif

namespace {
std::string ROOT;
std::string PCMF;
const char *PCMF_SHA256=PCMF_OWNER_CLI_SHA256;

struct Stub {
    J j;
    std::string token,note_hash,subject,domain,event_class,reason,client,profile,project,created_at;
    long long note_bytes=0;
    std::string canonical_hash;
};

[[noreturn]] void blocked(const std::string& why){
    std::cerr<<"{\"status\":\"BLOCKED\",\"reason\":\""<<why<<"\"}\n";
    std::exit(2);
}
std::string executable_dir(){
    std::array<char,4096> path{};
    const ssize_t n=readlink("/proc/self/exe",path.data(),path.size()-1);
    if(n<=0||(size_t)n>=path.size()-1)blocked("SELF_PATH_UNAVAILABLE");
    path[(size_t)n]='\0';
    std::string full(path.data());
    const auto slash=full.rfind('/');
    if(slash==std::string::npos||slash==0)blocked("SELF_PATH_INVALID");
    return full.substr(0,slash);
}
void configure_runtime(const std::string&root){
    if(root.empty()||root[0]!='/'||root.find("/../")!=std::string::npos)blocked("ROOT_ARGUMENT_INVALID");
    ROOT=root;
    PCMF=executable_dir()+"/pcmf";
}
std::string approval_sound_path(){
    return executable_dir()+"/../assets/pcmf-approval-retro-chime-v2.wav";
}
bool hexn(const std::string&s,size_t n){
    if(s.size()!=n)return false;
    for(unsigned char c:s)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    return true;
}
std::string read_all(int fd,size_t cap){
    std::string out;std::array<char,4096>b{};
    for(;;){
        ssize_t n=read(fd,b.data(),b.size());
        if(n<0&&errno==EINTR)continue;
        if(n<0)blocked("READ_FAILED");
        if(!n)break;
        out.append(b.data(),(size_t)n);
        if(out.size()>cap)blocked("READ_TOO_LARGE");
    }
    return out;
}
void secure_zero(void *p,size_t n){
    volatile unsigned char *v=(volatile unsigned char*)p;
    while(n--)*v++=0;
}
std::string sha256_string(const std::string&s){
    uint8_t h[32];char out[65];
    pcmf_sha256(s.data(),s.size(),h);
    pcmf_to_hex(h,32,out);
    secure_zero(h,sizeof h);
    return std::string(out,64);
}
std::string sha256_file(const std::string&path){
    int fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)blocked("PCMF_BINARY_OPEN_FAILED");
    struct stat st{};
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||
       (st.st_mode&022)!=0||st.st_size<=0||st.st_size>4*1024*1024){
        close(fd);blocked("PCMF_BINARY_UNSAFE");
    }
    std::string bytes=read_all(fd,4*1024*1024);
    close(fd);
    uint8_t h[32];char out[65];
    pcmf_sha256(bytes.data(),bytes.size(),h);
    pcmf_to_hex(h,32,out);
    secure_zero(h,sizeof h);
    secure_zero(bytes.data(),bytes.size());
    bytes.clear();
    return std::string(out,64);
}
void require_pinned_pcmf(){if(sha256_file(PCMF)!=PCMF_SHA256)blocked("PCMF_BINARY_HASH_MISMATCH");}
void require_secure_root(){
    char real[4096]={};struct stat st{};
    if(!realpath(ROOT.c_str(),real)||std::string(real)!=ROOT)blocked("ROOT_REALPATH_MISMATCH");
    if(lstat(ROOT.c_str(),&st)!=0||!S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)||
       st.st_uid!=geteuid()||(st.st_mode&077)!=0)blocked("ROOT_NOT_PRIVATE");
}
std::string reqstr(const J&j,const char*k,size_t cap){
    if(!j.has(k)||j.at(k).t!=J::Str||j.at(k).s.empty()||j.at(k).s.size()>cap)
        blocked(std::string("STUB_")+k+"_INVALID");
    return j.at(k).s;
}
Stub load_stub(const std::string&token){
    if(!hexn(token,64))blocked("TOKEN_FORMAT");
    require_secure_root();
    std::string dirp=ROOT+"/review/pending";
    int d=open(dirp.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(d<0)blocked("REVIEW_DIR_OPEN_FAILED");
    struct stat ds{};
    if(fstat(d,&ds)!=0||!S_ISDIR(ds.st_mode)||ds.st_uid!=geteuid()||(ds.st_mode&022)!=0){
        close(d);blocked("REVIEW_DIR_UNSAFE");
    }
    std::string name=token+".json";
    int fd=openat(d,name.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0){int e=errno;close(d);blocked(e==ENOENT?"PENDING_REVIEW_NOT_FOUND":"STUB_OPEN_FAILED");}
    struct stat st{};
    if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_uid!=geteuid()||
       (st.st_mode&077)!=0||st.st_size<=0||st.st_size>65536){
        close(fd);close(d);blocked("STUB_UNSAFE");
    }
    std::string raw=read_all(fd,65536);close(fd);close(d);
    Stub s;try{s.j=parse(raw);}catch(...){blocked("STUB_JSON_INVALID");}
    if(s.j.t!=J::Obj||s.j.has("note"))blocked("RAW_SENSITIVE_CONTENT_IN_STUB");
    s.token=reqstr(s.j,"token",64);s.note_hash=reqstr(s.j,"note_hash",64);
    s.subject=reqstr(s.j,"subject",95);s.domain=reqstr(s.j,"domain",64);
    s.event_class=reqstr(s.j,"event_class",64);s.reason=reqstr(s.j,"reason",128);
    s.client=reqstr(s.j,"client",95);s.profile=reqstr(s.j,"profile",95);
    s.project=reqstr(s.j,"project",95);s.created_at=reqstr(s.j,"created_at",64);
    if(s.token!=token||!hexn(s.note_hash,64))blocked("STUB_BINDING_INVALID");
    if(!s.j.has("note_bytes")||s.j.at("note_bytes").t!=J::Num)blocked("STUB_NOTE_BYTES_INVALID");
    s.note_bytes=s.j.at("note_bytes").as_int();
    if(s.note_bytes<1||s.note_bytes>4096)blocked("STUB_NOTE_BYTES_RANGE");
    s.canonical_hash=sha256_string(dump(s.j));
    return s;
}
void wipe(std::string&s){if(!s.empty())secure_zero(s.data(),s.size());s.clear();}

struct ChildResult{int code=-1;std::string out;};
ChildResult run_child_capture(const std::vector<std::string>&args,size_t cap){
    int pfd[2];if(pipe2(pfd,O_CLOEXEC)!=0)blocked("PIPE_FAILED");
    pid_t pid=fork();if(pid<0)blocked("FORK_FAILED");
    if(pid==0){
        if(dup2(pfd[1],STDOUT_FILENO)<0)_exit(125);
        close(pfd[0]);close(pfd[1]);
        std::vector<char*> av;av.reserve(args.size()+1);
        for(const auto&x:args)av.push_back(const_cast<char*>(x.c_str()));
        av.push_back(nullptr);execv(av[0],av.data());_exit(127);
    }
    close(pfd[1]);std::string out=read_all(pfd[0],cap);close(pfd[0]);
    int st=0;while(waitpid(pid,&st,0)<0&&errno==EINTR){}
    ChildResult r;r.out=std::move(out);r.code=WIFEXITED(st)?WEXITSTATUS(st):128;return r;
}
void require_os_owner_auth(){
    ChildResult r=run_child_capture({
        "/usr/bin/pkexec","/usr/bin/true"
    },1024);
    if(r.code!=0)blocked("OWNER_OS_AUTH_DENIED_OR_CANCELLED");
}
std::string random_challenge(){
    static constexpr char alphabet[]="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    static constexpr size_t nalpha=sizeof(alphabet)-1;
    std::string out;
    out.reserve(8);
    while(out.size()<8){
        unsigned char b=0;
        ssize_t n;
        do{ n=getrandom(&b,1,0); }while(n<0 && errno==EINTR);
        if(n!=1)blocked("CHALLENGE_RANDOM_FAILED");
        const unsigned int limit=256u-(256u%nalpha);
        if((unsigned int)b>=limit)continue;
        out.push_back(alphabet[(unsigned int)b % nalpha]);
    }
    return out;
}
pid_t launch_exact_note_window(const Stub&s,const std::string&note){
    int pfd[2];if(pipe2(pfd,O_CLOEXEC)!=0)blocked("DETAIL_PIPE_FAILED");
    pid_t pid=fork();if(pid<0){close(pfd[0]);close(pfd[1]);blocked("DETAIL_FORK_FAILED");}
    if(pid==0){
        if(dup2(pfd[0],STDIN_FILENO)<0)_exit(125);
        close(pfd[0]);close(pfd[1]);
        execl("/usr/bin/zenity","zenity","--text-info",
              "--title=PCMF Exact Entry Under Review",
              "--width=820","--height=520",
              "--font=Monospace 11",
              "--ok-label=Keep open while confirming",
              (char*)nullptr);
        _exit(127);
    }
    close(pfd[0]);
    std::string display=
        "PCMF EXACT ENTRY UNDER REVIEW\n"
        "========================================\n"
        "Subject: "+s.subject+"\n"
        "Domain: "+s.domain+"\n"
        "Class: "+s.event_class+"\n"
        "Reason: "+s.reason+"\n"
        "Bytes: "+std::to_string(s.note_bytes)+"\n"
        "SHA-256: "+s.note_hash+"\n\n"
        "EXACT ENTRY (byte-for-byte hash-bound):\n"
        "----------------------------------------\n"+note+
        "\n----------------------------------------\n\n"
        "Keep this window open while entering the challenge in the approval window.\n"
        "The entry is supplied through an ephemeral pipe and is not persisted by this reviewer.\n";
    size_t off=0;
    while(off<display.size()){
        ssize_t n=write(pfd[1],display.data()+off,display.size()-off);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){close(pfd[1]);kill(pid,SIGTERM);waitpid(pid,nullptr,0);blocked("DETAIL_WRITE_FAILED");}
        off+=(size_t)n;
    }
    close(pfd[1]);
    return pid;
}
bool child_alive(pid_t pid){
    int st=0;
    pid_t r=waitpid(pid,&st,WNOHANG);
    if(r==0)return true;
    return false;
}
void terminate_child(pid_t pid){
    if(pid<=0)return;
    if(child_alive(pid))kill(pid,SIGTERM);
    int st=0;while(waitpid(pid,&st,0)<0&&errno==EINTR){}
}
void owner_prompt_ping(){
    const std::string sound=approval_sound_path();
    // Ubuntu PipeWire typically supplies pw-play, not paplay. The audio
    // is advisory: a playback failure must never bypass owner approval.
    const char *player=nullptr;
    if(access("/usr/bin/pw-play",X_OK)==0)player="/usr/bin/pw-play";
    else if(access("/usr/bin/paplay",X_OK)==0)player="/usr/bin/paplay";
    struct stat asset{};
    if(!player||stat(sound.c_str(),&asset)!=0||!S_ISREG(asset.st_mode)){
        syslog(LOG_WARNING,"OWNER_CHIME_PLAYER_OR_ASSET_UNAVAILABLE");
        return;
    }
    pid_t pid=fork();
    if(pid==0){
        execl(player,player,sound.c_str(),(char*)nullptr);
        _exit(127);
    }
    if(pid<0){
        syslog(LOG_WARNING,"OWNER_CHIME_PROCESS_START_FAILED");
        return;
    }
    int st=0;
    while(waitpid(pid,&st,0)<0&&errno==EINTR){}
    if(WIFEXITED(st)&&WEXITSTATUS(st)==0)
        syslog(LOG_NOTICE,"OWNER_CHIME_PLAYER_EXIT_OK");
    else
        syslog(LOG_WARNING,"OWNER_CHIME_PLAYER_EXIT_FAILURE");
}

bool gui_challenge(const Stub&s,const std::string&challenge,pid_t detail_pid){
    Display *d=XOpenDisplay(nullptr);
    if(!d)blocked("OWNER_X11_DISPLAY_UNAVAILABLE");

    const int screen=DefaultScreen(d);
    const unsigned int width=760,height=430;
    Window win=XCreateSimpleWindow(
        d,RootWindow(d,screen),80,80,width,height,1,
        BlackPixel(d,screen),WhitePixel(d,screen));
    if(!win){XCloseDisplay(d);blocked("OWNER_X11_WINDOW_CREATE_FAILED");}

    XStoreName(d,win,"PCMF Owner Approval");
    XSelectInput(d,win,ExposureMask|KeyPressMask|ButtonPressMask|StructureNotifyMask);
    Atom wm_delete=XInternAtom(d,"WM_DELETE_WINDOW",False);
    XSetWMProtocols(d,win,&wm_delete,1);

    GC gc=XCreateGC(d,win,0,nullptr);
    if(!gc){XDestroyWindow(d,win);XCloseDisplay(d);blocked("OWNER_X11_GC_FAILED");}
    XSetForeground(d,gc,BlackPixel(d,screen));
    XSetBackground(d,gc,WhitePixel(d,screen));
    XFontStruct *font=XLoadQueryFont(d,"9x15");
    if(font)XSetFont(d,gc,font->fid);

    const int entry_x=60,entry_y=285,entry_w=640,entry_h=34;
    const int approve_x=60,approve_y=350,approve_w=260,approve_h=42;
    const int cancel_x=440,cancel_y=350,cancel_w=260,cancel_h=42;

    std::string typed;
    std::string feedback="Click the entry field. Lowercase letters are accepted.";
    unsigned int failed_attempts=0;
    bool done=false,approved=false;
    bool entry_focused=false,caret_visible=false;
    auto next_caret_toggle=std::chrono::steady_clock::now()+std::chrono::milliseconds(500);

    auto draw_text=[&](int x,int y,const std::string&v){
        XDrawString(d,win,gc,x,y,v.c_str(),(int)v.size());
    };
    auto draw=[&](){
        XClearWindow(d,win);
        draw_text(60,45,"PCMF OWNER APPROVAL");
        draw_text(60,78,"The exact entry is displayed in the separate owner-only review window.");
        draw_text(60,101,"Keep that window open while confirming.");
        draw_text(60,140,"Subject: "+s.subject);
        draw_text(60,163,"Domain: "+s.domain);
        draw_text(60,186,"Class: "+s.event_class);
        draw_text(60,209,"Reason: "+s.reason);
        draw_text(60,244,"ONE-TIME 8-CHARACTER CODE:  "+challenge);
        draw_text(60,271,"Type the 8 characters exactly to authorize this entry ONCE.");
        XDrawRectangle(d,win,gc,entry_x,entry_y,entry_w,entry_h);
        if(entry_focused){
            XDrawRectangle(d,win,gc,entry_x+1,entry_y+1,entry_w-2,entry_h-2);
        }
        draw_text(entry_x+10,entry_y+23,typed);
        if(entry_focused&&caret_visible){
            int text_px=font?XTextWidth(font,typed.c_str(),(int)typed.size()):(int)typed.size()*9;
            const int caret_x=entry_x+10+text_px+1;
            XDrawLine(d,win,gc,caret_x,entry_y+8,caret_x,entry_y+26);
        }
        draw_text(60,340,feedback);
        XDrawRectangle(d,win,gc,approve_x,approve_y,approve_w,approve_h);
        draw_text(approve_x+72,approve_y+27,"Authorize once");
        XDrawRectangle(d,win,gc,cancel_x,cancel_y,cancel_w,cancel_h);
        draw_text(cancel_x+76,cancel_y+27,"Leave pending");
        XFlush(d);
    };
    auto inside=[](int x,int y,int bx,int by,int bw,int bh){
        return x>=bx&&x<=bx+bw&&y>=by&&y<=by+bh;
    };
    auto verify=[&](){
        if(typed.size()!=challenge.size())return false;
        return pcmf_ct_equal(typed.data(),challenge.data(),challenge.size())!=0;
    };

    auto submit_attempt=[&](){
        if(typed.size()!=challenge.size()){
            feedback="Enter all 8 characters; this request is still pending.";
            draw();
            return;
        }
        if(verify()){
            approved=true;done=true;
            return;
        }
        failed_attempts++;
        typed.clear();
        if(failed_attempts>=5){
            feedback="Five unsuccessful attempts. Approval remains pending.";
            approved=false;done=true;
            return;
        }
        feedback="Code did not match. Re-enter it (attempts left: "+std::to_string(5-failed_attempts)+").";
        entry_focused=true;
        caret_visible=true;
        draw();
    };
    XMapRaised(d,win);
    draw();
    owner_prompt_ping();

    while(!done){
        if(!child_alive(detail_pid)){approved=false;break;}

        while(XPending(d)>0 && !done){
            XEvent ev{};
            XNextEvent(d,&ev);
            if(ev.type==Expose){
                if(ev.xexpose.count==0)draw();
            }else if(ev.type==MapNotify){
                entry_focused=true;
                caret_visible=true;
                XSetInputFocus(d,win,RevertToParent,CurrentTime);
                draw();
            }else if(ev.type==KeyPress){
                char buf[32]={};
                KeySym ks=NoSymbol;
                int n=XLookupString(&ev.xkey,buf,sizeof(buf),&ks,nullptr);
                if(ks==XK_Escape){
                    approved=false;done=true;
                }else if(entry_focused&&(ks==XK_Return||ks==XK_KP_Enter)){
                    submit_attempt();
                }else if(entry_focused&&(ks==XK_BackSpace||ks==XK_Delete)){
                    if(!typed.empty())typed.pop_back();
                    caret_visible=true;
                    next_caret_toggle=std::chrono::steady_clock::now()+std::chrono::milliseconds(500);
                    draw();
                }else if(entry_focused&&n>0 && typed.size()<8){
                    for(int i=0;i<n && typed.size()<8;i++){
                        unsigned char c=(unsigned char)buf[i];
                        if(c>='a'&&c<='z')c=(unsigned char)(c-'a'+'A');
                        if((c>='A'&&c<='Z')||(c>='2'&&c<='9'))
                            typed.push_back((char)c);
                    }
                    caret_visible=true;
                    next_caret_toggle=std::chrono::steady_clock::now()+std::chrono::milliseconds(500);
                    draw();
                }
            }else if(ev.type==ButtonPress){
                const int x=ev.xbutton.x,y=ev.xbutton.y;
                if(inside(x,y,entry_x,entry_y,entry_w,entry_h)){
                    entry_focused=true;
                    caret_visible=true;
                    next_caret_toggle=std::chrono::steady_clock::now()+std::chrono::milliseconds(500);
                    XSetInputFocus(d,win,RevertToParent,CurrentTime);
                    draw();
                }else if(inside(x,y,approve_x,approve_y,approve_w,approve_h)){
                    submit_attempt();
                }else if(inside(x,y,cancel_x,cancel_y,cancel_w,cancel_h)){
                    approved=false;done=true;
                }else{
                    entry_focused=false;
                    caret_visible=false;
                    draw();
                }
            }else if(ev.type==ClientMessage &&
                     (Atom)ev.xclient.data.l[0]==wm_delete){
                approved=false;done=true;
            }
        }

        if(!done){
            if(entry_focused){
                const auto now=std::chrono::steady_clock::now();
                if(now>=next_caret_toggle){
                    caret_visible=!caret_visible;
                    next_caret_toggle=now+std::chrono::milliseconds(500);
                    draw();
                }
            }
            pollfd pfd{};
            pfd.fd=ConnectionNumber(d);
            pfd.events=POLLIN;
            (void)poll(&pfd,1,100);
        }
    }

    wipe(typed);
    if(font)XFreeFont(d,font);
    XFreeGC(d,gc);
    XDestroyWindow(d,win);
    XCloseDisplay(d);
    return approved;
}
std::string run_authorize_once(const std::string&token){
    require_pinned_pcmf();
    ChildResult r=run_child_capture({
        PCMF,"review","resolve","--token",token,
        "--decision","authorize_once","--root",ROOT
    },262144);
    if(r.code!=0)blocked("PCMF_AUTHORIZE_FAILED");
    J j;try{j=parse(r.out);}catch(...){blocked("PCMF_AUTHORIZE_RESPONSE_INVALID");}
    if(j.t!=J::Obj||!j.has("status")||j.at("status").t!=J::Str||j.at("status").s!="OK")
        blocked("PCMF_AUTHORIZE_NOT_OK");
    if(!j.has("data")||!j.at("data").has("authorized")||!j.at("data").at("authorized").b)
        blocked("PCMF_AUTHORIZE_NOT_CONFIRMED");
    return r.out;
}
void inspect(const Stub&s){
    J o=J::object(),r=J::object();
    o["status"]=J::string("OWNER_APPROVAL_REQUIRED");
    o["raw_sensitive_content_persisted"]=J::boolean(false);
    o["exact_entry_display"]=J::string("OWNER_MACHINE_EPHEMERAL_ONLY");
    o["confirmation"]=J::string("POLKIT_OWNER_AUTH_PLUS_8_CHARACTER_CHALLENGE");
    r["token"]=J::string(s.token);r["note_hash"]=J::string(s.note_hash);
    r["subject"]=J::string(s.subject);r["domain"]=J::string(s.domain);
    r["event_class"]=J::string(s.event_class);r["reason"]=J::string(s.reason);
    r["note_bytes"]=J::number(s.note_bytes);r["created_at"]=J::string(s.created_at);
    r["stub_canonical_sha256"]=J::string(s.canonical_hash);o["review"]=r;
    std::cout<<dump(o)<<"\n";
}
std::string read_exact_note_stdin(const Stub&s){
    std::string note=read_all(STDIN_FILENO,4096);
    if((long long)note.size()!=s.note_bytes)blocked("EXACT_NOTE_BYTE_COUNT_MISMATCH");
    if(sha256_string(note)!=s.note_hash)blocked("EXACT_NOTE_HASH_MISMATCH");
    return note;
}
void prompt_exact(const std::string&token){
    Stub before=load_stub(token);
    std::string note=read_exact_note_stdin(before);

    require_os_owner_auth();

    std::string challenge=random_challenge();
    pid_t detail_pid=launch_exact_note_window(before,note);
    bool approved=gui_challenge(before,challenge,detail_pid);
    terminate_child(detail_pid);
    wipe(challenge);
    if(!approved){wipe(note);blocked("OWNER_CONFIRMATION_FAILED_OR_DETAIL_CLOSED");}

    Stub after=load_stub(token);
    if(after.canonical_hash!=before.canonical_hash){wipe(note);blocked("REVIEW_STUB_CHANGED_DURING_CONFIRMATION");}
    if(sha256_string(note)!=after.note_hash){wipe(note);blocked("NOTE_BINDING_CHANGED_DURING_CONFIRMATION");}

    (void)run_authorize_once(token);
    std::string auth=ROOT+"/review/authorized/"+token+".json";
    struct stat st{};
    if(lstat(auth.c_str(),&st)!=0||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077)!=0){
        wipe(note);blocked("POST_AUTHORIZE_MARKER_MISSING_OR_UNSAFE");
    }
    J o=J::object();o["status"]=J::string("PASS_OWNER_AUTHORIZED_ONCE");
    o["token"]=J::string(token);o["subject"]=J::string(before.subject);
    o["note_hash"]=J::string(before.note_hash);
    o["exact_entry_displayed_locally"]=J::boolean(true);
    o["challenge_verified"]=J::boolean(true);
    o["raw_note_persisted_by_reviewer"]=J::boolean(false);
    o["awaiting_exact_client_resubmission"]=J::boolean(true);
    wipe(note);
    std::cout<<dump(o)<<"\n";
}
}
int main(int argc,char**argv){
    if(argc==3&&std::string(argv[1])=="selfcheck"){
        configure_runtime(argv[2]);
        require_pinned_pcmf();
        require_secure_root();
        std::cout<<"PASS_R4_REVIEWER_SELFCHECK root_private=true pcmf_hash_pinned=true\n";
        return 0;
    }
    if(argc==4&&std::string(argv[1])=="inspect"){
        configure_runtime(argv[3]);inspect(load_stub(argv[2]));return 0;
    }
    if(argc==4&&std::string(argv[1])=="prompt-exact"){
        configure_runtime(argv[3]);prompt_exact(argv[2]);return 0;
    }
    std::cerr<<"usage: forge-pcmf-owner-review-r4 selfcheck ROOT | inspect TOKEN ROOT | prompt-exact TOKEN ROOT < exact-note\n";
    return 2;
}
