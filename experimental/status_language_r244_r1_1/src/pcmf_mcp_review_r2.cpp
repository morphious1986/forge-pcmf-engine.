// PCMF-only stdio boundary. No Engine linkage, shell, CLI, or Mini methods.
#include "pcmf_json.h"
#include "pcmf_util.h"
#include <iostream>
#include <set>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
using namespace pcmf;
namespace {
struct FD { int n; explicit FD(int f):n(f){} ~FD(){if(n>=0)close(n);} };

#ifndef PCMF_OWNER_REVIEWER_R4_SHA256
#define PCMF_OWNER_REVIEWER_R4_SHA256 "UNSET"
#endif

std::string executable_dir(){
 std::vector<char> path(4096);
 ssize_t n=readlink("/proc/self/exe",path.data(),path.size()-1);
 ensure(n>0&&(size_t)n<path.size()-1,"SELF_PATH_UNAVAILABLE");
 path[(size_t)n]='\0';
 std::string full(path.data());
 auto slash=full.rfind('/');
 ensure(slash!=std::string::npos&&slash>0,"SELF_PATH_INVALID");
 return full.substr(0,slash);
}
std::string reviewer_path(){
 return executable_dir()+"/../bin/forge-pcmf-owner-review-r4";
}
std::string root_from_socket(const std::string&sock){
 const std::string suffix="/run/pcmf.sock";
 ensure(sock.size()>suffix.size()&&
        sock.compare(sock.size()-suffix.size(),suffix.size(),suffix)==0,
        "SOCKET_ROOT_LAYOUT_REQUIRED");
 std::string root=sock.substr(0,sock.size()-suffix.size());
 ensure(!root.empty()&&root[0]=='/'&&root.find("/../")==std::string::npos,
        "ROOT_FROM_SOCKET_INVALID");
 return root;
}

std::string safe_exec_read(const std::string&p,size_t cap){
 FD f(open(p.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC)); struct stat s{};
 ensure(f.n>=0&&fstat(f.n,&s)==0&&S_ISREG(s.st_mode)&&s.st_nlink==1&&
        s.st_uid==geteuid()&&(s.st_mode&0022)==0,"REVIEWER_EXEC_UNSAFE");
 ensure(s.st_size>0&&(size_t)s.st_size<=cap,"REVIEWER_EXEC_SIZE");
 std::string out;char buf[8192];
 for(;;){ssize_t n=read(f.n,buf,sizeof buf);if(n<0&&errno==EINTR)continue;
  ensure(n>=0,"REVIEWER_EXEC_READ");if(!n)break;out.append(buf,(size_t)n);
  ensure(out.size()<=cap,"REVIEWER_EXEC_SIZE");}
 return out;
}
void require_pinned_reviewer(){
 const std::string path=reviewer_path();
 const std::string bytes=safe_exec_read(path,4ull*1024*1024);
 ensure(sha256_hex(bytes)==PCMF_OWNER_REVIEWER_R4_SHA256,"REVIEWER_HASH_MISMATCH");
}
struct ReviewChild{int code=-1;std::string out;};
ReviewChild run_owner_review_exact(const std::string&token,const std::string&note,
                                  const std::string&root){
 require_pinned_reviewer();
 const std::string reviewer=reviewer_path();
 int inpipe[2],outpipe[2];
 ensure(pipe2(inpipe,O_CLOEXEC)==0&&pipe2(outpipe,O_CLOEXEC)==0,"REVIEW_PIPE_FAILED");
 pid_t pid=fork();ensure(pid>=0,"REVIEW_FORK_FAILED");
 if(pid==0){
  if(dup2(inpipe[0],STDIN_FILENO)<0||dup2(outpipe[1],STDOUT_FILENO)<0)_exit(125);
  close(inpipe[0]);close(inpipe[1]);close(outpipe[0]);close(outpipe[1]);
  execl(reviewer.c_str(),reviewer.c_str(),"prompt-exact",token.c_str(),root.c_str(),(char*)nullptr);
  _exit(127);
 }
 close(inpipe[0]);close(outpipe[1]);
 size_t off=0;
 while(off<note.size()){
  ssize_t n=write(inpipe[1],note.data()+off,note.size()-off);
  if(n<0&&errno==EINTR)continue;
  ensure(n>0,"REVIEW_NOTE_SEND_FAILED");off+=(size_t)n;
 }
 close(inpipe[1]);
 std::string out;char buf[4096];
 for(;;){ssize_t n=read(outpipe[0],buf,sizeof buf);if(n<0&&errno==EINTR)continue;
  ensure(n>=0,"REVIEW_RESULT_READ_FAILED");if(!n)break;out.append(buf,(size_t)n);
  ensure(out.size()<=65536,"REVIEW_RESULT_TOO_LARGE");}
 close(outpipe[0]);
 int st=0;while(waitpid(pid,&st,0)<0&&errno==EINTR){}
 ReviewChild r;r.code=WIFEXITED(st)?WEXITSTATUS(st):128;r.out=std::move(out);return r;
}
std::string private_read(const std::string&p,size_t cap){
 FD f(open(p.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC)); struct stat s{};
 ensure(f.n>=0&&fstat(f.n,&s)==0&&S_ISREG(s.st_mode)&&s.st_uid==geteuid()&&(s.st_mode&0077)==0,"PRIVATE_FILE_REQUIRED");
 ensure(s.st_size>=0&&(size_t)s.st_size<=cap,"PRIVATE_FILE_SIZE");
 std::string out;char buf[4096];for(;;){ssize_t n=read(f.n,buf,sizeof buf);if(n<0&&errno==EINTR)continue;ensure(n>=0,"PRIVATE_FILE_READ");if(!n)break;out.append(buf,(size_t)n);ensure(out.size()<=cap,"PRIVATE_FILE_SIZE");}return out;
}
void exact(const J&v,const std::set<std::string>&allowed){ensure(v.t==J::Obj,"OBJECT_REQUIRED");for(const auto&kv:v.o)ensure(allowed.count(kv.first)!=0,"UNKNOWN_ARGUMENT");}
std::string str(const J&v,const char*k,size_t cap){ensure(v.has(k)&&v.at(k).t==J::Str,"STRING_REQUIRED");auto s=v.at(k).s;ensure(!s.empty()&&s.size()<=cap&&s.find('\0')==std::string::npos,"STRING_SIZE");return s;}
J prop(const char*t){J v=J::object();v["type"]=J::string(t);return v;}
J tool(const char*name,const char*desc,J properties,J required,bool readonly){J t=J::object();t["name"]=J::string(name);t["description"]=J::string(desc);J s=J::object();s["type"]=J::string("object");s["properties"]=properties;s["required"]=required;s["additionalProperties"]=J::boolean(false);t["inputSchema"]=s;J a=J::object();a["readOnlyHint"]=J::boolean(readonly);a["destructiveHint"]=J::boolean(false);a["openWorldHint"]=J::boolean(false);t["annotations"]=a;return t;}
J required(std::initializer_list<const char*> keys){J a=J::array();for(auto k:keys)a.a.push_back(J::string(k));return a;}
bool modern_request(const J&req){
 if(!req.has("params")||req.at("params").t!=J::Obj||!req.at("params").has("_meta"))return false;
 const J&m=req.at("params").at("_meta");ensure(m.t==J::Obj,"MCP_META_REQUIRED");
 auto version=str(m,"io.modelcontextprotocol/protocolVersion",32);
 ensure(version=="2026-07-28","UNSUPPORTED_MCP_VERSION");
 ensure(m.has("io.modelcontextprotocol/clientCapabilities")&&m.at("io.modelcontextprotocol/clientCapabilities").t==J::Obj,"CLIENT_CAPABILITIES_REQUIRED");
 if(m.has("io.modelcontextprotocol/clientInfo"))ensure(m.at("io.modelcontextprotocol/clientInfo").t==J::Obj,"CLIENT_INFO_INVALID");
 return true;
}
void stamp_modern(J&r,bool cacheable){
 r["resultType"]=J::string("complete");
 if(cacheable){r["ttlMs"]=J::number(0);r["cacheScope"]=J::string("private");}
 J m=J::object(),si=J::object();si["name"]=J::string("forge-gpt-pcmf");si["version"]=J::string("0.6.0-r17-r244");
 m["io.modelcontextprotocol/serverInfo"]=si;r["_meta"]=m;
}
J discovery(){
 J r=J::object(),versions=J::array();versions.a.push_back(J::string("2026-07-28"));r["supportedVersions"]=versions;
 r["capabilities"]=J::object();r["capabilities"]["tools"]=J::object();
 stamp_modern(r,true);return r;
}
J tools(){J a=J::array(),p=J::object();
 a.a.push_back(tool("pcmf_health","Authenticated health of the pinned TechMagnet PCMF instance; the live reconciled R243 writer authority is verified on every call.",p,required({}),true));
 a.a.push_back(tool("pcmf_state","Integrity and HOT/WARM/COLD/DORMANT counts for this dedicated instance.",p,required({}),true));
 p["subject"]=prop("string");p["limit"]=prop("integer");p["limit"]["minimum"]=J::number(1);p["limit"]["maximum"]=J::number(50);p["include_warm"]=prop("boolean");
 a.a.push_back(tool("pcmf_recall","Use before responding when prior durable context for a known subject may matter. Recall latest effective HOT memory per subject, optionally WARM, within the fixed profile/project. This is not full historical search.",p,required({"subject"}),true));
 p=J::object();p["subject"]=prop("string");p["domain"]=prop("string");p["domain"]["enum"]=required({"MEMORY_SYSTEM","BUILD_PROJECT","OPERATIONAL_CONTROL","LIBRARY_GOVERNANCE","SHARED_GOVERNANCE","DAILY_ROUTINE","PERSONAL_PREFERENCE","SCHEDULE_COMMITMENT","LEARNING_CONTEXT","ENVIRONMENT_CONTEXT","RELATIONSHIP_CONTEXT","GENERAL_CONTEXT"});p["event_class"]=prop("string");p["event_class"]["enum"]=required({"PREFERENCE","PROJECT_STATE","WORKFLOW_STATE","FAILURE_GOTCHA","OBSERVATION","ROUTINE_STATE","COMMITMENT","CORRECTION","REVOCATION"});p["note"]=prop("string");p["note"]["minLength"]=J::number(3);p["note"]["maxLength"]=J::number(4096);p["request_id"]=prop("string");p["request_id"]["pattern"]=J::string("^[0-9a-f]{32}$");p["ref_event_id"]=prop("string");p["ref_event_id"]["pattern"]=J::string("^[0-9a-f]{64}$");p["project_lifecycle"]=prop("string");p["project_lifecycle"]["enum"]=required({"COMPLETE"});
 a.a.push_back(tool("pcmf_observe","Use after a substantive interaction when it yields durable useful non-sensitive context: a preference, routine, commitment, observation, correction/revocation, project state, workflow state, or failure gotcha. Submit it through PCMF's autonomous admission policy. REVIEW_REQUIRED is not a commit; never auto-resubmit uncertain or sensitive content. REWORD_REQUIRED is not an approval gate: rephrase using the returned accepted_terms and submit the corrected wording as a new request without asking Morphius for approval. Reuse the same request_id only for retries of the identical request.",p,required({"subject","domain","event_class","note","request_id"}),false));
 p=J::object();p["review_token"]=prop("string");p["review_token"]["pattern"]=J::string("^[0-9a-f]{64}$");p["note"]=prop("string");p["note"]["minLength"]=J::number(3);p["note"]["maxLength"]=J::number(4096);p["request_id"]=prop("string");p["request_id"]["pattern"]=J::string("^[0-9a-f]{32}$");J review_p=p;
 p=J::object();p["subject"]=prop("string");p["tier"]=prop("string");p["tier"]["enum"]=required({"HOT","WARM","COLD"});p["reason"]=prop("string");p["request_id"]=prop("string");p["request_id"]["pattern"]=J::string("^[0-9a-f]{32}$");
 a.a.push_back(tool("pcmf_tier_request","ONLY use after the user explicitly asks to set an existing PCMF subject to HOT, WARM, or COLD. Uses the connector fixed profile/project scope, resolves a unique current subject domain under the writer lock, and appends a governed tier transition without granting owner authority.",p,required({"subject","tier","reason","request_id"}),false));
 p=J::object();p["subject"]=prop("string");p["domain"]=prop("string");p["domain"]["enum"]=required({"MEMORY_SYSTEM","BUILD_PROJECT","OPERATIONAL_CONTROL","LIBRARY_GOVERNANCE","SHARED_GOVERNANCE","DAILY_ROUTINE","PERSONAL_PREFERENCE","SCHEDULE_COMMITMENT","LEARNING_CONTEXT","ENVIRONMENT_CONTEXT","RELATIONSHIP_CONTEXT","GENERAL_CONTEXT"});p["tier"]=prop("string");p["tier"]["enum"]=required({"HOT","WARM","COLD"});p["reason"]=prop("string");p["reason"]["minLength"]=J::number(3);p["reason"]["maxLength"]=J::number(700);p["request_id"]=prop("string");p["request_id"]["pattern"]=J::string("^[0-9a-f]{32}$");
 a.a.push_back(tool("pcmf_tier_write","ONLY use after the user explicitly asks to set an existing PCMF subject to HOT, WARM, or COLD. Performs a governed scoped tier write against the current effective subject state; never grants owner authority and never changes memory content.",p,required({"subject","domain","tier","reason","request_id"}),false));
 a.a.push_back(tool("pcmf_review_submit","Consume an exact one-time sensitive-memory review only after the local owner has authorized the returned review token. This tool cannot approve, reject, list, or create owner review authority. The note must hash-match the pending review stub and the token is single-use.",review_p,required({"review_token","note","request_id"}),false));
 J out=J::object();out["tools"]=a;return out;}
class Boundary {
 J cfg;
 J call(const std::string&op,const J&params,const std::string&nonce){
  const std::string sock=cfg.at("socket").s;struct stat st{};
  ensure(lstat(sock.c_str(),&st)==0&&S_ISSOCK(st.st_mode)&&st.st_uid==geteuid()&&(st.st_mode&0077)==0,"PRIVATE_SOCKET_REQUIRED");
  FD fd(socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0));ensure(fd.n>=0,"SOCKET_OPEN_FAILED");
  timeval tv{5,0};ensure(setsockopt(fd.n,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv)==0&&setsockopt(fd.n,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv)==0,"SOCKET_TIMEOUT_SETUP");
  sockaddr_un addr{};addr.sun_family=AF_UNIX;ensure(sock.size()<sizeof addr.sun_path,"SOCKET_PATH_TOO_LONG");memcpy(addr.sun_path,sock.c_str(),sock.size());
  ensure(connect(fd.n,(sockaddr*)&addr,sizeof addr)==0,"PCMF_DAEMON_UNREACHABLE");
  ucred peer{};socklen_t len=sizeof peer;ensure(getsockopt(fd.n,SOL_SOCKET,SO_PEERCRED,&peer,&len)==0&&len==sizeof peer&&peer.uid==geteuid()&&peer.pid>0,"PCMF_PEER_REJECTED");
  J payload=J::object();payload["v"]=J::string("PCMF_IPv1");payload["client"]=cfg.at("client_id");payload["op"]=J::string(op);payload["params"]=params;payload["nonce"]=J::string(nonce);payload["ts"]=J::number(now_epoch());
  std::string key=private_read(cfg.at("key_file").s,32);ensure(key.size()==32,"KEY_SIZE");std::string body=dump(payload)+"\n";std::string frame=body+hmac_hex(key,body)+"\n";cleanse(key);ensure(frame.size()<=8332,"FRAME_TOO_LARGE");
  size_t off=0;while(off<frame.size()){ssize_t n=write(fd.n,frame.data()+off,frame.size()-off);if(n<0&&errno==EINTR)continue;ensure(n>0,"PCMF_SEND_UNCERTAIN");off+=(size_t)n;}
  std::string response;char buf[4096];while(response.find('\n')==std::string::npos){ssize_t n=read(fd.n,buf,sizeof buf);if(n<0&&errno==EINTR)continue;ensure(n>0,"PCMF_RESPONSE_UNCERTAIN_RECONCILE_BEFORE_RETRY");response.append(buf,(size_t)n);ensure(response.size()<=262144,"PCMF_RESPONSE_TOO_LARGE");}
  J r=parse(response);ensure(r.at("canonical_writer").s=="AUTHORIZED_R243_RECONCILED_SINGLE_WRITER","R243_WRITER_AUTHORITY_REQUIRED");return r;
 }
 public:
 explicit Boundary(const std::string&path):cfg(parse(private_read(path,8192))){
  exact(cfg,{"socket","root","root_id","key_file","client_id","profile","project"});
  for(auto k:{"socket","root_id","key_file","client_id","profile","project"})str(cfg,k,4096);
  if(cfg.has("root")){
    auto root=str(cfg,"root",4096);
    ensure(!root.empty()&&root[0]=='/'&&root.find("/../")==std::string::npos,"ROOT_INVALID");
  }
  ensure(is_hex(cfg.at("root_id").s,16),"ROOT_ID_INVALID");
  ensure(cfg.at("client_id").s=="forge_gpt_mcp","DEDICATED_CLIENT_REQUIRED");
 }

 // R243 Automatic Owner Review Dispatch.
 // Fork twice so MCP tool replies immediately and long-lived interactive
 // owner review is not tied to the ChatGPT request transport lifetime.
 // The review note remains only in process memory/private anonymous pipes;
 // NO plaintext note, token, or digest is put in argv, env, or logs.
 void start_owner_prompt(const std::string&token,const std::string&note,
                         const std::string&review_root,const std::string&nonce){
  require_pinned_reviewer();
  ensure(getenv("DISPLAY") && *getenv("DISPLAY"),
         "OWNER_DISPLAY_NOT_CONFIGURED_NEEDS_INSPECTION");
  pid_t bootstrap=fork();ensure(bootstrap>=0,"OWNER_DISPATCH_FORK_FAILED");
  if(bootstrap==0){
   pid_t worker=fork();
   if(worker<0)_exit(125);
   if(worker>0)_exit(0);
   (void)setsid();
   // Never hold the ChatGPT stdio transport open in an interactive child.
   int devnull=open("/dev/null",O_RDWR|O_CLOEXEC);
   if(devnull>=0){
    (void)dup2(devnull,STDIN_FILENO);
    (void)dup2(devnull,STDOUT_FILENO);
    (void)dup2(devnull,STDERR_FILENO);
    if(devnull>STDERR_FILENO)close(devnull);
   }
   auto event=[](const char*code){
     openlog("pcmf-owner-review",LOG_PID|LOG_NDELAY,LOG_USER);
     syslog(LOG_NOTICE,"%s",code);
     closelog();
   };
   try{
    // Serialize multiple ChatGPT instances' approval windows. No duplicate
    // memory root or writer; only an advisory GUI dispatch lock.
    const std::string dir="/run/user/"+std::to_string(geteuid())+"/pcmf";
    struct stat ds{};
    ensure(stat(dir.c_str(),&ds)==0 && S_ISDIR(ds.st_mode) &&
           ds.st_uid==geteuid() && (ds.st_mode&0077)==0,
           "OWNER_RUNTIME_DIR_UNSAFE");
    const std::string lp=dir+"/owner-review-dispatch.lock";
    FD lock(open(lp.c_str(),O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600));
    struct stat ls{};
    ensure(lock.n>=0 && fstat(lock.n,&ls)==0 && S_ISREG(ls.st_mode) &&
           ls.st_uid==geteuid() && ls.st_nlink==1 && (ls.st_mode&0077)==0,
           "OWNER_DISPATCH_LOCK_UNSAFE");
    bool locked=false;
    for(unsigned i=0;i<300;i++){
     if(flock(lock.n,LOCK_EX|LOCK_NB)==0){locked=true;break;}
     if(errno!=EWOULDBLOCK&&errno!=EAGAIN)break;
     sleep(1);
    }
    ensure(locked,"OWNER_DISPATCH_QUEUE_NEEDS_INSPECTION");
    event("OWNER_APPROVAL_PROMPT_START");
    ReviewChild owner=run_owner_review_exact(token,note,review_root);
    if(owner.code!=0){
      event("NEEDS_INSPECTION_OWNER_PROMPT_NOT_APPROVED_OR_UNAVAILABLE");
      _exit(0);
    }
    J approval=parse(owner.out);
    ensure(approval.t==J::Obj && approval.has("status") &&
           approval.at("status").t==J::Str &&
           approval.at("status").s=="PASS_OWNER_AUTHORIZED_ONCE",
           "OWNER_REVIEW_NOT_CONFIRMED");
    ensure(approval.has("token") && approval.at("token").t==J::Str &&
           approval.at("token").s==token,"OWNER_REVIEW_TOKEN_MISMATCH");
    ensure(approval.has("note_hash") &&
           approval.at("note_hash").t==J::Str &&
           approval.at("note_hash").s==sha256_hex(note),
           "OWNER_REVIEW_NOTE_HASH_MISMATCH");
    J rp=J::object();
    rp["token"]=J::string(token);
    rp["note"]=J::string(note);
    const std::string review_nonce=
        sha256_hex(std::string("pcmf-review-submit|")+nonce+"|"+token).substr(0,32);
    // The authoritative R243 daemon remains the *sole writer*.
    J committed=call("review.submit",rp,review_nonce);
    ensure(committed.has("status") && committed.at("status").t==J::Str &&
           committed.at("status").s=="OK","OWNER_REVIEW_COMMIT_NEEDS_INSPECTION");
    event("OWNER_APPROVAL_COMMITTED_BY_AUTHORIZED_DAEMON");
   }catch(const std::exception&){
    // Intentionally do not print note, token, hash, or runtime errors.
    event("NEEDS_INSPECTION_OWNER_REVIEW_DISPATCH_FAILURE");
   }
   _exit(0);
  }
  // Only reap the short-lived bootstrap. Interactive worker is reparented.
  int st=0;
  while(waitpid(bootstrap,&st,0)<0 && errno==EINTR){}
  ensure(WIFEXITED(st) && WEXITSTATUS(st)==0,
         "OWNER_DISPATCH_BOOTSTRAP_FAILED_NEEDS_INSPECTION");
 }

 J invoke(const std::string&name,const J&args){
  std::string op,nonce=random_hex(16);J p=J::object();
  if(name=="pcmf_health"||name=="pcmf_state"){exact(args,{});op=name=="pcmf_health"?"health.get":"memory.state";}
  else if(name=="pcmf_recall"||name=="pcmf_observe"){
   exact(args,name=="pcmf_recall"?std::set<std::string>{"subject","limit","include_warm"}:std::set<std::string>{"subject","domain","event_class","note","request_id","ref_event_id","project_lifecycle"});
   auto subject=str(args,"subject",95);ensure(is_name(subject,2,95),"SUBJECT_INVALID");p["subject"]=J::string(subject);p["profile"]=cfg.at("profile");p["project"]=cfg.at("project");
   if(name=="pcmf_recall"){op="hot.get";if(args.has("limit")){auto n=args.at("limit").as_int();ensure(n>=1&&n<=50,"LIMIT_INVALID");p["limit"]=J::number(n);}if(args.has("include_warm")){ensure(args.at("include_warm").t==J::Bool,"BOOLEAN_REQUIRED");p["include_warm"]=args.at("include_warm");}}
   else{op="observe.submit";auto cls=str(args,"event_class",32);ensure(cls=="PREFERENCE"||cls=="PROJECT_STATE"||cls=="WORKFLOW_STATE"||cls=="FAILURE_GOTCHA"||cls=="OBSERVATION"||cls=="ROUTINE_STATE"||cls=="COMMITMENT"||cls=="CORRECTION"||cls=="REVOCATION","CLASS_NOT_EXPOSED");p["event_class"]=J::string(cls);p["domain"]=J::string(str(args,"domain",64));p["note"]=J::string(str(args,"note",4096));p["privacy_class"]=J::string("INTERNAL_PROJECT");if(args.has("ref_event_id")){auto ref=str(args,"ref_event_id",64);ensure(is_hex(ref,32),"REF_EVENT_ID_INVALID");p["ref_event_id"]=J::string(ref);}if(args.has("project_lifecycle")){auto life=str(args,"project_lifecycle",16);ensure(life=="COMPLETE","PROJECT_LIFECYCLE_INVALID");ensure(cls=="PROJECT_STATE"&&p.at("domain").s=="BUILD_PROJECT","PROJECT_COMPLETION_SCOPE_INVALID");p["project_lifecycle"]=J::string(life);}nonce=str(args,"request_id",32);ensure(is_hex(nonce,16),"REQUEST_ID_INVALID");}
  }else if(name=="pcmf_tier_request"){
   exact(args,{"subject","tier","reason","request_id"});op="tier.request";
   auto subject=str(args,"subject",95);ensure(is_name(subject,2,95),"SUBJECT_INVALID");
   auto tier=str(args,"tier",4);ensure(tier=="HOT"||tier=="WARM"||tier=="COLD","TIER_INVALID");
   auto reason=str(args,"reason",700);ensure(reason.size()>=3,"TIER_REASON_INVALID");
   p["subject"]=J::string(subject);p["profile"]=cfg.at("profile");p["project"]=cfg.at("project");
   p["tier"]=J::string(tier);p["reason"]=J::string(reason);
   nonce=str(args,"request_id",32);ensure(is_hex(nonce,16),"REQUEST_ID_INVALID");
  }else if(name=="pcmf_tier_write"){
   exact(args,{"subject","domain","tier","reason","request_id"});op="tier.set";
   auto subject=str(args,"subject",95);ensure(is_name(subject,2,95),"SUBJECT_INVALID");
   auto domain=str(args,"domain",64);ensure(is_name(domain,2,64),"DOMAIN_INVALID");
   auto tier=str(args,"tier",4);ensure(tier=="HOT"||tier=="WARM"||tier=="COLD","TIER_INVALID");
   auto reason=str(args,"reason",700);ensure(reason.size()>=3,"TIER_REASON_INVALID");
   p["subject"]=J::string(subject);p["domain"]=J::string(domain);
   p["profile"]=cfg.at("profile");p["project"]=cfg.at("project");
   p["tier"]=J::string(tier);p["reason"]=J::string(reason);
   nonce=str(args,"request_id",32);ensure(is_hex(nonce,16),"REQUEST_ID_INVALID");
  }else if(name=="pcmf_review_submit"){
   exact(args,{"review_token","note","request_id"});op="review.submit";auto token=str(args,"review_token",64);ensure(is_hex(token,32),"REVIEW_TOKEN_INVALID");p["token"]=J::string(token);p["note"]=J::string(str(args,"note",4096));nonce=str(args,"request_id",32);ensure(is_hex(nonce,16),"REQUEST_ID_INVALID");
  }else die("TOOL_NOT_EXPOSED");
  J h=call("health.get",J::object(),random_hex(16));ensure(h.at("status").s=="OK","PCMF_AUTHENTICATION_OR_HEALTH_FAILED");const J&d=h.at("data");ensure(d.at("root_id").s==cfg.at("root_id").s,"WRONG_INSTANCE");ensure(d.at("healthy").t==J::Bool&&d.at("healthy").b,"PCMF_INTEGRITY_HOLD");
  if(name=="pcmf_health")return h;
  J result=call(op,p,nonce);

  if(name=="pcmf_observe" && result.has("status") &&
     result.at("status").t==J::Str && result.at("status").s=="REVIEW_REQUIRED"){
    ensure(result.has("data")&&result.at("data").t==J::Obj,"REVIEW_DATA_REQUIRED");
    const J&rd=result.at("data");
    ensure(rd.has("review_token")&&rd.at("review_token").t==J::Str,"REVIEW_TOKEN_REQUIRED");
    const std::string token=rd.at("review_token").s;
    ensure(is_hex(token,32),"REVIEW_TOKEN_INVALID");
    const std::string note=p.at("note").s;

    const std::string review_root=cfg.has("root")?cfg.at("root").s:
                                  root_from_socket(cfg.at("socket").s);
    start_owner_prompt(token,note,review_root,nonce);
    // Do not claim a commit. The local approval process runs in a
    // detached, ephemeral worker and the daemon remains authoritative.
    result["owner_review"]=J::object();
    result["owner_review"]["status"]=J::string("PROMPT_DISPATCHED_OWNER_DECISION_PENDING");
    result["owner_review"]["local_prompt_completed"]=J::boolean(false);
    result["owner_review"]["exact_entry_persisted"]=J::boolean(false);
    result["owner_review"]["admitted"]=J::boolean(false);
    return result;
  }
  return result;
 }
};
J error(long long code,const char*msg){J e=J::object();e["code"]=J::number(code);e["message"]=J::string(msg);return e;}
// Bound before allocation; drain oversized lines to maintain framing.
bool line(std::string&out,bool&oversize){out.clear();oversize=false;char c;bool any=false;while(std::cin.get(c)){any=true;if(c=='\n')return true;if(out.size()<16384)out+=c;else oversize=true;}return any;}
}
int main(int argc,char**argv){
 std::signal(SIGPIPE,SIG_IGN);if(argc!=3||std::string(argv[1])!="--config"){std::cerr<<"usage: pcmf-mcp --config PRIVATE_JSON\n";return 2;}
 try{Boundary boundary(argv[2]);bool initialized=false;std::string input;bool oversized=false;
 while(line(input,oversized)){
  J reply=J::object(),id;reply["jsonrpc"]=J::string("2.0");bool notification=false;
  try{ensure(!oversized,"MCP_LINE_TOO_LARGE");J req=parse(input);ensure(req.t==J::Obj&&req.at("jsonrpc").s=="2.0","INVALID_REQUEST");if(req.has("id")){id=req.at("id");ensure(id.t==J::Str||id.t==J::Num||id.t==J::Null,"INVALID_ID");}else notification=true;reply["id"]=id;auto method=str(req,"method",128);
   if(notification){if(method=="notifications/initialized")initialized=true;continue;}
   const bool modern=modern_request(req);
   if(method=="server/discover"){ensure(modern,"MODERN_META_REQUIRED");reply["result"]=discovery();}
   else if(method=="initialize"){J r=J::object();const auto&params=req.at("params");auto version=str(params,"protocolVersion",32);ensure(version=="2025-11-25"||version=="2025-06-18"||version=="2025-03-26"||version=="2024-11-05","UNSUPPORTED_MCP_VERSION");r["protocolVersion"]=J::string(version);r["capabilities"]=J::object();r["capabilities"]["tools"]=J::object();r["serverInfo"]=J::object();r["serverInfo"]["name"]=J::string("forge-gpt-pcmf");r["serverInfo"]["version"]=J::string("0.5.0-r17-r243");reply["result"]=r;}
   else if(method=="ping"){J r=J::object();if(modern)stamp_modern(r,false);reply["result"]=r;}
   else if(!modern&&!initialized)reply["error"]=error(-32002,"NOT_INITIALIZED");
   else if(method=="tools/list"){J r=tools();if(modern)stamp_modern(r,true);reply["result"]=r;}
   else if(method=="tools/call"){
    J result=J::object(),items=J::array(),item=J::object();bool failed=false;std::string body;
    try{const J&p=req.at("params");exact(p,modern?std::set<std::string>{"name","arguments","_meta"}:std::set<std::string>{"name","arguments"});J args=p.has("arguments")?p.at("arguments"):J::object();J r=boundary.invoke(str(p,"name",64),args);body=dump(r);auto status=r.at("status").s;failed=status!="OK"&&status!="DUPLICATE_NOOP"&&status!="REWORD_REQUIRED";}catch(const Fail&e){body=e.why;failed=true;}catch(const std::exception&){body="INVALID_ARGUMENTS";failed=true;}
    item["type"]=J::string("text");item["text"]=J::string(body);items.a.push_back(item);result["content"]=items;result["isError"]=J::boolean(failed);if(modern)stamp_modern(result,false);reply["result"]=result;
   }else reply["error"]=error(-32601,"METHOD_NOT_FOUND");
  }catch(const Fail&){reply["id"]=id;reply["error"]=error(-32600,"INVALID_REQUEST");}catch(const std::exception&){reply["id"]=id;reply["error"]=error(-32700,"PARSE_OR_REQUEST_ERROR");}
  if(!notification)std::cout<<dump(reply)<<"\n"<<std::flush;
 }
 }catch(const Fail&e){std::cerr<<e.why<<"\n";return 2;}catch(const std::exception&){std::cerr<<"CONFIGURATION_INVALID\n";return 2;}return 0;
}
