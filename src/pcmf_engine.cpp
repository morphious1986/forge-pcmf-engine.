/*
 * PCMF Living Memory R14 - engine core: root lifecycle, config, store
 * primitives, clients, nonce ledger. (Ops/dispatcher in pcmf_engine_ops.cpp)
 */
#include "pcmf_engine.h"
#include "pcmf_policy.h"
#include "pcmf_sha256.h"
#include "pcmf_util.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#include <sys/stat.h>
#include <unistd.h>

namespace pcmf {

/* ===================================================================== */
/* root lifecycle                                                        */
/* ===================================================================== */

bool Engine::looks_initialized(const std::string&root){
    return file_exists(root+"/.pcmf_root");
}

void Engine::init_root(const std::string&root_in,
                       const std::string&profile,const std::string&project){
    std::string root=root_in;
    ensure(!root.empty()&&root[0]=='/',"ROOT_NOT_ABSOLUTE");
    ensure(!contains_component_dotdot(root),"ROOT_PATH_INVALID");
    ensure(!looks_initialized(root),"ROOT_ALREADY_INITIALIZED");
    ensure(is_name(profile,2,95)&&is_name(project,2,95),"INVALID_DEFAULT_SCOPE");
    ensure_dir(root,0700);
    require_private_dir(root);
    ensure_dir(root+"/STORE",0700);
    ensure_dir(root+"/keys",0700);
    ensure_dir(root+"/keys/clients",0700);
    ensure_dir(root+"/config",0700);
    ensure_dir(root+"/review",0700);
    ensure_dir(root+"/review/pending",0700);
    ensure_dir(root+"/review/authorized",0700);
    ensure_dir(root+"/review/approved",0700);
    ensure_dir(root+"/review/rejected",0700);
    ensure_dir(root+"/state",0700);
    ensure_dir(root+"/backups",0700);
    ensure_dir(root+"/proofs",0700);

    /* marker */
    J marker=J::object();
    marker["kind"]=J::string("PCMF_LIVING_MEMORY_ROOT");
    marker["version"]=J::string(PCMF_VERSION_STRING);
    marker["root_id"]=J::string(random_hex(16));
    marker["created_at"]=J::string(format_time(now_epoch()));
    marker["canonical_writer"]=J::string(PCMF_CANONICAL_HOLD);
    write_file_private(root+"/.pcmf_root",dump(marker)+"\n");

    /* owner key + record */
    write_file_private(root+"/keys/owner.key",[](){
        std::string k=random_hex(32);
        std::string raw;raw.resize(32);
        uint8_t buf[32];
        ensure(pcmf_from_hex(k.c_str(),buf,32),"KEY_DERIV_FAILED");
        memcpy(raw.data(),buf,32);
        return raw;
    }());
    J owner=J::object();
    owner["client_id"]=J::string("owner");
    owner["role"]=J::string("owner");
    owner["enabled"]=J::boolean(true);
    owner["created_at"]=J::string(format_time(now_epoch()));
    J oscopes=J::object();
    oscopes["profiles"]=J::array();oscopes["profiles"].a.push_back(J::string("*"));
    oscopes["projects"]=J::array();oscopes["projects"].a.push_back(J::string("*"));
    oscopes["subjects"]=J::array();oscopes["subjects"].a.push_back(J::string("*"));
    oscopes["event_classes"]=J::array();oscopes["event_classes"].a.push_back(J::string("*"));
    oscopes["max_privacy"]=J::string("REVIEWED_SENSITIVE");
    owner["scopes"]=oscopes;
    write_file_private(root+"/keys/owner.json",dump(owner)+"\n");

    /* root config */
    std::string conf=
        "# PCMF Living Memory R14 root configuration\n"
        "hot_days=7\n"
        "warm_days=30\n"
        "cold_days=180\n"
        "ts_window_past=300\n"
        "ts_window_future=120\n"
        "retrieval_default_limit=5\n"
        "auto_admit=on\n"
        "sol_integration=disabled\n"
        "writer_authority=hold\n";
    write_file_private(root+"/config/pcmf.conf",conf);

    /* profiles */
    J profiles=J::object();
    J plist=J::array();
    J prof=J::object();
    prof["profile_id"]=J::string(profile);
    prof["default"]=J::boolean(true);
    J projects=J::array();projects.a.push_back(J::string(project));
    prof["projects"]=projects;
    plist.a.push_back(prof);
    profiles["profiles"]=plist;
    write_file_private(root+"/config/profiles.json",dump(profiles)+"\n");

    /* empty store (R55 lineage names preserved) */
    write_file_private(root+"/STORE/local_memory.jsonl","");
    J idx=J::object();
    idx["schema"]=J::string("pcmf.deterministic.collection_index.v1");
    idx["derived"]=J::boolean(true);
    idx["authority"]=J::string("NONE");
    idx["ledger_sha256"]=J::string(sha256_hex(""));
    idx["event_count"]=J::number(0);
    idx["streams"]=J::object();
    idx["subjects"]=J::object();
    write_file_private(root+"/STORE/local_index.json",dump(idx)+"\n");
    write_file_private(root+"/STORE/writer.lock","");
    std::string nonce_db="";
    write_file_private(root+"/state/nonces.db",nonce_db);
}

/* ===================================================================== */
/* construction / paths / config                                         */
/* ===================================================================== */

Engine::Engine(std::string root):root_(std::move(root)){
    ensure(!root_.empty()&&root_[0]=='/',"ROOT_NOT_ABSOLUTE");
    ensure(mkpath_absolute(root_),"ROOT_RESOLVE_FAILED");
    require_private_dir(root_);
    ensure(looks_initialized(root_),"ROOT_NOT_INITIALIZED_RUN_PCMF_INIT");
    /* marker */
    try{
        J m=parse(read_file_bounded(p(".pcmf_root"),4096));
        root_id_=m.has("root_id")?m.at("root_id").as_string():std::string("UNKNOWN");
        ensure(m.has("kind")&&m.at("kind").as_string()=="PCMF_LIVING_MEMORY_ROOT",
               "ROOT_MARKER_INVALID");
    }catch(const Fail&){throw;}
    load_config();
}

std::string Engine::p(const std::string&rel) const { return root_+"/"+rel; }

std::string Engine::canonical_writer_state() const {
    auto it=conf_.find("writer_authority");
    if(it==conf_.end()||it->second!="authorized_r243")
        return PCMF_CANONICAL_HOLD;
    try{
        J r=parse(read_file_bounded(
            p("MIGRATION_RECEIPT_EXAMPLE_NODE_20261102.json"),131072));
        if(r.t!=J::Obj)return PCMF_CANONICAL_HOLD;
        auto eq=[&](const char*k,const char*v){
            return r.has(k)&&r.at(k).t==J::Str&&r.at(k).as_string()==v;
        };
        if(!eq("schema","forge.pcmf.example_node.legacy_to_r16_migration.v2"))
            return PCMF_CANONICAL_HOLD;
        if(!r.has("new_root_id")||r.at("new_root_id").t!=J::Str||
           r.at("new_root_id").as_string()!=root_id_)
            return PCMF_CANONICAL_HOLD;
        if(!r.has("source_events")||r.at("source_events").t!=J::Num||
           r.at("source_events").as_int()<0)
            return PCMF_CANONICAL_HOLD;
        if(!r.has("source_media_modified")||
           r.at("source_media_modified").t!=J::Bool||
           r.at("source_media_modified").b)
            return PCMF_CANONICAL_HOLD;
        if(!r.has("acceptance")||r.at("acceptance").t!=J::Obj)
            return PCMF_CANONICAL_HOLD;
        const J&a=r.at("acceptance");
        if(!a.has("status_healthy")||a.at("status_healthy").t!=J::Bool||
           !a.at("status_healthy").b)
            return PCMF_CANONICAL_HOLD;
        if(!a.has("store_verify")||a.at("store_verify").t!=J::Str||
           a.at("store_verify").as_string()!="PASS")
            return PCMF_CANONICAL_HOLD;
        if(!a.has("store_replay")||a.at("store_replay").t!=J::Str||
           a.at("store_replay").as_string()!="PASS_READBACK_IDENTICAL")
            return PCMF_CANONICAL_HOLD;
        return PCMF_CANONICAL_AUTH;
    }catch(...){
        return PCMF_CANONICAL_HOLD;
    }
}

bool Engine::writer_authorized() const {
    return canonical_writer_state()==PCMF_CANONICAL_AUTH;
}

void Engine::load_config(){
    conf_.clear();
    std::string bytes=read_file_bounded(p("config/pcmf.conf"),65536);
    for(const auto&line:split_lines(bytes)){
        std::string l=trim(line);
        if(l.empty()||l[0]=='#')continue;
        auto eq=l.find('=');
        if(eq==std::string::npos)continue;
        conf_[trim(l.substr(0,eq))]=trim(l.substr(eq+1));
    }
    try{
        profiles_=parse(read_file_bounded(p("config/profiles.json"),262144));
        ensure(profiles_.t==J::Obj,"PROFILES_NOT_OBJECT");
    }catch(const Fail&){die("PROFILES_UNREADABLE");}
}

long long Engine::conf_ll(const char*k,long long dflt) const {
    auto i=conf_.find(k);
    if(i==conf_.end())return dflt;
    const std::string&v=i->second;
    if(v.empty()||v.size()>9)return dflt;
    long long out=0;
    for(char c:v){
        if(c<'0'||c>'9')return dflt;
        out=out*10+(c-'0');
    }
    return out;
}
bool Engine::conf_on(const char*k,bool dflt) const {
    auto i=conf_.find(k);
    if(i==conf_.end())return dflt;
    return i->second=="on"||i->second=="true"||i->second=="enabled";
}
long long Engine::window_past() const {return conf_ll("ts_window_past",300);}
long long Engine::window_future() const {return conf_ll("ts_window_future",120);}

/* ===================================================================== */
/* store primitives (R55 lineage, behavior-identical to verified R10)    */
/* ===================================================================== */

std::vector<J> Engine::read_events(const std::string&bytes) const {
    std::vector<J> rows;size_t start=0;
    while(start<bytes.size()){
        size_t end=bytes.find('\n',start);
        ensure(end!=std::string::npos&&end>start,"LEDGER_TORN_LINE");
        std::string line=bytes.substr(start,end-start);
        ensure(line.size()<8192,"LEDGER_LINE_LIMIT");
        try{
            J row=parse(line);
            ensure(row.t==J::Obj&&dump(row)==line,"LEDGER_NOT_CANONICAL");
            rows.push_back(std::move(row));
        }catch(const Fail&){throw;}
        catch(const std::exception&){die("LEDGER_NOT_CANONICAL");}
        ensure(rows.size()<=100000,"LEDGER_COUNT_LIMIT");
        start=end+1;
    }
    return rows;
}

void Engine::verify_rows(const std::vector<J>&rows) const {
    std::map<std::string,Stream> streams;
    std::map<std::string,bool> seen;
    for(auto&e:rows){
        ensure(e.t==J::Obj,"EVENT_NOT_OBJECT");
        J base=e;base.o.erase("event_id");base.o.erase("event_hash");
        base.o.erase("sequence_id");base.o.erase("previous_event_hash");
        std::string eid=sha256_hex(dump(base));
        ensure(e.at("event_id").as_string()==eid,"EVENT_ID_MISMATCH");
        ensure(!seen[eid],"EVENT_DUPLICATE");seen[eid]=true;
        const std::string sk=e.at("profile_id").as_string()+"|"+e.at("project_id").as_string();
        Stream&st=streams[sk];
        ensure(e.at("sequence_id").as_int()==st.seq+1,"SEQUENCE_MISMATCH");
        ensure(e.at("previous_event_hash").as_string()==st.last,"PREVIOUS_HASH_MISMATCH");
        J payload=e;payload.o.erase("event_hash");
        std::string eh=sha256_hex(dump(payload));
        ensure(e.at("event_hash").as_string()==eh,"EVENT_HASH_MISMATCH");
        st.seq++;st.last=eh;
    }
}

J Engine::make_index(const std::vector<J>&events,const std::string&ledger_sha) const {
    J idx=J::object();idx["schema"]=J::string("pcmf.deterministic.collection_index.v1");
    idx["derived"]=J::boolean(true);idx["authority"]=J::string("NONE");
    idx["ledger_sha256"]=J::string(ledger_sha);
    idx["event_count"]=J::number((long long)events.size());
    idx["streams"]=J::object();idx["subjects"]=J::object();
    for(auto&e:events){
        std::string stream=e.at("profile_id").as_string()+"|"+e.at("project_id").as_string();
        std::string dom=e.has("subject_domain")?e.at("subject_domain").as_string():std::string("LEGACY_UNCLASSIFIED");
        std::string subject=stream+"|"+dom+"|"+e.at("subject_key").as_string();
        J st=J::object();st["last_sequence_id"]=e.at("sequence_id");
        st["last_event_hash"]=e.at("event_hash");idx["streams"][stream]=st;
        J&target=idx["subjects"][subject];
        if(target.t==J::Null)target=J::array();
        J ent=J::object();
        for(const char*key:{"sequence_id","event_id","event_hash","event_class",
                            "source_ref","observed_at","trust_class","evidence_strength"})
            ent[key]=e.at(key);
        ent["subject_domain"]=J::string(dom);
        ent["source_generation"]=e.has("source_generation")?e.at("source_generation"):J();
        target.a.push_back(ent);
    }
    return idx;
}

Engine::Loaded Engine::load_locked(){
    Loaded st;
    st.ledger_bytes=read_file_bounded(p("STORE/local_memory.jsonl"),64ull*1024*1024);
    st.index_bytes=read_file_bounded(p("STORE/local_index.json"),64ull*1024*1024);
    try{
        st.rows=read_events(st.ledger_bytes);
        verify_rows(st.rows);
        st.chain_ok=true;
    }catch(const Fail&e){st.error=e.why;return st;}
    try{
        J expect=make_index(st.rows,sha256_hex(st.ledger_bytes));
        J actual=parse(st.index_bytes);
        st.index_ok=dump(actual)==dump(expect);
        if(!st.index_ok)st.error="INDEX_PREIMAGE_MISMATCH";
        for(auto&e:st.rows){
            std::string sk=e.at("profile_id").as_string()+"|"+e.at("project_id").as_string();
            Stream&s=st.streams[sk];
            s.seq=e.at("sequence_id").as_int();
            s.last=e.at("event_hash").as_string();
        }
    }catch(const Fail&e){st.error=e.why;return st;}
    return st;
}

J Engine::build_event(const J&params,const ClientRecord&client,const std::string&nonce,
                      long long issued,const std::string&note_hash,
                      const std::string&privacy_class){
    J e=J::object();
    e["schema"]=J::string("pcmf.deterministic.event.v2");
    e["event_class"]=params.at("event_class");
    e["profile_id"]=params.at("profile");
    e["project_id"]=params.at("project");
    e["subject_key"]=params.at("subject");
    e["subject_domain"]=params.at("domain");
    const bool owner=(client.role=="owner");
    e["source_type"]=J::string(owner?"OWNER_LOCAL_SIGNED_NOT_CHATGPT"
                                    :"LOCAL_CLIENT_SIGNED_NOT_CHATGPT");
    e["source_ref"]=J::string("pcmf://"+client.client_id+"/"+nonce);
    e["source_generation"]=J::string("R14_"+nonce);
    e["source_hash"]=J::string(note_hash);
    e["epistemic_class"]=J::string("HISTORICAL_STATE");
    e["trust_class"]=J::string(owner?"OWNER_OBSERVED":"VERIFIED_TOOL_RESULT");
    e["privacy_class"]=J::string(privacy_class);
    e["evidence_strength"]=J::string(client.role=="test"?"SYNTHETIC_TEST":
                                     owner?"OWNER_OBSERVED":"SIGNED_LOCAL_OBSERVATION");
    e["observed_at"]=J::string(format_time(issued));
    e["event_time"]=J::string(format_time(issued));
    e["recorded_at"]=J::string(format_time(now_epoch()));
    J content=J::object();
    content["summary"]=params.at("note");
    content["action_authority"]=J::string("NONE");
    content["origin"]=J::string("LOCAL_CLIENT_NOT_CHATGPT");
    const std::string&cls=params.at("event_class").as_string();
    if(cls=="CORRECTION"||cls=="REVOCATION")
        content[cls=="CORRECTION"?"correction_of":"revokes"]=params.at("ref_event_id");
    if(params.has("project_lifecycle")&&params.at("project_lifecycle").t==J::Str)
        content["project_lifecycle"]=params.at("project_lifecycle");
    e["content"]=content;
    e["policy_id"]=J::string("PCMF_LIVING_MEMORY_R14");
    return e;
}

void Engine::commit_event(Loaded&st,const J&event){
    /* caller holds writer.lock and has verified st */
    verify_rows(st.rows);
    std::string prior=st.ledger_bytes;
    std::string after=prior+dump(event)+"\n";
    J newindex=make_index(st.rows,sha256_hex(after));
    const std::string indexstr=dump(newindex)+"\n";
    /* Ledger first; an interrupted pair fails closed on the next writer and
     * the index is regenerated from the verified ledger by store.recover. */
    atomic_replace(p("STORE"),"local_memory.jsonl",after);
    if(std::getenv("PCMF_R14_TEST_CRASH_AFTER_LEDGER_RENAME"))std::_Exit(97);
    atomic_replace(p("STORE"),"local_index.json",indexstr);
    /* readback verification */
    Loaded post=load_locked();
    ensure(post.chain_ok&&post.index_ok,"POST_COMMIT_VERIFY_FAILED");
    ensure(post.ledger_bytes==after,"POST_LEDGER_MISMATCH");
    st=post;
}

/* ===================================================================== */
/* clients                                                               */
/* ===================================================================== */

ClientRecord Engine::load_client(const std::string&client_id,bool&found) const {
    found=false;
    std::string path=(client_id=="owner")?p("keys/owner.json")
                                          :p("keys/clients/"+client_id+".json");
    if(!file_exists(path))return ClientRecord{};
    J rec;
    try{rec=parse(read_file_bounded(path,65536));}
    catch(const Fail&){return ClientRecord{};}
    ClientRecord c;
    try{
        c.client_id=rec.at("client_id").as_string();
        c.role=rec.at("role").as_string();
        c.enabled=rec.has("enabled")&&rec.at("enabled").t==J::Bool&&rec.at("enabled").b;
        c.created_at=rec.has("created_at")?rec.at("created_at").as_string():std::string("");
        c.revoked_at=rec.has("revoked_at")&&rec.at("revoked_at").t==J::Str
                    ?rec.at("revoked_at").as_string():std::string("");
        c.scopes=rec.at("scopes");
        c.raw=rec;
        found=true;
    }catch(const Fail&){return ClientRecord{};}
    return c;
}

std::string Engine::client_key_for(const std::string&client_id) const {
    std::string path=(client_id=="owner")?p("keys/owner.key")
                                          :p("keys/clients/"+client_id+".key");
    require_private_file(path,32);
    std::string key=read_file_bounded(path,64);
    ensure(key.size()==32,"KEY_SIZE_INVALID");
    return key;
}

static bool scope_match(const J&scopes,const char*field,const std::string&value){
    if(!scopes.has(field)||scopes.at(field).t!=J::Arr)return false;
    for(const auto&v:scopes.at(field).a)
        if(v.t==J::Str&&(v.s=="*"||v.s==value))return true;
    return false;
}
static bool scope_subject(const J&scopes,const std::string&subject){
    if(!scopes.has("subjects")||scopes.at("subjects").t!=J::Arr)return false;
    for(const auto&v:scopes.at("subjects").a){
        if(v.t!=J::Str)continue;
        if(v.s=="*")return true;
        if(!v.s.empty()&&v.s.back()=='*'&&subject.rfind(v.s.substr(0,v.s.size()-1),0)==0)return true;
        if(v.s==subject)return true;
    }
    return false;
}

void Engine::require_scope(const ClientRecord&c,const J&params,bool hot) const {
    if(c.role=="owner")return;
    const J&s=c.scopes;
    if(hot){
        /* Retrieval: declared dimensions are scope-checked; non-owner clients
         * must declare profile and project explicitly. */
        ensure(params.has("profile")&&params.at("profile").t==J::Str,
               "SCOPE_PROFILE_REQUIRED");
        ensure(scope_match(s,"profiles",params.at("profile").as_string()),
               "SCOPE_PROFILE_NOT_AUTHORIZED");
        ensure(params.has("project")&&params.at("project").t==J::Str,
               "SCOPE_PROJECT_REQUIRED");
        ensure(scope_match(s,"projects",params.at("project").as_string()),
               "SCOPE_PROJECT_NOT_AUTHORIZED");
        if(params.has("subject")&&params.at("subject").t==J::Str)
            ensure(scope_subject(s,params.at("subject").as_string()),
                   "SCOPE_SUBJECT_NOT_AUTHORIZED");
        return;
    }
    ensure(params.has("profile")&&params.at("profile").t==J::Str,
           "SCOPE_PROFILE_REQUIRED");
    if(!scope_match(s,"profiles",params.at("profile").as_string()))
        die("SCOPE_PROFILE_NOT_AUTHORIZED");
    ensure(params.has("project")&&params.at("project").t==J::Str,
           "SCOPE_PROJECT_REQUIRED");
    if(!scope_match(s,"projects",params.at("project").as_string()))
        die("SCOPE_PROJECT_NOT_AUTHORIZED");
    if(params.has("subject")&&params.at("subject").t==J::Str)
        ensure(scope_subject(s,params.at("subject").as_string()),
               "SCOPE_SUBJECT_NOT_AUTHORIZED");
    if(params.has("event_class")&&params.at("event_class").t==J::Str){
        const std::string&cls=params.at("event_class").as_string();
        if(!scope_match(s,"event_classes",cls))
            die("SCOPE_EVENT_CLASS_NOT_AUTHORIZED");
    }
    if(params.has("privacy_class")&&params.at("privacy_class").t==J::Str){
        const std::string&pc=params.at("privacy_class").as_string();
        if(pc=="REVIEWED_SENSITIVE")die("PRIVACY_CLASS_NOT_AUTHORIZED");
    }
    if(c.role=="sol"&&conf_.count("sol_integration")&&
       conf_.at("sol_integration")!="enabled")
        die("SOL_INTEGRATION_DISABLED");
}

/* ===================================================================== */
/* nonce ledger                                                          */
/* ===================================================================== */

std::vector<Engine::NonceRec> Engine::load_nonces(){
    std::vector<NonceRec> out;
    if(!file_exists(p("state/nonces.db")))return out;
    std::string bytes=read_file_bounded(p("state/nonces.db"),16ull*1024*1024);
    const long long keep=window_past()+86400;
    const long long cutoff=now_epoch()-keep;
    for(const auto&line:split_lines(bytes)){
        if(line.empty())continue;
        try{
            J r=parse(line);
            NonceRec n;
            n.nonce=r.at("nonce").as_string();
            n.client=r.at("client").as_string();
            n.content_hash=r.has("content_hash")?r.at("content_hash").as_string():std::string("");
            n.ts=r.at("ts").as_int();
            if(n.ts>=cutoff)out.push_back(std::move(n));
        }catch(const Fail&){die("NONCE_DB_CORRUPT");}
    }
    ensure(out.size()<=50000,"NONCE_DB_OVERFLOW");
    return out;
}

void Engine::save_nonces(const std::vector<NonceRec>&recs){
    std::string bytes;
    for(const auto&n:recs){
        J r=J::object();
        r["nonce"]=J::string(n.nonce);
        r["client"]=J::string(n.client);
        r["content_hash"]=J::string(n.content_hash);
        r["ts"]=J::number(n.ts);
        bytes+=dump(r)+"\n";
    }
    atomic_replace(p("state"),"nonces.db",bytes);
}

} // namespace pcmf
