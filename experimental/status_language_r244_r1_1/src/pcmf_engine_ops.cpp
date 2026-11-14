/*
 * PCMF Living Memory R14 - engine operations part 1: response envelopes,
 * frames, memory-state derivation, deterministic admission pipeline.
 * (Dispatcher and admin ops in pcmf_engine_admin.cpp)
 */
#include "pcmf_engine.h"
#include "pcmf_policy.h"
#include "pcmf_sha256.h"
#include "pcmf_util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include <sys/stat.h>
#include <unistd.h>

namespace pcmf {

/* ===================================================================== */
/* responses                                                             */
/* ===================================================================== */

std::string Engine::dump_line(const J&v){return dump(v);}

J Engine::resp(const std::string&op,const std::string&status,
               const std::string&reason,J data) const {
    J r=J::object();
    r["v"]=J::string(PCMF_PROTOCOL);
    r["op"]=J::string(op);
    r["status"]=J::string(status);
    if(!reason.empty())r["reason"]=J::string(reason);
    r["data"]=std::move(data);
    r["canonical_writer"]=J::string(canonical_writer_state());
    r["engine"]=J::string(PCMF_VERSION_STRING);
    return r;
}
J Engine::ok(const std::string&op,J data) const {
    return resp(op,"OK","",std::move(data));
}

/* ===================================================================== */
/* frame builder/verifier                                                */
/* ===================================================================== */

std::string Frame::build(const std::string&key,const std::string&client_id,
                         const std::string&op,const J&params,
                         const std::string&nonce_hex,long long ts){
    J req=J::object();
    req["v"]=J::string(PCMF_PROTOCOL);
    req["client"]=J::string(client_id);
    req["op"]=J::string(op);
    req["nonce"]=J::string(nonce_hex.empty()?random_hex(16):nonce_hex);
    req["ts"]=J::number(ts>0?ts:now_epoch());
    req["params"]=params;
    std::string payload=dump(req);
    return payload+"\n"+hmac_hex(key,payload+"\n")+"\n";
}

std::string Frame::parse_and_verify(const std::string&key,const std::string&frame){
    ensure(!frame.empty(),"EMPTY_FRAME");
    ensure(frame.size()<=8192+132+4,"FRAME_TOO_LARGE");
    size_t nl=frame.find('\n');
    ensure(nl!=std::string::npos&&nl+1<frame.size(),"FRAME_STRUCTURE");
    std::string payload=frame.substr(0,nl);
    std::string rest=frame.substr(nl+1);
    size_t nl2=rest.find('\n');
    ensure(nl2!=std::string::npos,"FRAME_TRAILING");
    std::string sig=rest.substr(0,nl2);
    ensure(rest.size()==nl2+1,"FRAME_TRAILING");
    ensure(is_hex(sig,32),"SIGNATURE_FORMAT");
    std::string expect=hmac_hex(key,payload+"\n");
    if(!pcmf_ct_equal(expect.data(),sig.data(),64))die("SOURCE_SIGNATURE_INVALID");
    return payload;
}

/* ===================================================================== */
/* memory states / retrieval helpers                                     */
/* ===================================================================== */

void Engine::derive_sets(const std::vector<J>&rows,
                         std::map<std::string,bool>&revoked_effective,
                         std::map<std::string,std::string>&superseded_by) const {
    std::map<std::string,bool> revoked_events;   /* revocation event ids */
    std::vector<std::pair<std::string,std::string>> revokes,corrections;
    for(const auto&e:rows){
        const std::string id=e.at("event_id").as_string();
        const std::string&cls=e.at("event_class").as_string();
        const J&content=e.at("content");
        if(cls=="REVOCATION"&&content.has("revokes"))
            revokes.emplace_back(id,content.at("revokes").as_string());
        else if(cls=="CORRECTION"&&content.has("correction_of"))
            corrections.emplace_back(id,content.at("correction_of").as_string());
    }
    /* A revocation is effective unless it is itself revoked. */
    for(const auto&rv:revokes){
        bool self_revoked=false;
        for(const auto&other:revokes)
            if(other.second==rv.first){self_revoked=true;break;}
        if(!self_revoked){
            revoked_effective[rv.second]=true;
            revoked_events[rv.first]=true;
        }
    }
    /* Newest effective correction per target wins (ledger order). */
    for(const auto&co:corrections){
        if(revoked_effective.count(co.first))continue;
        superseded_by[co.second]=co.first;
    }
}

std::string Engine::state_for_age(long long age) const {
    const long long hot=conf_ll("hot_days",7)*86400;
    const long long warm=conf_ll("warm_days",30)*86400;
    const long long cold=conf_ll("cold_days",180)*86400;
    if(age<=hot)return "HOT";
    if(age<=warm)return "WARM";
    if(age<=cold)return "COLD";
    return "DORMANT";
}

std::vector<Engine::SubjectState> Engine::subject_states(const std::vector<J>&rows) const {
    std::map<std::string,bool> revoked;std::map<std::string,std::string> superseded;
    derive_sets(rows,revoked,superseded);
    std::map<std::string,SubjectState> out;
    std::map<std::string,std::pair<std::string,std::string>> tier_overrides;
    struct ProjectLifecycle { long long seq=0; bool completed=false; };
    std::map<std::string,ProjectLifecycle> project_lifecycle;
    const long long now=now_epoch();
    for(const auto&e:rows){
        const std::string&cls=e.at("event_class").as_string();
        const std::string key=e.at("profile_id").as_string()+"|"+
            e.at("project_id").as_string()+"|"+
            e.at("subject_domain").as_string()+"|"+
            e.at("subject_key").as_string();
        SubjectState&s=out[key];
        s.profile=e.at("profile_id").as_string();
        s.project=e.at("project_id").as_string();
        s.domain=e.at("subject_domain").as_string();
        s.subject=e.at("subject_key").as_string();
        s.total++;
        const std::string id=e.at("event_id").as_string();
        if(revoked.count(id)){s.revoked++;continue;}
        if(superseded.count(id)){s.superseded++;continue;}
        if(cls=="TIER_CHANGE"){
            const J&c=e.at("content");
            if(c.has("target_event_id")&&c.has("target_tier"))
                tier_overrides[key]={c.at("target_event_id").as_string(),c.at("target_tier").as_string()};
            continue; /* metadata, never replaces subject content */
        }
        if(cls=="REVOCATION")continue;   /* meta event, not memory content */
        const std::string project_key=e.at("profile_id").as_string()+"|"+
            e.at("project_id").as_string();
        const long long seq=e.at("sequence_id").as_int();
        ProjectLifecycle&life=project_lifecycle[project_key];
        if(seq>=life.seq){
            life.seq=seq;
            life.completed=false;
            const J&c=e.at("content");
            if(c.has("project_lifecycle")&&c.at("project_lifecycle").t==J::Str&&
               c.at("project_lifecycle").as_string()=="COMPLETE")
                life.completed=true;
        }
        s.effective++;
        s.last_event_id=id;
        long long rec=0;
        if(epoch_from_utc(e.at("recorded_at").as_string(),rec))s.last_epoch=rec;
    }
    std::vector<SubjectState> list;
    list.reserve(out.size());
    for(auto&kv:out){
        kv.second.state=kv.second.effective==0?"EMPTY"
            :state_for_age(now-kv.second.last_epoch);
        auto override_it=tier_overrides.find(kv.first);
        if(override_it!=tier_overrides.end()&&
           override_it->second.first==kv.second.last_event_id&&
           kv.second.state!="EMPTY"&&kv.second.state!="DORMANT")
            kv.second.state=override_it->second.second;
        const std::string project_key=kv.second.profile+"|"+kv.second.project;
        auto life_it=project_lifecycle.find(project_key);
        if(life_it!=project_lifecycle.end()&&life_it->second.completed&&
           kv.second.state!="EMPTY"&&kv.second.state!="DORMANT")
            kv.second.state="COLD";
        list.push_back(kv.second);
    }
    return list;
}

/* ===================================================================== */
/* admission pipeline                                                    */
/* ===================================================================== */

bool Engine::content_duplicate(const Loaded&st,const J&params,
                               const std::string&note_hash) const {
    std::map<std::string,bool> revoked;std::map<std::string,std::string> sup;
    derive_sets(st.rows,revoked,sup);
    for(const auto&e:st.rows){
        const std::string&cls=e.at("event_class").as_string();
        if(cls=="CORRECTION"||cls=="REVOCATION")continue;
        if(e.at("profile_id").as_string()==params.at("profile").as_string()&&
           e.at("project_id").as_string()==params.at("project").as_string()&&
           e.at("subject_key").as_string()==params.at("subject").as_string()&&
           e.at("source_hash").as_string()==note_hash&&
           !revoked.count(e.at("event_id").as_string())&&
           !sup.count(e.at("event_id").as_string()))
            return true;
    }
    return false;
}

void Engine::check_subject_binding(const Loaded&st,const J&params){
    for(const auto&e:st.rows){
        if(e.at("profile_id").as_string()==params.at("profile").as_string()&&
           e.at("project_id").as_string()==params.at("project").as_string()&&
           e.at("subject_key").as_string()==params.at("subject").as_string()&&
           e.at("subject_domain").as_string()!=params.at("domain").as_string())
            die("SUBJECT_DOMAIN_CONFLICT");
    }
}

J Engine::admit_event(Loaded&st,const J&params,const ClientRecord&client,
                      const std::string&nonce,long long issued,
                      const std::string&privacy,const std::string&review_token){
    J event=build_event(params,client,nonce,issued,
                        sha256_hex(params.at("note").as_string()),privacy);
    if(!review_token.empty())event["content"]["review_token"]=J::string(review_token);
    /* Canonical R55 derivation order (matches verify_rows exactly):
     *   event_id   = sha256(canonical dump WITHOUT event_id, sequence_id,
     *                       previous_event_hash, event_hash)
     *   event_hash = sha256(canonical dump WITH event_id+sequence_id+
     *                       previous_event_hash but WITHOUT event_hash)     */
    J base=event;
    base["event_id"]=J::string(sha256_hex(dump(base)));
    Stream&s=st.streams[params.at("profile").as_string()+"|"+
                        params.at("project").as_string()];
    base["sequence_id"]=J::number(s.seq+1);
    base["previous_event_hash"]=J::string(s.last);
    base["event_hash"]=J::string(sha256_hex(dump(base)));
    st.rows.push_back(base);
    commit_event(st,base);   /* verifies chain+index+readback or dies */
    return base;
}

J Engine::normalize_observe_params(const J&params) const {
    if(params.has("profile")&&params.at("profile").t==J::Str&&
       !params.at("profile").as_string().empty())return params;
    std::string dflt;
    try{
        for(const auto&prof:profiles_.at("profiles").a){
            if(prof.has("default")&&prof.at("default").t==J::Bool&&
               prof.at("default").b){
                dflt=prof.at("profile_id").as_string();break;
            }
        }
    }catch(const Fail&){}
    ensure(!dflt.empty(),"PROFILE_REQUIRED");
    J out=params;
    out["profile"]=J::string(dflt);
    return out;
}

static bool pcmf_contains_disallowed_hold_status(const std::string&text){
    for(size_t i=0;i+4<=text.size();++i){
        const char h=(char)std::tolower((unsigned char)text[i]);
        const char o=(char)std::tolower((unsigned char)text[i+1]);
        const char l=(char)std::tolower((unsigned char)text[i+2]);
        const char d=(char)std::tolower((unsigned char)text[i+3]);
        if(h!='h'||o!='o'||l!='l'||d!='d')continue;
        const bool before=(i==0)||(!std::isalnum((unsigned char)text[i-1])&&text[i-1]!='_');
        const size_t j=i+4;
        const bool after=(j==text.size())||(!std::isalnum((unsigned char)text[j])||text[j]=='_');
        if(before&&after)return true;
    }
    return false;
}

ObserveOutcome Engine::observe_impl(const J&params_in,const ClientRecord&client,
                                    const std::string&nonce,long long issued,
                                    const ObserveOptions&opt){
    ObserveOutcome out;
    /* normalize: profile defaults to the configured default profile */
    const J params=normalize_observe_params(params_in);
    for(const char*f:{"project","subject","domain","event_class","note"})
        ensure(params.has(f)&&params.at(f).t==J::Str&&
               !params.at(f).as_string().empty(),
               std::string("OBSERVE_FIELD_REQUIRED:")+f);
    const std::string&note=params.at("note").as_string();
    const std::string note_hash=sha256_hex(note);
    if(!opt.skip_policy&&pcmf_contains_disallowed_hold_status(note)){
        out.status="REWORD_REQUIRED";
        out.reason="GENERIC_HOLD_LANGUAGE_NOT_ALLOWED";
        out.reword_required=true;
        return out;
    }
    if(params.has("project_lifecycle")){
        ensure(params.at("project_lifecycle").t==J::Str,
               "PROJECT_LIFECYCLE_INVALID");
        const std::string lifecycle=params.at("project_lifecycle").as_string();
        ensure(lifecycle=="COMPLETE","PROJECT_LIFECYCLE_INVALID");
        ensure(params.at("event_class").as_string()=="PROJECT_STATE"&&
               params.at("domain").as_string()=="BUILD_PROJECT",
               "PROJECT_LIFECYCLE_SCOPE_INVALID");
        ensure(client.role=="sol"||client.role=="owner",
               "PROJECT_LIFECYCLE_AUTHORITY_REQUIRED");
    }
    const std::string privacy=!opt.force_privacy.empty()
        ?opt.force_privacy
        :(params.has("privacy_class")&&params.at("privacy_class").t==J::Str&&
          !params.at("privacy_class").as_string().empty()
            ?params.at("privacy_class").as_string():std::string("INTERNAL_PROJECT"));

    FileLock lock;
    lock.acquire(p("STORE/writer.lock"));
    Loaded st=load_locked();
    if(!st.chain_ok||!st.index_ok){
        out.status="HOLD_INTEGRITY_OR_AUTHORITY";
        out.reason=st.error.empty()?"STORE_UNHEALTHY":st.error;
        return out;
    }
    check_subject_binding(st,params);
    if(!opt.skip_policy&&content_duplicate(st,params,note_hash)){
        out.status="DUPLICATE_NOOP";out.reason="CONTENT_DUPLICATE";
        out.events_post=(long long)st.rows.size();
        return out;
    }

    /* nonce replay is handled uniformly by Engine::request() for every op:
     * identical logical request with a used nonce -> idempotent NOOP;
     * reused nonce with different content -> NONCE_REPLAY_CONFLICT. Direct
     * observe() callers (tests) pass distinct nonces per logical event. */

    std::string admit_privacy=privacy;
    if(!opt.skip_policy){
        /* deterministic classifier */
        pcmf_input input{};
        const std::string proj=params.at("project").as_string();
        const std::string subj=params.at("subject").as_string();
        const std::string dom=params.at("domain").as_string();
        const std::string cls=params.at("event_class").as_string();
        input.project=proj.c_str();input.subject=subj.c_str();
        input.domain=dom.c_str();input.event_class=cls.c_str();
        input.note=note.c_str();
        input.scope_confirmed=1;
        input.source_authenticated=1;
        input.writer_authorized=writer_authorized()?1:0;
        input.integrity_healthy=1;
        /* ONLY the pre-existing authenticated ChatGPT connector client
         * receives length-neutral admission classification.
         * Sol and every other client retain existing policy behavior.
         */
        input.privacy_class=privacy.c_str();
        if(params.has("ref_event_id")&&params.at("ref_event_id").t==J::Str){
            const std::string ref=params.at("ref_event_id").as_string();
            input.ref_event_id=ref.c_str();
        }
        const pcmf_verdict v=(client.client_id=="forge_gpt_mcp")
            ?pcmf_decide_gpt(&input):pcmf_decide(&input);
        if(v.decision==PCMF_HOLD){
            out.status="HOLD_INTEGRITY_OR_AUTHORITY";out.reason=v.reason;return out;
        }
        if(v.decision==PCMF_REJECT){out.status="REJECT";out.reason=v.reason;return out;}
        if(v.decision==PCMF_DUPLICATE){
            out.status="DUPLICATE_NOOP";out.reason=v.reason;
            out.events_post=(long long)st.rows.size();return out;
        }
        if(v.decision==PCMF_REVIEW){
            /* Owner rules may admit sensitive content deterministically. */
            J rules=J::object();rules["rules"]=J::array();
            try{
                rules=parse(read_file_bounded(p("review/rules.json"),1ull*1024*1024));
            }catch(const Fail&){/* no rules file yet */}
            bool rule_found=false;std::string rule_decision;
            if(rules.has("rules")&&rules.at("rules").t==J::Arr){
                for(const auto&r:rules.at("rules").a){
                    if(r.t!=J::Obj)continue;
                    auto eqs=[&](const char*f,const std::string&val){
                        return r.has(f)&&r.at(f).t==J::Str&&
                            (r.at(f).as_string()=="*"||r.at(f).as_string()==val);
                    };
                    if(eqs("client",client.client_id)&&
                       eqs("profile",params.at("profile").as_string())&&
                       eqs("project",params.at("project").as_string())&&
                       eqs("subject",subj)&&eqs("domain",dom)&&eqs("event_class",cls)){
                        rule_found=true;
                        rule_decision=r.has("decision")&&
                            r.at("decision").as_string()=="deny"?"deny":"allow";
                        break;
                    }
                }
            }
            if(rule_found&&rule_decision=="deny"){
                out.status="REJECT";out.reason="SENSITIVE_CONTENT_DENIED_BY_OWNER";
                return out;
            }
            if(!rule_found){
                /* NEVER persist raw sensitive candidates: stub only. */
                const std::string token=hmac_hex(client_key_for("owner"),
                    "review|"+client.client_id+"|"+nonce);
                J stub=J::object();
                stub["token"]=J::string(token);
                stub["created_at"]=J::string(format_time(now_epoch()));
                stub["client"]=J::string(client.client_id);
                stub["profile"]=params.at("profile");
                stub["project"]=params.at("project");
                stub["subject"]=params.at("subject");
                stub["domain"]=params.at("domain");
                stub["event_class"]=params.at("event_class");
                stub["reason"]=J::string(v.reason);
                stub["note_hash"]=J::string(note_hash);
                stub["note_bytes"]=J::number((long long)note.size());
                atomic_replace(p("review/pending"),token+".json",dump(stub)+"\n");
                out.status="REVIEW_REQUIRED";out.reason=v.reason;
                out.review_token=token;
                return out;
            }
            admit_privacy="REVIEWED_SENSITIVE";
        }
        if(v.decision==PCMF_AUTO&&!conf_on("auto_admit",true)){
            out.status="REVIEW_REQUIRED";out.reason="AUTO_ADMIT_DISABLED";
            return out;
        }
        /* correction/revocation reference validation */
        if(cls=="CORRECTION"||cls=="REVOCATION"){
            if(!params.has("ref_event_id")||params.at("ref_event_id").t!=J::Str){
                out.status="REJECT";out.reason="CORRECTION_REFERENCE_REQUIRED";
                return out;
            }
            const std::string&ref=params.at("ref_event_id").as_string();
            bool found=false;
            for(const auto&e:st.rows)
                if(e.at("event_id").as_string()==ref&&
                   e.at("profile_id").as_string()==params.at("profile").as_string()&&
                   e.at("project_id").as_string()==params.at("project").as_string())
                {found=true;break;}
            if(!found){out.status="REJECT";out.reason="REFERENCE_NOT_FOUND_IN_STREAM";
                return out;}
        }
    }

    try{
        J event=admit_event(st,params,client,nonce,issued,admit_privacy,opt.review_token);
        out.status="OK";out.reason="ADMITTED";
        out.event_id=event.at("event_id").as_string();
        out.events_post=(long long)st.rows.size();
        out.stored=true;
    }catch(const Fail&e){
        out.status="HOLD_INTEGRITY_OR_AUTHORITY";out.reason=e.why;return out;
    }

    return out;
}

ObserveOutcome Engine::observe(const J&params,const ClientRecord&client,
                               const std::string&nonce,long long issued){
    ObserveOptions opt;
    return observe_impl(params,client,nonce,issued,opt);
}

} // namespace pcmf
