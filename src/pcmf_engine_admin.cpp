/*
 * PCMF Living Memory R14 - engine operations part 2: PCMF_IPv1 request
 * dispatcher (authentication, replay prevention, authorization), HOT
 * retrieval, client registry, review queue, integrity ops, proofs, backups.
 */
#include "pcmf_engine.h"
#include "pcmf_policy.h"
#include "pcmf_sha256.h"
#include "pcmf_util.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pcmf {

/* Create all parent directories of a relative component path under base. */
static void ensure_parents(const std::string&base,const std::string&rel){
    std::string acc;
    for(size_t i=0;i<rel.size();i++){
        if(rel[i]=='/'){
            ensure_dir(base+"/"+acc,0700);
            acc+='/';
        }else acc+=rel[i];
    }
}

/* ===================================================================== */
/* nonce / replay handling (uniform for every authenticated op)          */
/* ===================================================================== */

static std::string request_identity_hash(const std::string&op,
                                         const std::string&client,
                                         const J&params){
    return sha256_hex(op+"|"+client+"|"+dump(params));
}

/* ===================================================================== */
/* request dispatcher                                                    */
/* ===================================================================== */

std::string Engine::request(const std::string&payload_line,const std::string&sig_hex){
    const std::string op_unknown="UNKNOWN";
    try{
        ensure(payload_line.size()>=2&&payload_line.size()<=8192,"INVALID_REQUEST_SIZE");
        ensure(is_hex(sig_hex,32),"SIGNATURE_FORMAT");
        J req;
        try{
            req=parse(payload_line);
        }catch(const std::exception&){
            die("REQUEST_NOT_VALID_JSON");
        }
        ensure(req.t==J::Obj,"REQUEST_NOT_OBJECT");
        ensure(req.has("v")&&req.at("v").as_string()==PCMF_PROTOCOL,"PROTOCOL_VERSION_UNSUPPORTED");
        const std::string client_id=req.has("client")?req.at("client").as_string():"";
        const std::string op=req.has("op")?req.at("op").as_string():"";
        const std::string nonce=req.has("nonce")?req.at("nonce").as_string():"";
        ensure(is_name(client_id,3,64)||client_id=="owner","INVALID_CLIENT_ID");
        ensure(!op.empty()&&op.size()<=32,"INVALID_OP");
        for(char c:op)
            ensure(isalnum((unsigned char)c)||c=='.'||c=='_',"INVALID_OP");
        ensure(is_hex(nonce,16),"ENVELOPE_NONCE_REQUIRED");
        ensure(req.has("ts")&&req.at("ts").t==J::Num,"ENVELOPE_TIME_REQUIRED");
        const long long ts=req.at("ts").as_int();
        ensure(req.has("params")&&req.at("params").t==J::Obj,"PARAMS_REQUIRED");

        bool found=false;
        ClientRecord client=load_client(client_id,found);
        ensure(found,"UNKNOWN_CLIENT");
        ensure(client.enabled,"CLIENT_REVOKED");

        /* source authentication (HMAC over payload incl. trailing newline) */
        std::string key=client_key_for(client_id);
        const std::string expect=hmac_hex(key,payload_line+"\n");
        ensure(pcmf_ct_equal(expect.data(),sig_hex.data(),64),
               "SOURCE_SIGNATURE_INVALID");
        cleanse(key);

        /* freshness window */
        const long long now=now_epoch();
        ensure(ts>now-window_past()-1&&ts<now+window_future()+1,
               "EXPIRED_OR_FUTURE_REQUEST");

        /* replay prevention: identical logical request with a used nonce is an
         * idempotent NOOP; a reused nonce with different content is a conflict. */
        const std::string identity=request_identity_hash(op,client_id,req.at("params"));
        nonces_=load_nonces();
        for(const auto&n:nonces_){
            if(n.nonce==nonce){
                if(n.client==client_id&&n.content_hash==identity){
                    return dump_line(resp(op,"DUPLICATE_NOOP","IDEMPOTENT_REPLAY",
                        [](){J d=J::object();d["idempotent"]=J::boolean(true);return d;}()));
                }
                return dump_line(resp(op,"HOLD_INTEGRITY_OR_AUTHORITY",
                    "NONCE_REPLAY_CONFLICT",J::object()));
            }
        }

        /* authorization classes */
        static const char*const OWNER_OPS[]={
            "client.register","client.revoke","client.list",
            "review.list","review.resolve",
            "store.verify","store.replay","store.recover",
            "backup.create","backup.verify","backup.restore",
            "config.get","config.set","sol.enable","sol.disable","profiles.add","tier.commit"};
        static const char*const CLIENT_OPS[]={
            "ping","health.get","hot.get","observe.submit","review.submit",
            "memory.state","proof.get","tier.request","tier.set"};
        auto among=[](const char*const*items,size_t n,const std::string&v){
            for(size_t i=0;i<n;i++)if(v==items[i])return true;
            return false;
        };
        const bool owner_op=among(OWNER_OPS,sizeof OWNER_OPS/sizeof *OWNER_OPS,op);
        const bool client_op=among(CLIENT_OPS,sizeof CLIENT_OPS/sizeof *CLIENT_OPS,op);
        if(!owner_op&&!client_op)
            return dump_line(resp(op,"HOLD_INTEGRITY_OR_AUTHORITY","UNKNOWN_OP",J::object()));
        if(owner_op&&client.role!="owner")
            return dump_line(resp(op,"DENIED","OWNER_AUTHORITY_REQUIRED",J::object()));

        J data=J::object();
        std::string status="OK",reason;
        if(op=="ping"){
            data["pong"]=J::boolean(true);
            data["version"]=J::string(PCMF_VERSION_STRING);
            data["role"]=J::string(client.role);
        }else if(op=="health.get"){
            return dump_line(ok(op,parse(status_json())));
        }else if(op=="hot.get"){
            try{
                /* no profile defaulting here: absent profile = all authorized */
                return dump_line(ok(op,hot_retrieve(req.at("params"),client)));
            }catch(const Fail&e){
                return dump_line(resp(op,"DENIED",e.why,J::object()));
            }
        }else if(op=="observe.submit"){
            try{
                const J np=normalize_observe_params(req.at("params"));
                require_scope(client,np,false);
                const ObserveOutcome o=observe(np,client,nonce,ts);
                data["stored"]=J::boolean(o.stored);
                data["admission_status"]=J::string(o.status);
                if(!o.reason.empty())data["admission_reason"]=J::string(o.reason);
                if(!o.event_id.empty())data["event_id"]=J::string(o.event_id);
                if(o.events_post>0)data["events_post"]=J::number(o.events_post);
                if(!o.review_token.empty())data["review_token"]=J::string(o.review_token);
                status=(o.status=="OK")?"OK":o.status;
                reason=o.reason;
            }catch(const Fail&e){
                return dump_line(resp(op,"DENIED",e.why,J::object()));
            }
        }else if(op=="review.submit"){
            try{
                data=op_review_submit(req.at("params"),client,nonce,ts);
            }catch(const Fail&e){
                return dump_line(resp(op,"DENIED",e.why,J::object()));
            }
        }else if(op=="tier.commit"){
            try{
                const J&tp=req.at("params");
                ensure(tp.t==J::Obj&&tp.o.size()==7,"TIER_COMMIT_FIELDS_INVALID");
                for(const char*k:{"subject","domain","profile","project","ref_event_id","tier","reason"})
                    ensure(tp.has(k)&&tp.at(k).t==J::Str,"TIER_COMMIT_FIELD_REQUIRED");
                const std::string subject=tp.at("subject").s;
                const std::string domain=tp.at("domain").s;
                const std::string profile=tp.at("profile").s;
                const std::string project=tp.at("project").s;
                const std::string target=tp.at("ref_event_id").s;
                const std::string tier=tp.at("tier").s;
                const std::string why=tp.at("reason").s;
                ensure(is_name(subject,2,95)&&is_name(domain,2,95)&&is_name(profile,2,95)&&is_name(project,2,95),"TIER_SUBJECT_INVALID");
                ensure(is_hex(target,32),"TIER_REFERENCE_INVALID");
                ensure(tier=="HOT"||tier=="WARM"||tier=="COLD","TIER_INVALID");
                ensure(why.size()>=3&&why.size()<=700,"TIER_REASON_INVALID");
                ensure(writer_authorized(),"WRITER_AUTHORITY_UNVERIFIED");
                FileLock lock;lock.acquire(p("STORE/writer.lock"));
                Loaded st=load_locked();
                ensure(st.chain_ok&&st.index_ok,"TIER_STORE_UNHEALTHY");
                const auto states=subject_states(st.rows);
                bool matched=false;
                for(const auto&ss:states){
                    if(ss.profile==profile&&ss.project==project&&ss.domain==domain&&ss.subject==subject){
                        ensure(ss.last_event_id==target,"TIER_STALE_REFERENCE");
                        ensure(ss.state!="EMPTY"&&ss.state!="DORMANT","TIER_INACTIVE_SUBJECT");
                        matched=true;break;
                    }
                }
                ensure(matched,"TIER_SUBJECT_NOT_FOUND");
                J ep=J::object();
                ep["profile"]=J::string(profile);ep["project"]=J::string(project);
                ep["domain"]=J::string(domain);ep["subject"]=J::string(subject);
                ep["event_class"]=J::string("TIER_CHANGE");
                ep["note"]=J::string(why);
                J event=build_event(ep,client,nonce,ts,sha256_hex(why),"INTERNAL_PROJECT");
                event["content"]["action_authority"]=J::string("OWNER_SIGNED");
                event["content"]["target_event_id"]=J::string(target);
                event["content"]["target_tier"]=J::string(tier);
                J base=event;
                base["event_id"]=J::string(sha256_hex(dump(base)));
                Stream&stream=st.streams[profile+"|"+project];
                base["sequence_id"]=J::number(stream.seq+1);
                base["previous_event_hash"]=J::string(stream.last);
                base["event_hash"]=J::string(sha256_hex(dump(base)));
                st.rows.push_back(base);
                commit_event(st,base);
                data["stored"]=J::boolean(true);
                data["event_id"]=base.at("event_id");
                data["target_event_id"]=J::string(target);
                data["effective_tier"]=J::string(tier);
                data["owner_role"]=J::string(client.role);
            }catch(const Fail&e){
                return dump_line(resp(op,"DENIED",e.why,J::object()));
            }
        }else if(op=="tier.set"){
            try{
                const J&tp=req.at("params");
                ensure(tp.t==J::Obj&&tp.o.size()==6,"TIER_SET_FIELDS_INVALID");
                for(const char*k:{"subject","domain","profile","project","tier","reason"})
                    ensure(tp.has(k)&&tp.at(k).t==J::Str,"TIER_SET_FIELD_REQUIRED");
                const std::string subject=tp.at("subject").s;
                const std::string domain=tp.at("domain").s;
                const std::string profile=tp.at("profile").s;
                const std::string project=tp.at("project").s;
                const std::string tier=tp.at("tier").s;
                const std::string why=tp.at("reason").s;
                ensure(is_name(subject,2,95)&&is_name(domain,2,95)&&
                       is_name(profile,2,95)&&is_name(project,2,95),
                       "TIER_SET_SCOPE_INVALID");
                ensure(tier=="HOT"||tier=="WARM"||tier=="COLD","TIER_INVALID");
                ensure(why.size()>=3&&why.size()<=700,"TIER_REASON_INVALID");
                require_scope(client,tp,false);
                ensure(writer_authorized(),"WRITER_AUTHORITY_UNVERIFIED");

                FileLock lock;lock.acquire(p("STORE/writer.lock"));
                Loaded st=load_locked();
                ensure(st.chain_ok&&st.index_ok,"TIER_STORE_UNHEALTHY");
                const auto states=subject_states(st.rows);
                const SubjectState*match=nullptr;
                for(const auto&ss:states){
                    if(ss.profile==profile&&ss.project==project&&
                       ss.domain==domain&&ss.subject==subject){
                        ensure(match==nullptr,"TIER_SET_SUBJECT_AMBIGUOUS");
                        match=&ss;
                    }
                }
                ensure(match!=nullptr,"TIER_SUBJECT_NOT_FOUND");
                ensure(match->state!="EMPTY"&&match->state!="DORMANT",
                       "TIER_INACTIVE_SUBJECT");
                const std::string target=match->last_event_id;
                ensure(!target.empty(),"TIER_REFERENCE_INVALID");

                if(match->state==tier){
                    data["stored"]=J::boolean(false);
                    data["idempotent"]=J::boolean(true);
                    data["target_event_id"]=J::string(target);
                    data["effective_tier"]=J::string(tier);
                    data["client_role"]=J::string(client.role);
                    return dump_line(resp(op,"DUPLICATE_NOOP",
                        "TIER_ALREADY_EFFECTIVE",std::move(data)));
                }

                J ep=J::object();
                ep["profile"]=J::string(profile);ep["project"]=J::string(project);
                ep["domain"]=J::string(domain);ep["subject"]=J::string(subject);
                ep["event_class"]=J::string("TIER_CHANGE");
                ep["note"]=J::string(why);
                J event=build_event(ep,client,nonce,ts,sha256_hex(why),
                                    "INTERNAL_PROJECT");
                event["content"]["action_authority"]=
                    J::string("CLIENT_SCOPED_EXPLICIT_TIER_SET");
                event["content"]["requested_by_client"]=J::string(client.client_id);
                event["content"]["requested_by_role"]=J::string(client.role);
                event["content"]["target_event_id"]=J::string(target);
                event["content"]["target_tier"]=J::string(tier);
                J base=event;
                base["event_id"]=J::string(sha256_hex(dump(base)));
                Stream&stream=st.streams[profile+"|"+project];
                base["sequence_id"]=J::number(stream.seq+1);
                base["previous_event_hash"]=J::string(stream.last);
                base["event_hash"]=J::string(sha256_hex(dump(base)));
                st.rows.push_back(base);
                commit_event(st,base);
                data["stored"]=J::boolean(true);
                data["event_id"]=base.at("event_id");
                data["target_event_id"]=J::string(target);
                data["effective_tier"]=J::string(tier);
                data["client_role"]=J::string(client.role);
            }catch(const Fail&e){
                return dump_line(resp(op,"DENIED",e.why,J::object()));
            }
        }else if(op=="tier.request"){
            try{
                const J&tp=req.at("params");
                ensure(tp.t==J::Obj&&tp.o.size()==5,"TIER_REQUEST_FIELDS_INVALID");
                for(const char*k:{"subject","profile","project","tier","reason"})
                    ensure(tp.has(k)&&tp.at(k).t==J::Str,"TIER_REQUEST_FIELD_REQUIRED");
                const std::string subject=tp.at("subject").s;
                const std::string profile=tp.at("profile").s;
                const std::string project=tp.at("project").s;
                const std::string tier=tp.at("tier").s;
                const std::string why=tp.at("reason").s;
                ensure(is_name(subject,2,95)&&is_name(profile,2,95)&&is_name(project,2,95),
                       "TIER_REQUEST_SCOPE_INVALID");
                ensure(tier=="HOT"||tier=="WARM"||tier=="COLD","TIER_INVALID");
                ensure(why.size()>=3&&why.size()<=700,"TIER_REASON_INVALID");
                require_scope(client,tp,false);
                ensure(writer_authorized(),"WRITER_AUTHORITY_UNVERIFIED");

                FileLock lock;lock.acquire(p("STORE/writer.lock"));
                Loaded st=load_locked();
                ensure(st.chain_ok&&st.index_ok,"TIER_STORE_UNHEALTHY");
                const auto states=subject_states(st.rows);
                const SubjectState*match=nullptr;
                for(const auto&ss:states){
                    if(ss.profile==profile&&ss.project==project&&ss.subject==subject){
                        ensure(match==nullptr,"TIER_REQUEST_SUBJECT_AMBIGUOUS_DOMAIN");
                        match=&ss;
                    }
                }
                ensure(match!=nullptr,"TIER_SUBJECT_NOT_FOUND");
                ensure(match->state!="EMPTY"&&match->state!="DORMANT","TIER_INACTIVE_SUBJECT");
                const std::string target=match->last_event_id;
                ensure(!target.empty(),"TIER_REFERENCE_INVALID");

                if(match->state==tier){
                    data["stored"]=J::boolean(false);
                    data["idempotent"]=J::boolean(true);
                    data["target_event_id"]=J::string(target);
                    data["effective_tier"]=J::string(tier);
                    data["domain"]=J::string(match->domain);
                    data["client_role"]=J::string(client.role);
                    return dump_line(resp(op,"DUPLICATE_NOOP","TIER_ALREADY_EFFECTIVE",std::move(data)));
                }

                J ep=J::object();
                ep["profile"]=J::string(profile);ep["project"]=J::string(project);
                ep["domain"]=J::string(match->domain);ep["subject"]=J::string(subject);
                ep["event_class"]=J::string("TIER_CHANGE");ep["note"]=J::string(why);
                J event=build_event(ep,client,nonce,ts,sha256_hex(why),"INTERNAL_PROJECT");
                event["content"]["action_authority"]=J::string("CLIENT_SCOPED_EXPLICIT_TIER_REQUEST");
                event["content"]["requested_by_client"]=J::string(client.client_id);
                event["content"]["requested_by_role"]=J::string(client.role);
                event["content"]["target_event_id"]=J::string(target);
                event["content"]["target_tier"]=J::string(tier);
                J base=event;
                base["event_id"]=J::string(sha256_hex(dump(base)));
                Stream&stream=st.streams[profile+"|"+project];
                base["sequence_id"]=J::number(stream.seq+1);
                base["previous_event_hash"]=J::string(stream.last);
                base["event_hash"]=J::string(sha256_hex(dump(base)));
                st.rows.push_back(base);commit_event(st,base);
                data["stored"]=J::boolean(true);
                data["event_id"]=base.at("event_id");
                data["target_event_id"]=J::string(target);
                data["effective_tier"]=J::string(tier);
                data["domain"]=J::string(match->domain);
                data["client_role"]=J::string(client.role);
            }catch(const Fail&e){
                return dump_line(resp(op,"DENIED",e.why,J::object()));
            }
        }else if(op=="memory.state"){
            FileLock lock;lock.acquire(p("STORE/writer.lock"));
            Loaded st=load_locked();
            data["chain_ok"]=J::boolean(st.chain_ok);
            data["index_ok"]=J::boolean(st.index_ok);
            data["events"]=J::number((long long)st.rows.size());
            J by=J::object();
            long long hot=0,warm=0,cold=0,dorm=0,empty=0;
            for(const auto&s:subject_states(st.rows)){
                if(s.state=="HOT")hot++;
                else if(s.state=="WARM")warm++;
                else if(s.state=="COLD")cold++;
                else if(s.state=="DORMANT")dorm++;
                else empty++;
            }
            by["HOT"]=J::number(hot);by["WARM"]=J::number(warm);
            by["COLD"]=J::number(cold);by["DORMANT"]=J::number(dorm);
            by["EMPTY"]=J::number(empty);
            data["subjects_by_state"]=by;
            data["windows"]=J::object();
            data["windows"]["hot_days"]=J::number(conf_ll("hot_days",7));
            data["windows"]["warm_days"]=J::number(conf_ll("warm_days",30));
            data["windows"]["cold_days"]=J::number(conf_ll("cold_days",180));
        }else if(op=="store.verify"){data=op_store_verify();}
        else if(op=="store.replay"){data=op_store_replay();}
        else if(op=="store.recover"){data=op_store_recover();}
        else if(op=="proof.get"){data=op_proof_get(req.at("params"));}
        else if(op=="client.register"){data=op_client_register(req.at("params"));}
        else if(op=="client.revoke"){data=op_client_revoke(req.at("params"));}
        else if(op=="client.list"){data=op_client_list();}
        else if(op=="review.list"){data=op_review_list();}
        else if(op=="review.resolve"){data=op_review_resolve(req.at("params"));}
        else if(op=="backup.create"){data=op_backup_create(req.at("params"));}
        else if(op=="backup.verify"){data=op_backup_verify(req.at("params"));}
        else if(op=="backup.restore"){data=op_backup_restore(req.at("params"));}
        else if(op=="config.get"){
            J c=J::object();
            for(const auto&kv:conf_)c[kv.first]=J::string(kv.second);
            data["config"]=c;
            data["profiles"]=profiles_;
        }
        else if(op=="config.set"){data=op_config_set(req.at("params"));}
        else if(op=="sol.enable"){data=op_sol_set(true);}
        else if(op=="sol.disable"){data=op_sol_set(false);}
        else if(op=="profiles.add"){data=op_profiles_add(req.at("params"));}

        /* record nonce after a successful state-changing or read op */
        if(status=="OK"){
            NonceRec rec{nonce,client_id,identity,ts};
            nonces_.push_back(rec);
            try{save_nonces(nonces_);}catch(const Fail&){/* non-fatal */}
        }
        return dump_line(resp(op,status,reason,std::move(data)));
    }catch(const Fail&e){
        return dump_line(resp(op_unknown,"HOLD_INTEGRITY_OR_AUTHORITY",e.why,J::object()));
    }catch(const std::exception&e){
        return dump_line(resp(op_unknown,"HOLD_INTEGRITY_OR_AUTHORITY",
            std::string("ENGINE_ERROR:")+e.what(),J::object()));
    }
}

std::string Engine::call(const std::string&client_id,const std::string&op,
                         const J&params,const std::string&nonce_hex){
    /* Local convenience path: mirror request() authorization states before
     * touching key material so revoked/unknown clients get structured holds
     * instead of file-level errors. */
    bool found=false;
    const ClientRecord c=load_client(client_id,found);
    if(!found)
        return dump_line(resp(op,"HOLD_INTEGRITY_OR_AUTHORITY","UNKNOWN_CLIENT",J::object()));
    if(!c.enabled)
        return dump_line(resp(op,"HOLD_INTEGRITY_OR_AUTHORITY","CLIENT_REVOKED",J::object()));
    std::string key;
    try{
        key=client_key_for(client_id);
    }catch(const Fail&e){
        return dump_line(resp(op,"HOLD_INTEGRITY_OR_AUTHORITY",e.why,J::object()));
    }
    const std::string frame=Frame::build(key,client_id,op,params,nonce_hex,0);
    cleanse(key);
    size_t nl=frame.find('\n');
    std::string payload=frame.substr(0,nl);
    std::string sig=frame.substr(nl+1,64);
    return request(payload,sig);
}

/* ===================================================================== */
/* HOT retrieval                                                         */
/* ===================================================================== */

J Engine::hot_retrieve(const J&params,const ClientRecord&client){
    require_scope(client,params,true);
    long long limit=conf_ll("retrieval_default_limit",5);
    if(params.has("limit")&&params.at("limit").t==J::Num){
        limit=params.at("limit").as_int();
        if(limit<1||limit>50)die("LIMIT_OUT_OF_RANGE");
    }
    bool include_warm=params.has("include_warm")&&params.at("include_warm").t==J::Bool
        &&params.at("include_warm").b;
    FileLock lock;lock.acquire(p("STORE/writer.lock"));
    Loaded st=load_locked();
    if(!st.chain_ok||!st.index_ok)die("STORE_UNHEALTHY");
    std::map<std::string,bool> revoked;std::map<std::string,std::string> sup;
    derive_sets(st.rows,revoked,sup);
    std::vector<Engine::SubjectState> states=subject_states(st.rows);
    J items=J::array();
    std::vector<std::pair<long long,J>> ranked;
    for(const auto&s:states){
        if(params.has("profile")&&params.at("profile").t==J::Str&&
           s.profile!=params.at("profile").as_string())continue;
        if(params.has("project")&&params.at("project").t==J::Str&&
           s.project!=params.at("project").as_string())continue;
        if(params.has("subject")&&params.at("subject").t==J::Str&&
           s.subject!=params.at("subject").as_string())continue;
        if(s.state!="HOT"&&!(include_warm&&s.state=="WARM"))continue;
        if(s.last_event_id.empty())continue;
        const J*last=nullptr;
        for(const auto&e:st.rows)
            if(e.at("event_id").as_string()==s.last_event_id)last=&e;
        if(!last)continue;
        J item=J::object();
        item["profile"]=J::string(s.profile);
        item["project"]=J::string(s.project);
        item["subject"]=J::string(s.subject);
        item["subject_domain"]=J::string(s.domain);
        item["memory_state"]=J::string(s.state);
        item["event_id"]=(*last).at("event_id");
        item["event_hash"]=(*last).at("event_hash");
        item["sequence_id"]=(*last).at("sequence_id");
        item["event_class"]=(*last).at("event_class");
        item["privacy_class"]=(*last).at("privacy_class");
        item["observed_at"]=(*last).at("observed_at");
        item["recorded_at"]=(*last).at("recorded_at");
        item["summary"]=(*last).at("content").at("summary");
        long long rec=0;
        epoch_from_utc((*last).at("recorded_at").as_string(),rec);
        ranked.emplace_back(rec,item);
    }
    std::sort(ranked.begin(),ranked.end(),
        [](const std::pair<long long,J>&a,const std::pair<long long,J>&b){
            if(a.first!=b.first)return a.first>b.first;
            return a.second.at("event_id").as_string()<b.second.at("event_id").as_string();
        });
    if((long long)ranked.size()>limit)ranked.resize((size_t)limit);
    for(auto&kv:ranked)items.a.push_back(kv.second);
    J data=J::object();
    data["memory_items"]=J::number((long long)items.a.size());
    data["items"]=items;
    data["store"]=J::object();
    data["store"]["chain_ok"]=J::boolean(st.chain_ok);
    data["store"]["index_ok"]=J::boolean(st.index_ok);
    data["store"]["events"]=J::number((long long)st.rows.size());
    data["store"]["ledger_sha256"]=J::string(sha256_hex(st.ledger_bytes));
    data["windows"]=J::object();
    data["windows"]["hot_days"]=J::number(conf_ll("hot_days",7));
    data["windows"]["warm_days"]=J::number(conf_ll("warm_days",30));
    data["windows"]["cold_days"]=J::number(conf_ll("cold_days",180));
    return data;
}

/* ===================================================================== */
/* client registry ops                                                   */
/* ===================================================================== */

J Engine::op_client_register(const J&params){
    const std::string id=params.has("client_id")?params.at("client_id").as_string():"";
    const std::string role=params.has("role")?params.at("role").as_string():"";
    ensure(is_name(id,3,64),"INVALID_CLIENT_ID");
    ensure(id!="owner","OWNER_ID_RESERVED");
    ensure(!name_has_reserved_identity(id),
           "RESERVED_IDENTITY_IDS_FORBIDDEN_NOT_CHATGPT");
    ensure(role=="forge"||role=="sol"||role=="test","INVALID_ROLE");
    if(role=="sol"||id.rfind("sol",0)==0)
        ensure(conf_.count("sol_integration")&&conf_.at("sol_integration")=="enabled",
               "SOL_INTEGRATION_DISABLED");
    ensure(params.has("scopes")&&params.at("scopes").t==J::Obj,"SCOPES_REQUIRED");
    const J&sc=params.at("scopes");
    for(const char*f:{"profiles","projects","subjects","event_classes"})
        ensure(sc.has(f)&&sc.at(f).t==J::Arr,"SCOPE_FIELD_INVALID");
    if(sc.has("max_privacy"))
        ensure(sc.at("max_privacy").as_string()=="INTERNAL_PROJECT",
               "MAX_PRIVACY_FIXED_FOR_NON_OWNER");
    bool exists=false;
    load_client(id,exists);
    ensure(!exists||!file_exists(p("keys/clients/"+id+".key")),
           "CLIENT_ALREADY_REGISTERED");

    J rec=J::object();
    rec["client_id"]=J::string(id);
    rec["role"]=J::string(role);
    rec["enabled"]=J::boolean(true);
    rec["created_at"]=J::string(format_time(now_epoch()));
    if(exists)rec["reregistered_after_revoke"]=J::boolean(true);
    rec["scopes"]=sc;
    write_file_private(p("keys/clients/"+id+".json"),dump(rec)+"\n");
    write_file_private(p("keys/clients/"+id+".key"),[](){
        std::string k=random_hex(32);
        std::string raw;raw.resize(32);
        uint8_t buf[32];
        ensure(pcmf_from_hex(k.c_str(),buf,32),"KEY_DERIV_FAILED");
        memcpy(raw.data(),buf,32);
        return raw;
    }());
    J data=J::object();
    data["client_id"]=J::string(id);
    data["role"]=J::string(role);
    data["key_path"]=J::string(p("keys/clients/"+id+".key"));
    data["key_fingerprint"]=J::string(sha256_hex(id+"/key").substr(0,16));
    data["registered"]=J::boolean(true);
    return data;
}

J Engine::op_client_revoke(const J&params){
    const std::string id=params.has("client_id")?params.at("client_id").as_string():"";
    ensure(is_name(id,3,64)&&id!="owner","INVALID_CLIENT_ID");
    bool found=false;
    ClientRecord c=load_client(id,found);
    ensure(found,"UNKNOWN_CLIENT");
    if(!c.enabled){
        J data=J::object();
        data["client_id"]=J::string(id);
        data["already_revoked"]=J::boolean(true);
        return data;
    }
    c.raw["enabled"]=J::boolean(false);
    c.raw["revoked_at"]=J::string(format_time(now_epoch()));
    write_file_private(p("keys/clients/"+id+".json"),dump(c.raw)+"\n");
    if(file_exists(p("keys/clients/"+id+".key")))
        if(unlink(p("keys/clients/"+id+".key").c_str())!=0)die("KEY_REVOKE_FAILED");
    J data=J::object();
    data["client_id"]=J::string(id);
    data["revoked"]=J::boolean(true);
    data["revoked_at"]=c.raw.at("revoked_at");
    return data;
}

J Engine::op_client_list(){
    J list=J::array();
    /* owner */
    {
        bool f=false;ClientRecord o=load_client("owner",f);
        if(f){
            J e=J::object();
            e["client_id"]=J::string("owner");
            e["role"]=J::string(o.role);
            e["enabled"]=J::boolean(o.enabled);
            e["created_at"]=J::string(o.created_at);
            list.a.push_back(e);
        }
    }
    /* enumerate keys/clients dir */
    DIR*dir=opendir(p("keys/clients").c_str());
    if(dir){
        struct dirent*ent;
        while((ent=readdir(dir))!=nullptr){
            std::string name=ent->d_name;
            if(name.size()<=5||name.substr(name.size()-5)!=".json")continue;
            std::string id=name.substr(0,name.size()-5);
            bool f=false;ClientRecord c=load_client(id,f);
            if(!f)continue;
            J e=J::object();
            e["client_id"]=J::string(id);
            e["role"]=J::string(c.role);
            e["enabled"]=J::boolean(c.enabled);
            e["created_at"]=J::string(c.created_at);
            if(!c.revoked_at.empty())e["revoked_at"]=J::string(c.revoked_at);
            e["scopes"]=c.scopes;
            list.a.push_back(e);
        }
        closedir(dir);
    }
    J data=J::object();
    data["clients"]=list;
    return data;
}

/* ===================================================================== */
/* review queue ops                                                      */
/* ===================================================================== */

J Engine::op_review_list(){
    J pending=J::array();
    DIR*dir=opendir(p("review/pending").c_str());
    if(dir){
        struct dirent*ent;
        while((ent=readdir(dir))!=nullptr){
            std::string name=ent->d_name;
            if(name.size()<=5||name.substr(name.size()-5)!=".json")continue;
            try{
                J s=parse(read_file_bounded(p("review/pending/"+name),65536));
                pending.a.push_back(s);
            }catch(const Fail&){/* unreadable stubs are reported as-is */}
        }
        closedir(dir);
    }
    J rules=J::object();rules["rules"]=J::array();
    try{rules=parse(read_file_bounded(p("review/rules.json"),1ull*1024*1024));}
    catch(const Fail&){}
    J data=J::object();
    data["pending"]=pending;
    data["rules"]=rules.has("rules")?rules.at("rules"):J::array();
    data["note"]=J::string("RAW_SENSITIVE_CONTENT_IS_NEVER_PERSISTED_BEFORE_REVIEW");
    return data;
}

J Engine::op_review_resolve(const J&params){
    const std::string token=params.has("token")?params.at("token").as_string():"";
    const std::string decision=params.has("decision")?params.at("decision").as_string():"";
    ensure(is_hex(token,32),"TOKEN_FORMAT");
    ensure(decision=="allow_once"||decision=="authorize_once"||
           decision=="allow_rule"||decision=="reject",
           "INVALID_DECISION");
    const std::string stub_path=p("review/pending/"+token+".json");
    ensure(file_exists(stub_path),"PENDING_REVIEW_NOT_FOUND");
    J stub=parse(read_file_bounded(stub_path,65536));

    bool owner_found=false;
    ClientRecord owner=load_client("owner",owner_found);
    ensure(owner_found&&owner.enabled,"OWNER_UNAVAILABLE");

    J rules=J::object();rules["rules"]=J::array();
    try{rules=parse(read_file_bounded(p("review/rules.json"),1ull*1024*1024));}
    catch(const Fail&){}
    if(!rules.has("rules"))rules["rules"]=J::array();

    J data=J::object();
    if(decision=="allow_rule"){
        J rule=J::object();
        rule["client"]=stub.at("client");
        rule["profile"]=stub.at("profile");
        rule["project"]=stub.at("project");
        rule["subject"]=params.has("subject")&&params.at("subject").t==J::Str
            ?params.at("subject"):stub.at("subject");
        rule["domain"]=stub.at("domain");
        rule["event_class"]=stub.at("event_class");
        rule["decision"]=J::string("allow");
        rule["created_at"]=J::string(format_time(now_epoch()));
        rule["from_token"]=J::string(token);
        rules["rules"].a.push_back(rule);
        atomic_replace(p("review"),"rules.json",dump(rules)+"\n");
        /* stub moves to approved */
        atomic_replace(p("review/approved"),token+".json",dump(stub)+"\n");
        unlink(stub_path.c_str());
        data["rule_saved"]=J::boolean(true);
        data["future_matches"]=J::string("AUTO_ADMIT_AS_REVIEWED_SENSITIVE");
    }else if(decision=="reject"){
        J rule=J::object();
        rule["client"]=stub.at("client");
        rule["profile"]=stub.at("profile");
        rule["project"]=stub.at("project");
        rule["subject"]=stub.at("subject");
        rule["domain"]=stub.at("domain");
        rule["event_class"]=stub.at("event_class");
        rule["decision"]=J::string("deny");
        rule["created_at"]=J::string(format_time(now_epoch()));
        rule["from_token"]=J::string(token);
        rules["rules"].a.push_back(rule);
        atomic_replace(p("review"),"rules.json",dump(rules)+"\n");
        atomic_replace(p("review/rejected"),token+".json",dump(stub)+"\n");
        unlink(stub_path.c_str());
        data["rule_saved"]=J::boolean(true);
        data["future_matches"]=J::string("REJECTED");
    }else if(decision=="authorize_once"){
        J auth=stub;
        auth["decision"]=J::string("allow_once");
        auth["authorized_at"]=J::string(format_time(now_epoch()));
        auth["authorized_by"]=J::string("owner");
        atomic_replace(p("review/authorized"),token+".json",dump(auth)+"\n");
        data["authorized"]=J::boolean(true);
        data["awaiting_exact_resubmission"]=J::boolean(true);
        data["note_hash"]=stub.at("note_hash");
    }else{ /* allow_once: owner resubmits the exact reviewed content */
        ensure(params.has("note")&&params.at("note").t==J::Str,
               "NOTE_REQUIRED_FOR_ALLOW_ONCE");
        const std::string&note=params.at("note").as_string();
        ensure(sha256_hex(note)==stub.at("note_hash").as_string(),
               "NOTE_HASH_MISMATCH_WITH_REVIEWED_STUB");
        J op=J::object();
        op["profile"]=stub.at("profile");
        op["project"]=stub.at("project");
        op["subject"]=stub.at("subject");
        op["domain"]=stub.at("domain");
        op["event_class"]=stub.at("event_class");
        op["note"]=J::string(note);
        op["privacy_class"]=J::string("REVIEWED_SENSITIVE");
        ObserveOptions opt;
        opt.skip_policy=true;
        opt.force_privacy="REVIEWED_SENSITIVE";
        opt.review_token=token;
        const std::string owner_nonce=params.has("nonce")&&params.at("nonce").t==J::Str
            ?params.at("nonce").as_string():random_hex(16);
        ObserveOutcome o=observe_impl(op,owner,owner_nonce,now_epoch(),opt);
        ensure(o.status=="OK",o.reason.c_str());
        atomic_replace(p("review/approved"),token+".json",dump(stub)+"\n");
        unlink(stub_path.c_str());
        data["admitted"]=J::boolean(true);
        data["event_id"]=J::string(o.event_id);
        data["privacy_class"]=J::string("REVIEWED_SENSITIVE");
    }
    return data;
}


J Engine::op_review_submit(const J&params,const ClientRecord&client,
                           const std::string&nonce,long long issued){
    const std::string token=params.has("token")?params.at("token").as_string():"";
    ensure(is_hex(token,32),"TOKEN_FORMAT");
    ensure(params.has("note")&&params.at("note").t==J::Str,
           "NOTE_REQUIRED_FOR_REVIEW_SUBMIT");
    const std::string&note=params.at("note").as_string();

    const std::string stub_path=p("review/pending/"+token+".json");
    const std::string auth_path=p("review/authorized/"+token+".json");
    ensure(file_exists(stub_path),"PENDING_REVIEW_NOT_FOUND");
    ensure(file_exists(auth_path),"OWNER_REVIEW_AUTHORIZATION_REQUIRED");

    J stub=parse(read_file_bounded(stub_path,65536));
    J auth=parse(read_file_bounded(auth_path,65536));
    ensure(stub.has("token")&&stub.at("token").as_string()==token,
           "REVIEW_STUB_TOKEN_MISMATCH");
    ensure(auth.has("token")&&auth.at("token").as_string()==token,
           "REVIEW_AUTH_TOKEN_MISMATCH");
    ensure(auth.has("decision")&&auth.at("decision").as_string()=="allow_once",
           "REVIEW_AUTH_DECISION_INVALID");
    ensure(stub.has("client")&&stub.at("client").as_string()==client.client_id,
           "REVIEW_CLIENT_MISMATCH");
    ensure(auth.has("client")&&auth.at("client").as_string()==client.client_id,
           "REVIEW_AUTH_CLIENT_MISMATCH");
    ensure(stub.has("note_hash")&&auth.has("note_hash")&&
           stub.at("note_hash").as_string()==auth.at("note_hash").as_string(),
           "REVIEW_AUTH_HASH_BINDING_MISMATCH");
    ensure(sha256_hex(note)==stub.at("note_hash").as_string(),
           "NOTE_HASH_MISMATCH_WITH_REVIEWED_STUB");

    J op=J::object();
    op["profile"]=stub.at("profile");
    op["project"]=stub.at("project");
    op["subject"]=stub.at("subject");
    op["domain"]=stub.at("domain");
    op["event_class"]=stub.at("event_class");
    op["note"]=J::string(note);
    /* Scope-check the original client at its ordinary privacy ceiling;
     * the exact owner-authorized token/hash elevates only this one commit. */
    require_scope(client,op,false);

    ObserveOptions opt;
    opt.skip_policy=true;
    opt.force_privacy="REVIEWED_SENSITIVE";
    opt.review_token=token;
    ObserveOutcome o=observe_impl(op,client,nonce,issued,opt);
    ensure(o.status=="OK",o.reason.c_str());

    J receipt=stub;
    receipt["authorized_at"]=auth.at("authorized_at");
    receipt["consumed_at"]=J::string(format_time(now_epoch()));
    receipt["event_id"]=J::string(o.event_id);
    atomic_replace(p("review/approved"),token+".json",dump(receipt)+"\n");
    ensure(unlink(stub_path.c_str())==0,"PENDING_REVIEW_CLEANUP_FAILED");
    ensure(unlink(auth_path.c_str())==0,"REVIEW_AUTH_CLEANUP_FAILED");

    J data=J::object();
    data["admitted"]=J::boolean(true);
    data["event_id"]=J::string(o.event_id);
    data["privacy_class"]=J::string("REVIEWED_SENSITIVE");
    data["review_token"]=J::string(token);
    return data;
}

/* ===================================================================== */
/* integrity ops                                                         */
/* ===================================================================== */

J Engine::op_store_verify(){
    FileLock lock;lock.acquire(p("STORE/writer.lock"));
    Loaded st=load_locked();
    J data=J::object();
    data["chain_ok"]=J::boolean(st.chain_ok);
    data["index_ok"]=J::boolean(st.index_ok);
    data["events"]=J::number((long long)st.rows.size());
    data["ledger_sha256"]=J::string(sha256_hex(st.ledger_bytes));
    if(!st.error.empty())data["error"]=J::string(st.error);
    data["healthy"]=J::boolean(st.chain_ok&&st.index_ok);
    return data;
}

J Engine::op_store_replay(){
    FileLock lock;lock.acquire(p("STORE/writer.lock"));
    std::string first=read_file_bounded(p("STORE/local_memory.jsonl"),64ull*1024*1024);
    Loaded st=load_locked();
    ensure(st.chain_ok,st.error.empty()?"LEDGER_CHAIN_BROKEN":st.error.c_str());
    J rebuilt=make_index(st.rows,sha256_hex(st.ledger_bytes));
    const bool index_matches=dump(parse(st.index_bytes))==dump(rebuilt);
    std::string second=read_file_bounded(p("STORE/local_memory.jsonl"),64ull*1024*1024);
    const bool readback_identical=(first==second)&&(second==st.ledger_bytes);
    ensure(index_matches&&readback_identical,"REPLAY_MISMATCH");
    J data=J::object();
    data["replay"]=J::string("OK");
    data["events"]=J::number((long long)st.rows.size());
    data["ledger_sha256"]=J::string(sha256_hex(st.ledger_bytes));
    data["index_matches"]=J::boolean(index_matches);
    data["readback_identical"]=J::boolean(readback_identical);
    return data;
}

J Engine::op_store_recover(){
    FileLock lock;lock.acquire(p("STORE/writer.lock"));
    Loaded st=load_locked();
    ensure(st.chain_ok,"LEDGER_CHAIN_BROKEN_RECOVERY_REFUSED");
    J expect=make_index(st.rows,sha256_hex(st.ledger_bytes));
    J data=J::object();
    if(dump(parse(st.index_bytes))!=dump(expect)){
        atomic_replace(p("STORE"),"local_index.json",dump(expect)+"\n");
        Loaded post=load_locked();
        ensure(post.chain_ok&&post.index_ok,"RECOVER_READBACK_FAILED");
        data["result"]=J::string("RECOVERED_INDEX_FROM_VERIFIED_LEDGER");
    }else{
        data["result"]=J::string("INDEX_ALREADY_VALID");
    }
    data["events"]=J::number((long long)st.rows.size());
    return data;
}

J Engine::op_proof_get(const J&params){
    ensure(params.has("event_id")&&params.at("event_id").t==J::Str,
           "EVENT_ID_REQUIRED");
    const std::string eid=params.at("event_id").as_string();
    ensure(is_hex(eid,32),"EVENT_ID_FORMAT");
    FileLock lock;lock.acquire(p("STORE/writer.lock"));
    Loaded st=load_locked();
    ensure(st.chain_ok&&st.index_ok,"STORE_UNHEALTHY");
    const J*target=nullptr;
    for(const auto&e:st.rows)
        if(e.at("event_id").as_string()==eid)target=&e;
    ensure(target!=nullptr,"EVENT_NOT_FOUND");
    J idx=make_index(st.rows,sha256_hex(st.ledger_bytes));
    bool in_index=false;
    for(const auto&kv:idx.at("subjects").o)
        for(const auto&ent:kv.second.a)
            if(ent.at("event_id").as_string()==eid)in_index=true;
    J packet=J::object();
    packet["proof_kind"]=J::string("PCMF_MEMORY_PROOF_PACKET_V1");
    packet["event_id"]=(*target).at("event_id");
    packet["event_hash"]=(*target).at("event_hash");
    packet["previous_event_hash"]=(*target).at("previous_event_hash");
    packet["sequence_id"]=(*target).at("sequence_id");
    packet["stream"]=J::string((*target).at("profile_id").as_string()+"|"+
                               (*target).at("project_id").as_string());
    packet["event_class"]=(*target).at("event_class");
    packet["privacy_class"]=(*target).at("privacy_class");
    packet["source_ref"]=(*target).at("source_ref");
    packet["observed_at"]=(*target).at("observed_at");
    packet["recorded_at"]=(*target).at("recorded_at");
    packet["ledger_sha256"]=J::string(sha256_hex(st.ledger_bytes));
    packet["ledger_event_count"]=J::number((long long)st.rows.size());
    packet["chain_verified"]=J::boolean(st.chain_ok);
    packet["index_contains_event"]=J::boolean(in_index);
    packet["verified_at"]=J::string(format_time(now_epoch()));
    packet["root_id"]=J::string(root_id_);
    atomic_replace(p("proofs"),eid+".json",dump(packet)+"\n");
    return packet;
}

/* ===================================================================== */
/* backups                                                               */
/* ===================================================================== */

static const char*const BACKUP_COMPONENTS[]={
    ".pcmf_root",
    "STORE/local_memory.jsonl","STORE/local_index.json",
    "config/pcmf.conf","config/profiles.json",
    "keys/owner.key","keys/owner.json",
    "state/nonces.db"
};

J Engine::op_backup_create(const J&params){
    std::string name=params.has("name")?params.at("name").as_string()
        :"backup-"+std::to_string(now_epoch());
    ensure(is_name(name,3,64),"INVALID_BACKUP_NAME");
    const std::string bdir=p("backups/"+name);
    ensure(!dir_exists(bdir),"BACKUP_NAME_EXISTS");
    ensure_dir(bdir,0700);
    long long total=0;
    std::string sums;
    for(const char*rel:BACKUP_COMPONENTS){
        const std::string src=p(rel);
        if(!file_exists(src))continue;
        std::string bytes=read_file_bounded(src,64ull*1024*1024);
        ensure_parents(bdir,rel);
        write_file_private(bdir+"/"+rel,bytes);
        total+=(long long)bytes.size();
        sums+=sha256_hex(bytes)+"  "+rel+"\n";
    }
    J manifest=J::object();
    manifest["backup_name"]=J::string(name);
    manifest["version"]=J::string(PCMF_VERSION_STRING);
    manifest["root_id"]=J::string(root_id_);
    manifest["created_at"]=J::string(format_time(now_epoch()));
    manifest["canonical_writer"]=J::string(PCMF_CANONICAL_HOLD);
    write_file_private(bdir+"/manifest.json",dump(manifest)+"\n");
    write_file_private(bdir+"/SHA256SUMS",sums);
    J data=J::object();
    data["backup"]=J::string(name);
    data["files"]=J::number((long long)(sizeof BACKUP_COMPONENTS/sizeof *BACKUP_COMPONENTS));
    data["bytes"]=J::number(total);
    return data;
}

J Engine::op_backup_verify(const J&params){
    const std::string name=params.has("name")?params.at("name").as_string():"";
    ensure(is_name(name,3,64),"INVALID_BACKUP_NAME");
    const std::string bdir=p("backups/"+name);
    ensure(dir_exists(bdir),"BACKUP_NOT_FOUND");
    std::string sums=read_file_bounded(bdir+"/SHA256SUMS",1ull*1024*1024);
    long long files=0;
    for(const auto&line:split_lines(sums)){
        if(line.size()<67)continue;
        const std::string hash=line.substr(0,64);
        const std::string rel=line.substr(66);
        const std::string bytes=read_file_bounded(bdir+"/"+rel,64ull*1024*1024);
        ensure(sha256_hex(bytes)==hash,"BACKUP_CHECKSUM_MISMATCH:"+rel);
        files++;
    }
    J data=J::object();
    data["backup"]=J::string(name);
    data["verified"]=J::boolean(true);
    data["files"]=J::number(files);
    return data;
}

J Engine::op_backup_restore(const J&params){
    const std::string name=params.has("name")?params.at("name").as_string():"";
    ensure(is_name(name,3,64),"INVALID_BACKUP_NAME");
    const std::string bdir=p("backups/"+name);
    ensure(dir_exists(bdir),"BACKUP_NOT_FOUND");
    /* verify first */
    {
        J v=op_backup_verify(params);
        ensure(v.has("verified"),"BACKUP_VERIFICATION_FAILED");
    }
    FileLock lock;lock.acquire(p("STORE/writer.lock"));
    const std::string aside=p("backups/.pre-restore-"+std::to_string(now_epoch()));
    ensure_dir(aside,0700);
    /* move current aside, copy backup in, verify; roll back on failure */
    std::vector<std::string> moved;
    for(const char*rel:BACKUP_COMPONENTS){
        const std::string cur=p(rel);
        if(!file_exists(cur))continue;
        const std::string dst=aside+"/"+rel;
        ensure_parents(aside,rel);
        ensure(rename(cur.c_str(),dst.c_str())==0,"RESTORE_STAGING_FAILED");
        moved.push_back(rel);
    }
    bool okall=true;
    std::string why;
    for(const char*rel:BACKUP_COMPONENTS){
        const std::string src=bdir+"/"+rel;
        const std::string dst=p(rel);
        if(!file_exists(src))continue;
        try{
            std::string bytes=read_file_bounded(src,64ull*1024*1024);
            ensure_parents(root_,rel);
            write_file_private(dst,bytes);
        }catch(const Fail&e){okall=false;why=e.why;break;}
    }
    if(okall){
        try{
            Loaded st=load_locked();
            okall=st.chain_ok&&st.index_ok;
            if(!okall)why=st.error;
        }catch(const Fail&e){okall=false;why=e.why;}
    }
    if(!okall){
        /* roll back: restore moved-aside files */
        for(const std::string&rel:moved){
            const std::string dst=p(rel);
            ensure_parents(root_,rel);
            rename((aside+"/"+rel).c_str(),dst.c_str());
        }
        die(why.empty()?"RESTORE_VERIFICATION_FAILED":why.c_str());
    }
    J data=J::object();
    data["restored"]=J::string(name);
    data["verified"]=J::boolean(true);
    data["prior_state_preserved_at"]=J::string(path_basename(aside));
    return data;
}

/* ===================================================================== */
/* config / sol / profiles                                               */
/* ===================================================================== */

J Engine::op_config_set(const J&params){
    ensure(params.has("key")&&params.at("key").t==J::Str,"KEY_REQUIRED");
    const std::string key=params.at("key").as_string();
    std::string value;
    if(params.has("value")&&params.at("value").t==J::Str)value=params.at("value").as_string();
    auto digits_range=[&](long long lo,long long hi){
        ensure(!value.empty()&&value.find_first_not_of("0123456789")==std::string::npos,
               "VALUE_MUST_BE_NUMBER");
        long long v=0;
        for(char c:value)v=v*10+(c-'0');
        ensure(v>=lo&&v<=hi,"VALUE_OUT_OF_RANGE");
    };
    if(key=="hot_days")digits_range(0,3650);
    else if(key=="warm_days")digits_range(1,36500);
    else if(key=="cold_days")digits_range(1,36500);
    else if(key=="ts_window_past")digits_range(30,86400);
    else if(key=="ts_window_future")digits_range(10,3600);
    else if(key=="retrieval_default_limit")digits_range(1,50);
    else if(key=="auto_admit")ensure(value=="on"||value=="off","VALUE_ON_OR_OFF");
    else die("CONFIG_KEY_NOT_CONFIGURABLE");
    conf_[key]=value;
    std::string out="# PCMF Living Memory R14 root configuration\n";
    for(const auto&kv:conf_)out+=kv.first+"="+kv.second+"\n";
    atomic_replace(p("config"),"pcmf.conf",out);
    J data=J::object();
    data[key]=J::string(value);
    data["updated"]=J::boolean(true);
    return data;
}

J Engine::op_sol_set(bool enable){
    conf_["sol_integration"]=enable?"enabled":"disabled";
    std::string out="# PCMF Living Memory R14 root configuration\n";
    for(const auto&kv:conf_)out+=kv.first+"="+kv.second+"\n";
    atomic_replace(p("config"),"pcmf.conf",out);
    if(enable){
        J ack=J::object();
        ack["sol_integration"]=J::string("enabled");
        ack["enabled_at"]=J::string(format_time(now_epoch()));
        ack["authorized_by"]=J::string("owner");
        ack["authorization"]=J::string("OWNER_EXPLICIT_AUTHORIZATION");
        write_file_private(p("state/sol_authorized.json"),dump(ack)+"\n");
    }
    J data=J::object();
    data["sol_integration"]=J::string(enable?"enabled":"disabled");
    data["default_state"]=J::string("DISABLED_UNLESS_EXPLICITLY_ENABLED");
    return data;
}

J Engine::op_profiles_add(const J&params){
    ensure(params.has("profile_id")&&params.at("profile_id").t==J::Str,
           "PROFILE_ID_REQUIRED");
    const std::string pid=params.at("profile_id").as_string();
    ensure(is_name(pid,2,95),"INVALID_PROFILE_ID");
    ensure(params.has("projects")&&params.at("projects").t==J::Arr&&
           !params.at("projects").a.empty(),"PROJECTS_REQUIRED");
    for(const auto&pr:params.at("projects").a){
        ensure(pr.t==J::Str&&is_name(pr.as_string(),2,95),"INVALID_PROJECT_ID");
    }
    for(const auto&prof:profiles_.at("profiles").a)
        ensure(prof.at("profile_id").as_string()!=pid,"PROFILE_ALREADY_EXISTS");
    J prof=J::object();
    prof["profile_id"]=J::string(pid);
    prof["default"]=J::boolean(false);
    prof["projects"]=params.at("projects");
    profiles_["profiles"].a.push_back(prof);
    atomic_replace(p("config"),"profiles.json",dump(profiles_)+"\n");
    J data=J::object();
    data["profile_added"]=J::string(pid);
    return data;
}

/* ===================================================================== */
/* status                                                                */
/* ===================================================================== */

std::string Engine::status_json(){
    J data=J::object();
    data["root"]=J::string(root_);
    data["root_id"]=J::string(root_id_);
    data["version"]=J::string(PCMF_VERSION_STRING);
    data["canonical_writer"]=J::string(canonical_writer_state());
    data["writer_authorized"]=J::boolean(writer_authorized());
    bool chain_ok=false,index_ok=false;
    long long events=0;
    std::string error;
    try{
        FileLock lock;lock.acquire(p("STORE/writer.lock"));
        Loaded st=load_locked();
        chain_ok=st.chain_ok;index_ok=st.index_ok;events=(long long)st.rows.size();
        error=st.error;
    }catch(const Fail&e){error=e.why;}
    data["healthy"]=J::boolean(chain_ok&&index_ok);
    data["chain_ok"]=J::boolean(chain_ok);
    data["index_ok"]=J::boolean(index_ok);
    data["events"]=J::number(events);
    if(!error.empty())data["error"]=J::string(error);
    J by=J::object();
    long long hot=0,warm=0,cold=0,dorm=0;
    if(chain_ok&&index_ok){
        try{
            FileLock lock;lock.acquire(p("STORE/writer.lock"));
            Loaded st=load_locked();
            for(const auto&s:subject_states(st.rows)){
                if(s.state=="HOT")hot++;
                else if(s.state=="WARM")warm++;
                else if(s.state=="COLD")cold++;
                else if(s.state=="DORMANT")dorm++;
            }
        }catch(const Fail&){}
    }
    by["HOT"]=J::number(hot);by["WARM"]=J::number(warm);
    by["COLD"]=J::number(cold);by["DORMANT"]=J::number(dorm);
    data["subjects_by_state"]=by;
    auto ci=conf_.find("sol_integration");
    data["sol_integration"]=J::string(ci==conf_.end()?"disabled":ci->second);
    return dump(data);
}

} // namespace pcmf
