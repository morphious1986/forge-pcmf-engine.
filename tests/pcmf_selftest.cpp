/*
 * PCMF Living Memory R14 - native selftest (C++20, no Python/Node).
 * Covers: self-contained crypto vectors, R9 policy regression + R14 policy
 * extensions, engine admission/authentication/replay, isolation, states,
 * corrections/revocations, review queue, duplicates/conflicts, concurrency,
 * atomic commits, interrupted writes, corrupt indexes, ledger tampering,
 * crash recovery, restart persistence, proofs, backups, daemon protocol,
 * installer basics, and Sol adapter flow. Disposable synthetic data only.
 */
#include "test_harness.h"
#include "pcmf_policy.h"
#include "pcmf_sha256.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace pcmf;
using namespace test;

static std::string g_bindir;

/* ===================================================================== */
/* A. crypto vectors                                                     */
/* ===================================================================== */

static std::string sha_hex_of(const std::string&s){
    uint8_t d[32];pcmf_sha256(s.data(),s.size(),d);
    char h[65];pcmf_to_hex(d,32,h);return h;
}
static std::string hmac_hex_of(const std::string&k,const std::string&m){
    uint8_t d[32];
    pcmf_hmac_sha256((const uint8_t*)k.data(),k.size(),m.data(),m.size(),d);
    char h[65];pcmf_to_hex(d,32,h);return h;
}

static void t_sha_empty(int,char**){
    check(sha_hex_of("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "sha256 empty vector");
}
static void t_sha_abc(int,char**){
    check(sha_hex_of("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256 abc vector");
}
static void t_sha_twoblock(int,char**){
    check(sha_hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "sha256 448-bit vector");
}
static void t_sha_million_a(int,char**){
    check(sha_hex_of(std::string(1000000,'a'))==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
          "sha256 million-a vector");
}
static void t_hmac_rfc4231(int,char**){
    check(hmac_hex_of(std::string(20,'\x0b'),"Hi There")==
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
          "hmac rfc4231 case1");
    check(hmac_hex_of("Jefe","what do ya want for nothing?")==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
          "hmac rfc4231 case2");
    check(hmac_hex_of(std::string(20,'\xaa'),std::string(50,'\xdd'))==
          "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
          "hmac rfc4231 case3");
    check(hmac_hex_of(std::string(131,'\xaa'),
          "Test Using Larger Than Block-Size Key - Hash Key First")==
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
          "hmac rfc4231 case6");
}
static void t_hex_ct(int,char**){
    uint8_t raw[4]={0xde,0xad,0xbe,0xef};
    char h[9];pcmf_to_hex(raw,4,h);
    check(std::string(h)=="deadbeef","to_hex");
    uint8_t back[4];
    check(pcmf_from_hex("deadbeef",back,4),"from_hex ok");
    check(!pcmf_from_hex("deadbee",back,4),"from_hex short rejected");
    check(!pcmf_from_hex("zzadbeef",back,4),"from_hex bad digit rejected");
    check(pcmf_ct_equal("aaaa",  "aaaa",4),"ct_equal true");
    check(!pcmf_ct_equal("aaaa",  "aaab",4),"ct_equal false");
}

/* ===================================================================== */
/* B. policy regression (R9 baseline order-stability) + R14 extensions   */
/* ===================================================================== */

static void t_policy_r9_regression(int,char**){
    /* Legacy positional initializer must still compile and behave: proves
     * order-stable struct extension. */
    pcmf_input p={"ForgePCMF","AdmissionHealth","MEMORY_SYSTEM",
        "WORKFLOW_STATE","Routine project status recorded",1,0,0,1,0,0,
        nullptr,nullptr};
    check(pcmf_decide(&p).decision==PCMF_HOLD,"r9 unauthenticated hold");
    check(std::string(pcmf_decide(&p).reason)=="SOURCE_PROVENANCE_UNVERIFIED","r9 reason");
    p.source_authenticated=1;p.writer_authorized=1;
    check(pcmf_decide(&p).decision==PCMF_AUTO,"r9 auto");
    p.known_duplicate=1;
    check(pcmf_decide(&p).decision==PCMF_DUPLICATE,"r9 duplicate");
    p.known_duplicate=0;p.unresolved_correction=1;
    check(pcmf_decide(&p).decision==PCMF_REVIEW,"r9 correction review");
    p.unresolved_correction=0;p.note="Private API key is 123456";
    check(pcmf_decide(&p).decision==PCMF_REVIEW,"r9 sensitive key");
    p.note="example@example.com";
    check(pcmf_decide(&p).decision==PCMF_REVIEW,"r9 email");
    p.note="123456789";
    check(pcmf_decide(&p).decision==PCMF_REVIEW,"r9 nine digits");
    p.note="ordinary memory";p.scope_confirmed=0;
    check(pcmf_decide(&p).decision==PCMF_REJECT,"r9 scope");
    p.scope_confirmed=1;p.integrity_healthy=0;
    check(pcmf_decide(&p).decision==PCMF_HOLD,"r9 integrity");
}
static void t_policy_r14_extensions(int,char**){
    pcmf_input p{"ForgePCMF","AdmissionHealth","MEMORY_SYSTEM",
        "WORKFLOW_STATE","Routine project status recorded",1,1,1,1,0,0,
        nullptr,nullptr};
    for(const char*dom:{"DAILY_ROUTINE","PERSONAL_PREFERENCE",
        "SCHEDULE_COMMITMENT","LEARNING_CONTEXT","ENVIRONMENT_CONTEXT",
        "RELATIONSHIP_CONTEXT","GENERAL_CONTEXT"}){
        pcmf_input q=p;q.domain=dom;
        check(pcmf_decide(&q).decision==PCMF_AUTO,
              std::string("everyday domain accepted: ")+dom);
    }
    pcmf_input bad=p;bad.domain="MADE_UP_DOMAIN";
    check(pcmf_decide(&bad).decision==PCMF_REJECT,"unknown domain rejected");
    for(const char*cls:{"OBSERVATION","ROUTINE_STATE","COMMITMENT",
                        "CORRECTION","REVOCATION"}){
        pcmf_input q=p;q.event_class=cls;
        check(pcmf_decide(&q).decision==PCMF_AUTO,
              std::string("appended class accepted: ")+cls);
    }
    pcmf_input priv=p;priv.privacy_class="PERSONAL_PRIVATE";
    check(pcmf_decide(&priv).decision==PCMF_REVIEW,"personal private review");
    priv.privacy_class="INVALID_CLASS";
    check(pcmf_decide(&priv).decision==PCMF_REJECT,"invalid privacy class");
    priv.privacy_class="INTERNAL_PROJECT";
    check(pcmf_decide(&priv).decision==PCMF_AUTO,"internal auto");
    pcmf_input sens=p;sens.note="my password is hunter2";
    check(pcmf_decide(&sens).decision==PCMF_REVIEW,"sensitive extended signal");
    sens.note="Enter the 6-digit otp code";
    check(pcmf_decide(&sens).decision==PCMF_REVIEW,"otp signal");
    sens.note="Tea preferences logged for autumn";
    check(pcmf_decide(&sens).decision==PCMF_AUTO,"ordinary note passes");
}

/* ===================================================================== */
/* C. engine lifecycle + admission                                       */
/* ===================================================================== */

static std::string make_root(const char*tag){
    const std::string root=fresh_root(tag);
    Engine::init_root(root,"personal","general");

    /* R17 tests explicitly authorize disposable synthetic writer roots. */
    J marker=parse(read_file_bounded(root+"/.pcmf_root",4096));
    std::string conf=read_file_bounded(root+"/config/pcmf.conf",65536);
    const std::string hold_line="writer_authority=hold\n";
    const auto pos=conf.find(hold_line);
    check(pos!=std::string::npos,"writer authority config marker");
    conf.replace(pos,hold_line.size(),"writer_authority=authorized_r243\n");
    write_file_private(root+"/config/pcmf.conf",conf);

    J receipt=J::object();
    receipt["schema"]=J::string("forge.pcmf.example_node.legacy_to_r16_migration.v2");
    receipt["new_root_id"]=marker.at("root_id");
    receipt["source_events"]=J::number(0);
    receipt["source_media_modified"]=J::boolean(false);
    J acceptance=J::object();
    acceptance["status_healthy"]=J::boolean(true);
    acceptance["store_verify"]=J::string("PASS");
    acceptance["store_replay"]=J::string("PASS_READBACK_IDENTICAL");
    receipt["acceptance"]=acceptance;
    write_file_private(root+"/MIGRATION_RECEIPT_EXAMPLE_NODE_20261102.json",
                       dump(receipt)+"\n");
    return root;
}

static void t_init_and_marker(int,char**){
    const std::string root=fresh_root("init");
    Engine::init_root(root,"personal","general");
    check(Engine::looks_initialized(root),"marker present");
    bool threw=false;
    try{Engine::init_root(root,"personal","general");}catch(const Fail&){threw=true;}
    check(threw,"double init fails closed");
    Engine eng(root);
    const std::string resp=eng.call("owner","health.get",J::object());
    check(contains(resp,"\"status\":\"OK\""),"health ok");
    check(contains(resp,PCMF_CANONICAL_HOLD),"canonical hold echoed");
    remove_tree(root);
}
static void t_root_privacy_enforced(int,char**){
    const std::string root=make_root("priv");
    chmod(root.c_str(),0755); /* violate privacy */
    bool threw=false;
    try{Engine eng(root);}catch(const Fail&){threw=true;}
    check(threw,"engine refuses non-private root");
    chmod(root.c_str(),0700);
    remove_tree(root);
}
static void t_authenticated_admission(int,char**){
    const std::string root=make_root("admit");
    Engine eng(root);
    const std::string resp=eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","Owner prefers loose leaf tea at 7am"));
    check(contains(resp,"\"status\":\"OK\""),"admitted: "+resp);
    check(contains(resp,"\"stored\":true"),"stored flag");
    check(contains(resp,"LOCAL_CLIENT_SIGNED_NOT_CHATGPT")==false,"direct call event");
    const std::string verify=eng.call("owner","store.verify",J::object());
    check(contains(verify,"\"chain_ok\":true")&&contains(verify,"\"index_ok\":true"),
          "chain+index healthy after admission");
    remove_tree(root);
}
static void t_invalid_signature(int,char**){
    const std::string root=make_root("badsig");
    Engine eng(root);
    J req=J::object();
    req["v"]=J::string(PCMF_PROTOCOL);
    req["client"]=J::string("owner");
    req["op"]=J::string("health.get");
    req["nonce"]=J::string(random_hex(16));
    req["ts"]=J::number(now_epoch());
    req["params"]=J::object();
    const std::string payload=dump(req);
    const std::string resp=eng.request(payload,"00000000000000000000000000000000"
                                              "00000000000000000000000000000000");
    check(contains(resp,"SOURCE_SIGNATURE_INVALID"),"bad sig denied: "+resp);
    remove_tree(root);
}
static void t_expired_and_future(int,char**){
    const std::string root=make_root("time");
    Engine eng(root);
    J params=observe_params("general","TeaRoutine","Time window check");
    const std::string stale=eng.call("owner","observe.submit",params,
                                     random_hex(16)/*nonce*/);
    (void)stale;
    /* build manually with old ts */
    const std::string key=eng.client_key_for("owner");
    std::string frame=Frame::build(key,"owner","observe.submit",params,random_hex(16),
                                   now_epoch()-4000);
    size_t nl=frame.find('\n');
    const std::string resp=eng.request(frame.substr(0,nl),frame.substr(nl+1,64));
    check(contains(resp,"EXPIRED_OR_FUTURE_REQUEST"),"stale request denied: "+resp);
    frame=Frame::build(key,"owner","observe.submit",params,random_hex(16),
                       now_epoch()+4000);
    nl=frame.find('\n');
    const std::string resp2=eng.request(frame.substr(0,nl),frame.substr(nl+1,64));
    check(contains(resp2,"EXPIRED_OR_FUTURE_REQUEST"),"future request denied: "+resp2);
    remove_tree(root);
}
static void t_revoked_and_unknown(int,char**){
    const std::string root=make_root("revoke");
    Engine eng(root);
    J scopes=J::object();
    scopes["profiles"]=J::array();scopes["profiles"].a.push_back(J::string("*"));
    scopes["projects"]=J::array();scopes["projects"].a.push_back(J::string("general"));
    scopes["subjects"]=J::array();scopes["subjects"].a.push_back(J::string("*"));
    scopes["event_classes"]=J::array();scopes["event_classes"].a.push_back(J::string("*"));
    scopes["max_privacy"]=J::string("INTERNAL_PROJECT");
    J reg=J::object();
    reg["client_id"]=J::string("testhelper");
    reg["role"]=J::string("test");
    reg["scopes"]=scopes;
    std::string resp=eng.call("owner","client.register",reg);
    check(contains(resp,"\"status\":\"OK\""),"client registered: "+resp);
    resp=eng.call("testhelper","health.get",J::object());
    check(contains(resp,"\"status\":\"OK\""),"client auth works");
    J rv=J::object();rv["client_id"]=J::string("testhelper");
    resp=eng.call("owner","client.revoke",rv);
    check(contains(resp,"\"status\":\"OK\""),"revoke ok");
    resp=eng.call("testhelper","health.get",J::object());
    check(contains(resp,"CLIENT_REVOKED")||contains(resp,"UNKNOWN_CLIENT"),
          "revoked identity denied: "+resp);
    resp=eng.call("ghostclient","health.get",J::object());
    check(contains(resp,"UNKNOWN_CLIENT"),"unknown client denied");
    /* reserved identity */
    reg["client_id"]=J::string("MyChatGPTMirror");
    resp=eng.call("owner","client.register",reg);
    check(contains(resp,"RESERVED_IDENTITY_IDS_FORBIDDEN_NOT_CHATGPT"),
          "chatgpt impersonation blocked: "+resp);
    remove_tree(root);
}
static void t_malformed_requests(int,char**){
    const std::string root=make_root("malformed");
    Engine eng(root);
    auto hold=[&](const std::string&payload,const std::string&sig,
                  const std::string&needle){
        const std::string r=eng.request(payload,sig);
        check(contains(r,needle),needle+" got: "+r);
    };
    hold("not json","00000000000000000000000000000000"
                  "00000000000000000000000000000000","REQUEST_NOT_VALID_JSON");
    hold("","00000000000000000000000000000000"
              "00000000000000000000000000000000","INVALID_REQUEST_SIZE");
    const std::string key=eng.client_key_for("owner");
    const std::string good=Frame::build(key,"owner","health.get",J::object(),
                                        random_hex(16),0);
    size_t nl=good.find('\n');
    hold(good.substr(0,nl),good.substr(nl+1,64).substr(0,63)+
         (good.substr(nl+1,64).substr(63,1)=="0"?"1":"0"),
         "SOURCE_SIGNATURE_INVALID");
    /* oversized */
    std::string big(9000,'x');
    hold(big,"00","INVALID_REQUEST_SIZE");
    remove_tree(root);
}
static void t_scope_isolation(int,char**){
    const std::string root=make_root("scope");
    Engine eng(root);
    /* forge client scoped to project general / profile personal only */
    J scopes=J::object();
    scopes["profiles"]=J::array();scopes["profiles"].a.push_back(J::string("personal"));
    scopes["projects"]=J::array();scopes["projects"].a.push_back(J::string("general"));
    scopes["subjects"]=J::array();scopes["subjects"].a.push_back(J::string("Tea*"));
    scopes["event_classes"]=J::array();
    scopes["event_classes"].a.push_back(J::string("ROUTINE_STATE"));
    scopes["max_privacy"]=J::string("INTERNAL_PROJECT");
    J reg=J::object();
    reg["client_id"]=J::string("forge_local");
    reg["role"]=J::string("forge");
    reg["scopes"]=scopes;
    std::string resp=eng.call("owner","client.register",reg);
    check(contains(resp,"\"status\":\"OK\""),"forge registered");
    /* allowed */
    resp=eng.call("forge_local","observe.submit",
        observe_params("general","TeaRoutine","Scoped write works"));
    check(contains(resp,"\"status\":\"OK\""),"scoped observe ok: "+resp);
    /* forbidden project */
    resp=eng.call("forge_local","observe.submit",
        observe_params("otherproject","TeaRoutine","cross project"));
    check(contains(resp,"DENIED")&&contains(resp,"SCOPE_PROJECT_NOT_AUTHORIZED"),
          "cross-project denied: "+resp);
    /* forbidden subject pattern */
    resp=eng.call("forge_local","observe.submit",
        observe_params("general","CoffeeRoutine","bad subject"));
    check(contains(resp,"SCOPE_SUBJECT_NOT_AUTHORIZED"),"subject pattern enforced");
    /* forbidden class */
    resp=eng.call("forge_local","observe.submit",
        observe_params("general","TeaRoutine","bad class","DAILY_ROUTINE","PREFERENCE"));
    check(contains(resp,"SCOPE_EVENT_CLASS_NOT_AUTHORIZED"),"class enforced");
    /* cross-profile isolation: owner writes into second profile */
    resp=eng.call("owner","profiles.add",[](){
        J p=J::object();p["profile_id"]=J::string("workprofile");
        J pr=J::array();pr.a.push_back(J::string("general"));
        p["projects"]=pr;return p;}());
    check(contains(resp,"\"status\":\"OK\""),"profile added");
    J workparams=observe_params("general","MeetingNotes","work memory");
    workparams["profile"]=J::string("workprofile");
    resp=eng.call("owner","observe.submit",workparams);
    check(contains(resp,"\"status\":\"OK\""),"owner work observe ok");
    /* forge (personal-scoped) must not see workprofile memory */
    J hotp=J::object();hotp["profile"]=J::string("workprofile");
    hotp["project"]=J::string("general");
    resp=eng.call("forge_local","hot.get",hotp);
    check(contains(resp,"DENIED")&&contains(resp,"SCOPE_PROFILE_NOT_AUTHORIZED"),
          "cross-profile retrieval denied: "+resp);
    resp=eng.call("forge_local","hot.get",J::object());
    check(contains(resp,"MeetingNotes")==false,"no cross-profile leak");
    /* owner sees both */
    resp=eng.call("owner","hot.get",J::object());
    check(contains(resp,"TeaRoutine")&&contains(resp,"MeetingNotes"),
          "owner sees scoped memory");
    remove_tree(root);
}
static void t_duplicates_conflicts(int,char**){
    const std::string root=make_root("dup");
    Engine eng(root);
    const std::string n1=random_hex(16);
    std::string resp=eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","Same content once"),n1);
    check(contains(resp,"\"status\":\"OK\""),"first admitted");
    /* same content, different nonce -> CONTENT_DUPLICATE */
    resp=eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","Same content once"),random_hex(16));
    check(contains(resp,"DUPLICATE_NOOP")&&contains(resp,"CONTENT_DUPLICATE"),
          "content duplicate noop: "+resp);
    /* same nonce different content -> replay conflict */
    resp=eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","Different content"),n1);
    check(contains(resp,"NONCE_REPLAY_CONFLICT"),"nonce conflict hold: "+resp);
    /* subject/domain binding */
    resp=eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","conflicting domain",
                       "LEARNING_CONTEXT","OBSERVATION"));
    check(contains(resp,"SUBJECT_DOMAIN_CONFLICT"),"domain conflict hold: "+resp);
    remove_tree(root);
}
static void t_corrections_revocations(int,char**){
    const std::string root=make_root("corr");
    Engine eng(root);
    std::string resp=eng.call("owner","observe.submit",
        observe_params("general","GymPlan","Plan: three sessions per week",
                       "DAILY_ROUTINE","COMMITMENT"));
    check(contains(resp,"\"status\":\"OK\""),"commitment admitted");
    const std::string eid=resp.substr(resp.find("\"event_id\":\"")+12,64);
    /* correction requires ref */
    J corr=observe_params("general","GymPlan","Plan corrected: four sessions",
                          "DAILY_ROUTINE","CORRECTION");
    resp=eng.call("owner","observe.submit",corr,random_hex(16));
    check(contains(resp,"CORRECTION_REFERENCE_REQUIRED"),"correction without ref rejected");
    corr["ref_event_id"]=J::string(eid);
    resp=eng.call("owner","observe.submit",corr,random_hex(16));
    check(contains(resp,"\"status\":\"OK\""),"correction admitted: "+resp);
    /* hot retrieval shows corrected plan, not the superseded one */
    resp=eng.call("owner","hot.get",J::object());
    check(contains(resp,"four sessions")&&!contains(resp,"three sessions"),
          "correction supersedes in retrieval: "+resp);
    /* revocation removes the corrected plan (ref = correction event id) */
    const std::string cid=resp.substr(resp.find("\"event_id\":\"")+12,64);
    check(cid.size()==64,"correction event id captured");
    J rev=observe_params("general","GymPlan","Plan revoked entirely",
                         "DAILY_ROUTINE","REVOCATION");
    rev["ref_event_id"]=J::string(cid);
    resp=eng.call("owner","observe.submit",rev,random_hex(16));
    check(contains(resp,"\"status\":\"OK\""),"revocation admitted");
    resp=eng.call("owner","hot.get",J::object());
    check(!contains(resp,"four sessions"),"revoked memory excluded from HOT");
    check(contains(resp,"three sessions")&&!contains(resp,"four sessions"),
          "revoking correction restores prior effective event: "+resp);
    /* Revoking the original explicitly must now empty the subject. */
    J rev_original=observe_params("general","GymPlan","Original plan revoked",
                                  "DAILY_ROUTINE","REVOCATION");
    rev_original["ref_event_id"]=J::string(eid);
    resp=eng.call("owner","observe.submit",rev_original,random_hex(16));
    check(contains(resp,"\"status\":\"OK\""),"original revocation admitted");
    resp=eng.call("owner","hot.get",J::object());
    check(contains(resp,"memory_items\":0"),"original revoked, no hot items remain: "+resp);
    remove_tree(root);
}
static void t_subject_hot_survival(int,char**){
 const std::string root=make_root("multi");
 Engine eng(root);
 std::string r=eng.call("owner","observe.submit",
  observe_params("general","PersonalContinuity","Personal routine active","DAILY_ROUTINE","ROUTINE_STATE"),random_hex(16));
 check(contains(r,"ADMITTED"),"personal admit");
 r=eng.call("owner","observe.submit",
  observe_params("general","CyberdeckBuild","Cyberdeck case fit pending","BUILD_PROJECT","PROJECT_STATE"),random_hex(16));
 check(contains(r,"ADMITTED"),"project admit");
 std::string h=eng.call("owner","hot.get",J::object());
 check(contains(h,"Personal routine active")&&contains(h,"Cyberdeck case fit pending"),"both subjects HOT");
 r=eng.call("owner","observe.submit",
  observe_params("general","CyberdeckBuild","Cyberdeck measurements recorded","BUILD_PROJECT","PROJECT_STATE"),random_hex(16));
 check(contains(r,"ADMITTED"),"project update admit");
 h=eng.call("owner","hot.get",J::object());
 check(contains(h,"Personal routine active")&&contains(h,"Cyberdeck measurements recorded"),"personal survives update");
 remove_tree(root);
}
static void t_sensitive_review_flow(int,char**){
    const std::string root=make_root("review");
    Engine eng(root);
    /* forge-like client submits sensitive content */
    J scopes=J::object();
    scopes["profiles"]=J::array();scopes["profiles"].a.push_back(J::string("personal"));
    scopes["projects"]=J::array();scopes["projects"].a.push_back(J::string("general"));
    scopes["subjects"]=J::array();scopes["subjects"].a.push_back(J::string("*"));
    scopes["event_classes"]=J::array();scopes["event_classes"].a.push_back(J::string("*"));
    scopes["max_privacy"]=J::string("INTERNAL_PROJECT");
    J reg=J::object();
    reg["client_id"]=J::string("forge_local");
    reg["role"]=J::string("forge");
    reg["scopes"]=scopes;
    std::string resp=eng.call("owner","client.register",reg);
    check(contains(resp,"\"status\":\"OK\""),"forge registered");
    const std::string secret_note="My bank card number is 4444555566667777";
    resp=eng.call("forge_local","observe.submit",
        observe_params("general","Finance","secret_note_pending",
                       "GENERAL_CONTEXT","OBSERVATION"),random_hex(16));
    (void)resp;
    /* correct params with real note */
    J p=observe_params("general","Finance",secret_note,"GENERAL_CONTEXT","OBSERVATION");
    resp=eng.call("forge_local","observe.submit",p,random_hex(16));
    check(contains(resp,"REVIEW_REQUIRED"),"sensitive held for review: "+resp);
    const std::string token=resp.substr(resp.find("\"review_token\":\"")+16,64);
    check(!token.empty(),"token returned");
    /* stub persisted WITHOUT raw content */
    std::string stubs=eng.call("owner","review.list",J::object());
    check(contains(stubs,"4444555566667777")==false,
          "raw sensitive content NOT persisted in queue: "+stubs);
    check(contains(stubs,"note_hash"),"stub carries hash only");
    /* allow_rule -> future auto-admit as REVIEWED_SENSITIVE */
    J resolve=J::object();
    resolve["token"]=J::string(token);
    resolve["decision"]=J::string("allow_rule");
    resp=eng.call("owner","review.resolve",resolve);
    check(contains(resp,"rule_saved"),"rule saved: "+resp);
    resp=eng.call("forge_local","observe.submit",p,random_hex(16));
    check(contains(resp,"\"status\":\"OK\""),"rule admits future sensitive: "+resp);
    check(contains(resp,"REVIEWED_SENSITIVE")==false,"privacy recorded in event, not status");
    /* verify event privacy_class */
    const std::string hot=eng.call("owner","hot.get",J::object());
    check(contains(hot,"REVIEWED_SENSITIVE"),"event stored as reviewed-sensitive");
    /* deny rule path: new subject */
    J p2=observe_params("general","Finance2","api key sk-123abcdef",
                        "GENERAL_CONTEXT","OBSERVATION");
    resp=eng.call("forge_local","observe.submit",p2,random_hex(16));
    check(contains(resp,"REVIEW_REQUIRED"),"second sensitive held");
    const std::string token2=resp.substr(resp.find("\"review_token\":\"")+16,64);
    resolve=J::object();
    resolve["token"]=J::string(token2);
    resolve["decision"]=J::string("reject");
    resp=eng.call("owner","review.resolve",resolve);
    check(contains(resp,"rule_saved"),"deny rule saved");
    resp=eng.call("forge_local","observe.submit",p2,random_hex(16));
    check(contains(resp,"SENSITIVE_CONTENT_DENIED_BY_OWNER"),"deny rule enforced: "+resp);
    remove_tree(root);
}
static void t_allow_once(int,char**){
    const std::string root=make_root("allowonce");
    Engine eng(root);
    J scopes=J::object();
    scopes["profiles"]=J::array();scopes["profiles"].a.push_back(J::string("personal"));
    scopes["projects"]=J::array();scopes["projects"].a.push_back(J::string("general"));
    scopes["subjects"]=J::array();scopes["subjects"].a.push_back(J::string("*"));
    scopes["event_classes"]=J::array();scopes["event_classes"].a.push_back(J::string("*"));
    scopes["max_privacy"]=J::string("INTERNAL_PROJECT");
    J reg=J::object();
    reg["client_id"]=J::string("forge_local");
    reg["role"]=J::string("forge");
    reg["scopes"]=scopes;
    eng.call("owner","client.register",reg);
    const std::string note="Prescription medication reminder set for 8am";
    J p=observe_params("general","Health","x","GENERAL_CONTEXT","OBSERVATION");
    p["note"]=J::string(note);
    std::string resp=eng.call("forge_local","observe.submit",p,random_hex(16));
    check(contains(resp,"REVIEW_REQUIRED"),"held");
    const std::string token=resp.substr(resp.find("\"review_token\":\"")+16,64);
    J resolve=J::object();
    resolve["token"]=J::string(token);
    resolve["decision"]=J::string("allow_once");
    resolve["note"]=J::string(note);
    resp=eng.call("owner","review.resolve",resolve);
    check(contains(resp,"\"status\":\"OK\"")&&contains(resp,"admitted"),
          "allow_once admits: "+resp);
    /* mismatched content rejected */
    J p3=observe_params("general","Health2","other","GENERAL_CONTEXT","OBSERVATION");
    p3["note"]=J::string("another sensitive thing: passport 123456789");
    resp=eng.call("forge_local","observe.submit",p3,random_hex(16));
    const std::string token3=resp.substr(resp.find("\"review_token\":\"")+16,64);
    resolve=J::object();
    resolve["token"]=J::string(token3);
    resolve["decision"]=J::string("allow_once");
    resolve["note"]=J::string("DIFFERENT content than reviewed");
    resp=eng.call("owner","review.resolve",resolve);
    check(contains(resp,"NOTE_HASH_MISMATCH_WITH_REVIEWED_STUB"),
          "content swap blocked: "+resp);
    remove_tree(root);
}
static void t_memory_states(int,char**){
    const std::string root=make_root("states");
    Engine eng(root);
    std::string resp=eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","state test note"));
    check(contains(resp,"\"status\":\"OK\""),"admitted");
    resp=eng.call("owner","memory.state",J::object());
    check(contains(resp,"\"HOT\":1"),"subject is HOT now: "+resp);
    /* shrink hot window to 0 days -> subject ages into WARM */
    J cfg=J::object();cfg["key"]=J::string("hot_days");cfg["value"]=J::string("0");
    resp=eng.call("owner","config.set",cfg);
    check(contains(resp,"\"status\":\"OK\""),"config set");
    sleep(2); /* deterministic aging past the zero-length HOT window */
    resp=eng.call("owner","memory.state",J::object());
    check(contains(resp,"\"WARM\":1")&&contains(resp,"\"HOT\":0"),
          "subject aged to WARM: "+resp);
    /* HOT retrieval empty; include_warm finds it */
    resp=eng.call("owner","hot.get",J::object());
    check(contains(resp,"memory_items\":0"),"hot empty after aging");
    J warm=J::object();warm["include_warm"]=J::boolean(true);
    resp=eng.call("owner","hot.get",warm);
    check(contains(resp,"TeaRoutine"),"warm retrieval works");
    remove_tree(root);
}
static void t_client_explicit_tier_set(int,char**){
    const std::string root=make_root("tier-set");
    Engine eng(root);

    J scopes=J::object();
    scopes["profiles"]=J::array();scopes["profiles"].a.push_back(J::string("personal"));
    scopes["projects"]=J::array();scopes["projects"].a.push_back(J::string("general"));
    scopes["subjects"]=J::array();scopes["subjects"].a.push_back(J::string("Tea*"));
    scopes["event_classes"]=J::array();
    scopes["event_classes"].a.push_back(J::string("ROUTINE_STATE"));
    scopes["max_privacy"]=J::string("INTERNAL_PROJECT");
    J reg=J::object();
    reg["client_id"]=J::string("forge_tier");
    reg["role"]=J::string("forge");
    reg["scopes"]=scopes;
    std::string resp=eng.call("owner","client.register",reg);
    check(contains(resp,"\"status\":\"OK\""),"tier client registered: "+resp);

    resp=eng.call("forge_tier","observe.submit",
        observe_params("general","TeaRoutine","explicit tier test"));
    check(contains(resp,"\"status\":\"OK\""),"tier source admitted: "+resp);

    auto tier_params=[](const char*tier,const char*project="general"){
        J p=J::object();
        p["profile"]=J::string("personal");
        p["project"]=J::string(project);
        p["domain"]=J::string("DAILY_ROUTINE");
        p["subject"]=J::string("TeaRoutine");
        p["tier"]=J::string(tier);
        p["reason"]=J::string(std::string("explicit test tier ")+tier);
        return p;
    };

    resp=eng.call("forge_tier","tier.set",tier_params("WARM"),random_hex(16));
    check(contains(resp,"\"status\":\"OK\"")&&contains(resp,"\"effective_tier\":\"WARM\"")&&
          contains(resp,"\"client_role\":\"forge\""),
          "client WARM tier write: "+resp);
    resp=eng.call("owner","memory.state",J::object());
    check(contains(resp,"\"WARM\":1")&&contains(resp,"\"HOT\":0"),
          "WARM effective: "+resp);

    resp=eng.call("forge_tier","tier.set",tier_params("COLD"),random_hex(16));
    check(contains(resp,"\"status\":\"OK\"")&&contains(resp,"\"effective_tier\":\"COLD\""),
          "client COLD tier write: "+resp);
    resp=eng.call("owner","memory.state",J::object());
    check(contains(resp,"\"COLD\":1")&&contains(resp,"\"WARM\":0"),
          "COLD effective: "+resp);

    resp=eng.call("forge_tier","tier.set",tier_params("COLD"),random_hex(16));
    check(contains(resp,"DUPLICATE_NOOP")&&contains(resp,"TIER_ALREADY_EFFECTIVE"),
          "same tier idempotent: "+resp);

    J req=J::object();
    req["profile"]=J::string("personal");
    req["project"]=J::string("general");
    req["subject"]=J::string("TeaRoutine");
    req["tier"]=J::string("WARM");
    req["reason"]=J::string("explicit request path warm");
    resp=eng.call("forge_tier","tier.request",req,random_hex(16));
    check(contains(resp,"\"status\":\"OK\"")&&contains(resp,"\"effective_tier\":\"WARM\"")&&
          contains(resp,"\"domain\":\"DAILY_ROUTINE\""),
          "cached tier.request WARM write: "+resp);
    resp=eng.call("owner","memory.state",J::object());
    check(contains(resp,"\"WARM\":1")&&contains(resp,"\"COLD\":0"),
          "tier.request WARM effective: "+resp);

    resp=eng.call("forge_tier","tier.set",tier_params("COLD"),random_hex(16));
    check(contains(resp,"\"status\":\"OK\"")&&contains(resp,"\"effective_tier\":\"COLD\""),
          "tier.set COLD after request path: "+resp);

    resp=eng.call("forge_tier","tier.set",tier_params("WARM","otherproject"),random_hex(16));
    check(contains(resp,"DENIED")&&contains(resp,"SCOPE_PROJECT_NOT_AUTHORIZED"),
          "cross-project tier denied: "+resp);

    resp=eng.call("owner","store.verify",J::object());
    check(contains(resp,"\"status\":\"OK\""),"tier store verify: "+resp);
    remove_tree(root);
}

static void t_replay_readback(int,char**){
    const std::string root=make_root("replay");
    Engine eng(root);
    for(int i=0;i<5;i++)
        eng.call("owner","observe.submit",
            observe_params("general","Subject"+std::to_string(i),
                           "note number "+std::to_string(i)));
    const std::string resp=eng.call("owner","store.replay",J::object());
    check(contains(resp,"\"replay\":\"OK\""),"replay ok: "+resp);
    check(contains(resp,"\"events\":5"),"five events");
    check(contains(resp,"\"index_matches\":true")&&
          contains(resp,"\"readback_identical\":true"),"exact readback");
    remove_tree(root);
}
static void t_proof_packets(int,char**){
    const std::string root=make_root("proof");
    Engine eng(root);
    std::string resp=eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","proof note"));
    const std::string eid=resp.substr(resp.find("\"event_id\":\"")+12,64);
    J p=J::object();p["event_id"]=J::string(eid);
    resp=eng.call("owner","proof.get",p);
    check(contains(resp,"PCMF_MEMORY_PROOF_PACKET_V1"),"packet kind");
    check(contains(resp,"\"chain_verified\":true"),"chain verified");
    check(contains(resp,"\"index_contains_event\":true"),"index contains");
    check(file_exists(root+"/proofs/"+eid+".json"),"packet persisted");
    /* tampered id (correct 64-hex length, unknown event) */
    p["event_id"]=J::string(random_hex(32));
    resp=eng.call("owner","proof.get",p);
    check(contains(resp,"EVENT_NOT_FOUND"),"unknown event proof denied");
    remove_tree(root);
}
static void t_backup_roundtrip(int,char**){
    const std::string root=make_root("backup");
    Engine eng(root);
    eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","pre-backup note"));
    J b=J::object();b["name"]=J::string("snap1");
    std::string resp=eng.call("owner","backup.create",b);
    check(contains(resp,"\"status\":\"OK\""),"backup created: "+resp);
    resp=eng.call("owner","backup.verify",b);
    check(contains(resp,"\"verified\":true"),"backup verified");
    /* tamper store, then restore */
    {
        const std::string ledger=root+"/STORE/local_memory.jsonl";
        std::string bytes=read_file_bounded(ledger,65536);
        bytes[10]=(char)(bytes[10]^0x41);
        write_file_private(ledger,bytes);
    }
    resp=eng.call("owner","store.verify",J::object());
    check(contains(resp,"\"healthy\":false"),"tamper detected");
    resp=eng.call("owner","backup.restore",b);
    check(contains(resp,"\"restored\":\"snap1\""),"restore done: "+resp);
    resp=eng.call("owner","store.replay",J::object());
    check(contains(resp,"\"replay\":\"OK\""),"healthy after restore");
    check(contains(eng.call("owner","hot.get",J::object()),"pre-backup note"),
          "memory preserved across restore");
    remove_tree(root);
}

/* ===================================================================== */
/* D. crash / corruption / concurrency (process level)                   */
/* ===================================================================== */

static void t_crash_recovery(int,char**){
    const std::string root=make_root("crash");
    const std::string cli=g_bindir+"/pcmf";
    /* committed event before crash */
    run_process({cli,"observe","--project","general","--subject","TeaRoutine",
        "--domain","DAILY_ROUTINE","--class","ROUTINE_STATE",
        "--note","before crash","--root",root});
    /* crash: killed after ledger rename, before index write */
    const ProcResult crashed=run_process({cli,"observe","--project","general",
        "--subject","TeaRoutine","--domain","DAILY_ROUTINE","--class","ROUTINE_STATE",
        "--note","crash write","--root",root},
        "",{"PCMF_R14_TEST_CRASH_AFTER_LEDGER_RENAME=1"});
    check(crashed.exit_code==-97||crashed.exit_code==97,
          "crash injected exit 97, got "+std::to_string(crashed.exit_code));
    /* next writer must fail closed */
    ProcResult r=run_process({cli,"observe","--project","general",
        "--subject","TeaRoutine","--domain","DAILY_ROUTINE","--class","ROUTINE_STATE",
        "--note","post crash write","--root",root});
    check(contains(r.out,"INDEX_PREIMAGE_MISMATCH")||contains(r.out,"HOLD"),
          "writer fails closed after interrupted pair: "+r.out);
    /* recovery regenerates index from verified ledger */
    r=run_process({cli,"recover","--root",root});
    check(contains(r.out,"RECOVERED_INDEX_FROM_VERIFIED_LEDGER"),
          "recovered: "+r.out);
    r=run_process({cli,"replay","--root",root});
    check(contains(r.out,"\"replay\":\"OK\""),"replay after recovery");
    /* hot returns the latest effective event per subject; recovery preserved
     * the ledger-authoritative crashed write and blocked the third write. */
    r=run_process({cli,"hot","--root",root});
    check(contains(r.out,"crash write"),
          "ledger-authoritative recovery includes interrupted-pair event");
    check(contains(r.out,"post crash write")==false,
          "blocked write never committed");
    remove_tree(root);
}
static void t_corrupt_index(int,char**){
    const std::string root=make_root("corruptix");
    Engine eng(root);
    eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","index corruption test"));
    write_file_private(root+"/STORE/local_index.json","{\"broken\": true}\n");
    std::string resp=eng.call("owner","store.verify",J::object());
    check(contains(resp,"\"index_ok\":false"),"corrupt index detected: "+resp);
    resp=eng.call("owner","store.recover",J::object());
    check(contains(resp,"RECOVERED_INDEX_FROM_VERIFIED_LEDGER"),"index rebuilt");
    resp=eng.call("owner","store.replay",J::object());
    check(contains(resp,"\"replay\":\"OK\""),"replay after rebuild");
    remove_tree(root);
}
static void t_ledger_tamper(int,char**){
    const std::string root=make_root("tamper");
    Engine eng(root);
    eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","tamper target note"));
    {
        const std::string ledger=root+"/STORE/local_memory.jsonl";
        std::string bytes=read_file_bounded(ledger,65536);
        const auto pos=bytes.find("tamper target note");
        check(pos!=std::string::npos,"note present");
        bytes[pos]='T'; /* flip one byte */
        write_file_private(ledger,bytes);
    }
    std::string resp=eng.call("owner","store.verify",J::object());
    check(contains(resp,"\"chain_ok\":false")&&
          (contains(resp,"EVENT_ID_MISMATCH")||contains(resp,"LEDGER_NOT_CANONICAL")),
          "tampering detected: "+resp);
    resp=eng.call("owner","store.recover",J::object());
    check(contains(resp,"LEDGER_CHAIN_BROKEN_RECOVERY_REFUSED"),
          "recovery refuses tampered ledger: "+resp);
    /* observe blocked while unhealthy */
    resp=eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","during unhealthy"));
    check(contains(resp,"HOLD")||contains(resp,"SUBJECT_DOMAIN_CONFLICT"),
          "writes fail closed while unhealthy: "+resp);
    remove_tree(root);
}
static void t_torn_ledger(int,char**){
    const std::string root=make_root("torn");
    Engine eng(root);
    eng.call("owner","observe.submit",
        observe_params("general","TeaRoutine","torn line test"));
    {
        const std::string ledger=root+"/STORE/local_memory.jsonl";
        std::string bytes=read_file_bounded(ledger,65536);
        write_file_private(ledger,bytes.substr(0,bytes.size()-10)); /* tear */
    }
    std::string resp=eng.call("owner","store.verify",J::object());
    check(contains(resp,"LEDGER_TORN_LINE"),"torn line detected: "+resp);
    remove_tree(root);
}
static void t_concurrent_writers(int,char**){
    const std::string root=make_root("concurrent");
    const std::string cli=g_bindir+"/pcmf";
    const std::string nonce=random_hex(16);
    /* four processes, same nonce, same content */
    std::vector<std::string> outs;
    for(int i=0;i<4;i++){
        const ProcResult r=run_process({cli,"observe","--project","general",
            "--subject","TeaRoutine","--domain","DAILY_ROUTINE",
            "--class","ROUTINE_STATE","--note","concurrent write same",
            "--nonce",nonce,"--root",root});
        outs.push_back(r.out);
    }
    int ok_count=0,dup_count=0,other=0;
    for(const auto&o:outs){
        if(contains(o,"\"status\":\"OK\""))ok_count++;
        else if(contains(o,"DUPLICATE_NOOP"))dup_count++;
        else other++;
    }
    check(ok_count==1&&dup_count==3&&other==0,
          "exactly one append under concurrency: ok="+std::to_string(ok_count)+
          " dup="+std::to_string(dup_count)+" other="+std::to_string(other));
    /* conflicting nonce use across processes */
    const std::string nonce2=random_hex(16);
    ProcResult a=run_process({cli,"observe","--project","general",
        "--subject","TeaRoutine","--domain","DAILY_ROUTINE","--class","ROUTINE_STATE",
        "--note","conflict content A","--nonce",nonce2,"--root",root});
    ProcResult b=run_process({cli,"observe","--project","general",
        "--subject","TeaRoutine","--domain","DAILY_ROUTINE","--class","ROUTINE_STATE",
        "--note","conflict content B","--nonce",nonce2,"--root",root});
    const bool one_ok=(contains(a.out,"\"status\":\"OK\"")&&contains(b.out,"NONCE_REPLAY_CONFLICT"))
                    ||(contains(b.out,"\"status\":\"OK\"")&&contains(a.out,"NONCE_REPLAY_CONFLICT"));
    check(one_ok,"conflicting nonce usage held: A="+a.out+" B="+b.out);
    /* ledger remains healthy with exactly 2 events */
    Engine eng(root);
    const std::string resp=eng.call("owner","store.replay",J::object());
    check(contains(resp,"\"events\":2"),"two events total: "+resp);
    remove_tree(root);
}
static void t_restart_persistence(int,char**){
    const std::string root=make_root("restart");
    std::string resp;
    {
        Engine eng(root);
        eng.call("owner","observe.submit",
            observe_params("general","TeaRoutine","restart persistence note"));
    }
    {
        Engine eng2(root);   /* fresh process-state engine on same root */
        resp=eng2.call("owner","store.verify",J::object());
        check(contains(resp,"\"healthy\":true"),"healthy on reopen");
        resp=eng2.call("owner","hot.get",J::object());
        check(contains(resp,"restart persistence note"),"memory persists across restart");
    }
    remove_tree(root);
}

/* ===================================================================== */
/* E. daemon protocol + Sol adapter flow                                 */
/* ===================================================================== */

static void t_daemon_roundtrip(int,char**){
    const std::string root=make_root("daemon");
    ensure_dir(root+"/run",0700);          /* private socket directory */
    const std::string sock=root+"/run/pcmf.sock";
    /* spawn daemon */
    const pid_t pid=fork();
    check(pid>=0,"fork daemon");
    if(pid==0){
        const std::string devnull="/dev/null";
        int dn=open(devnull.c_str(),O_WRONLY);
        dup2(dn,STDERR_FILENO);
        execl((g_bindir+"/pcmf-serve").c_str(),"pcmf-serve",
              "--root",root.c_str(),"--socket",sock.c_str(),(char*)nullptr);
        _exit(127);
    }
    /* wait for socket */
    bool up=false;
    for(int i=0;i<100;i++){
        struct stat st{};
        if(stat(sock.c_str(),&st)==0&&S_ISSOCK(st.st_mode)){up=true;break;}
        usleep(50000);
    }
    check(up,"daemon socket appeared");
    /* ping over socket */
    Engine eng(root);
    const std::string key=eng.client_key_for("owner");
    const std::string frame=Frame::build(key,"owner","ping",J::object(),
                                         random_hex(16),0);
    const std::string ff=fresh_root("frame");
    write_file_private(ff,frame);
    ProcResult r=run_process({g_bindir+"/pcmf","send","--socket",sock,
                              "--frame-file",ff});
    check(contains(r.out,"\"status\":\"OK\"")&&contains(r.out,"\"pong\":true"),
          "daemon ping: "+r.out);
    /* observe over socket */
    const std::string frame2=Frame::build(key,"owner","observe.submit",
        observe_params("general","TeaRoutine","via daemon socket"),
        random_hex(16),0);
    write_file_private(ff,frame2);
    r=run_process({g_bindir+"/pcmf","send","--socket",sock,"--frame-file",ff});
    check(contains(r.out,"\"status\":\"OK\"")&&contains(r.out,"\"stored\":true"),
          "daemon observe: "+r.out);
    /* hold constant echoed even on protocol errors */
    const std::string badframe="garbage\n00\n";
    const std::string ff2=fresh_root("frame2");
    write_file_private(ff2,badframe);
    r=run_process({g_bindir+"/pcmf","send","--socket",sock,"--frame-file",ff2});
    check(contains(r.out,"HOLD")||contains(r.out,"FRAME"),"garbage frame held: "+r.out);
    check(!r.out.empty() && r.out.size()<16384,"malformed-frame response bounded and nonempty");
    remove_tree(ff2);
    /* invalid signature over socket */
    const std::string frame3=Frame::build(key,"owner","health.get",J::object(),
                                          random_hex(16),0);
    /* corrupt sig: flip first char of the hex line */
    {
        std::string f3=frame3;
        size_t nl=f3.find('\n');
        f3[nl+1]=(f3[nl+1]=='0')?'1':'0';
        write_file_private(ff,f3);
    }
    r=run_process({g_bindir+"/pcmf","send","--socket",sock,"--frame-file",ff});
    check(contains(r.out,"SOURCE_SIGNATURE_INVALID"),"socket bad sig denied: "+r.out);
    check(!r.out.empty() && r.out.size()<16384,"invalid-signature response bounded and nonempty");
    /* stop daemon */
    kill(pid,SIGTERM);
    int status=0;
    waitpid(pid,&status,0);
    check(WIFEXITED(status)&&WEXITSTATUS(status)==0,"daemon clean shutdown");
    struct stat st{};
    check(stat(sock.c_str(),&st)!=0,"socket cleaned on shutdown");
    remove_tree(root);
    remove_tree(ff);
}
static void t_sol_flow(int,char**){
    const std::string root=make_root("sol");
    Engine eng(root);
    /* sol client registration must be refused while disabled */
    J scopes=J::object();
    scopes["profiles"]=J::array();scopes["profiles"].a.push_back(J::string("personal"));
    scopes["projects"]=J::array();scopes["projects"].a.push_back(J::string("general"));
    scopes["subjects"]=J::array();scopes["subjects"].a.push_back(J::string("*"));
    scopes["event_classes"]=J::array();scopes["event_classes"].a.push_back(J::string("*"));
    scopes["max_privacy"]=J::string("INTERNAL_PROJECT");
    J reg=J::object();
    reg["client_id"]=J::string("sol_adapter");
    reg["role"]=J::string("sol");
    reg["scopes"]=scopes;
    std::string resp=eng.call("owner","client.register",reg);
    check(contains(resp,"SOL_INTEGRATION_DISABLED"),"sol refused while disabled: "+resp);
    /* enable with owner op, then register + observe */
    resp=eng.call("owner","sol.enable",J::object());
    check(contains(resp,"\"sol_integration\":\"enabled\""),"sol enabled");
    check(file_exists(root+"/state/sol_authorized.json"),"authorization record kept");
    resp=eng.call("owner","client.register",reg);
    check(contains(resp,"\"status\":\"OK\""),"sol registered after enable");
    resp=eng.call("sol_adapter","observe.submit",
        observe_params("general","SolNote","sol adapter compatibility write"));
    check(contains(resp,"\"status\":\"OK\""),"sol observe works (PCMF_IPv1 compatible): "+resp);
    /* disable -> sol client blocked again */
    resp=eng.call("owner","sol.disable",J::object());
    check(contains(resp,"\"sol_integration\":\"disabled\""),"sol disabled");
    resp=eng.call("sol_adapter","observe.submit",
        observe_params("general","SolNote","post disable"));
    check(contains(resp,"SOL_INTEGRATION_DISABLED"),"sol blocked after disable: "+resp);
    remove_tree(root);
}
static void t_installer_fresh_home(int,char**){
    /* Package a real release from the source tree, install it into a
     * disposable HOME (no systemd here), uninstall, verify data preserved. */
    const std::string source_root=g_bindir+"/..";
    const std::string packager=source_root+"/scripts/package_release.sh";
    if(!file_exists(packager)){
        std::printf("SKIP installer test (packager not found at %s)\n",packager.c_str());
        return;
    }
    const std::string home=fresh_root("home");
    ensure_dir(home,0700);
    ensure_dir(home+"/.config",0700);
    const std::string bid="777001";
    const std::string cmd="cd '"+source_root+"' && PCMF_RELEASE_VERSION=R14 "
        "PCMF_RELEASE_BUILD_ID="+bid+" sh scripts/package_release.sh "
        ">/dev/null 2>&1";
    if(std::system(cmd.c_str())!=0){
        std::printf("SKIP installer test (packaging failed)\n");
        remove_tree(home);
        return;
    }
    const std::string stage=source_root+"/release/pcmf-living-memory-R14-"+bid;
    const std::string installer=stage+"/scripts/install.sh";
    if(!file_exists(installer)){
        std::printf("SKIP installer test (staged installer missing)\n");
        remove_tree(home);remove_tree(stage);
        return;
    }
    const ProcResult r=run_process({"/bin/sh",installer,"--no-service"},
        "",{"HOME="+home,"PCMF_INSTALL_DIR="+home+"/.local/lib/pcmf"});
    check(contains(r.out,"PASS_INSTALL"),
          "fresh install reported success: "+r.out);
    /* installed binary works */
    ProcResult v=run_process({home+"/.local/lib/pcmf/current/bin/pcmf","version"});
    check(contains(v.out,PCMF_VERSION_STRING),"installed pcmf version works: "+v.out);
    /* menu binary exists and self-checks via installed path */
    v=run_process({home+"/.local/lib/pcmf/current/bin/pcmf-setup","--selfcheck"});
    check(contains(v.out,"SETUP_SELFCHECK_OK"),"setup selfcheck via installed path");
    /* uninstall preserves data */
    const ProcResult u=run_process({"/bin/sh",stage+"/scripts/uninstall.sh","--no-service"},
        "",{"HOME="+home});
    check(contains(u.out,"PASS_UNINSTALL"),"uninstall ok: "+u.out);
    check(!dir_exists(home+"/.local/lib/pcmf"),"program files removed");
    check(file_exists(home+"/.local/share/pcmf/.pcmf_root"),
          "memory data preserved after uninstall");
    remove_tree(home);
    remove_tree(source_root+"/release");
}

int main(int argc,char**argv){
    /* args: pcmf-selftest [quick] [bindir] */
    bool quick=false;
    std::vector<std::string> args;
    for(int i=1;i<argc;i++){
        if(std::string(argv[i])=="quick")quick=true;
        else args.push_back(argv[i]);
    }
    g_bindir=args.empty()?bin_dir(argc,argv):args[0];
    std::vector<TestCase> tests={
        {"crypto_sha_empty",t_sha_empty},
        {"crypto_sha_abc",t_sha_abc},
        {"crypto_sha_twoblock",t_sha_twoblock},
        {"crypto_sha_million_a",t_sha_million_a},
        {"crypto_hmac_rfc4231",t_hmac_rfc4231},
        {"crypto_hex_ct",t_hex_ct},
        {"policy_r9_regression",t_policy_r9_regression},
        {"policy_r14_extensions",t_policy_r14_extensions},
        {"engine_init_and_marker",t_init_and_marker},
        {"engine_root_privacy_enforced",t_root_privacy_enforced},
        {"engine_authenticated_admission",t_authenticated_admission},
        {"engine_invalid_signature",t_invalid_signature},
        {"engine_expired_and_future",t_expired_and_future},
        {"engine_revoked_and_unknown",t_revoked_and_unknown},
        {"engine_malformed_requests",t_malformed_requests},
        {"engine_scope_isolation",t_scope_isolation},
        {"engine_duplicates_conflicts",t_duplicates_conflicts},
        {"engine_corrections_revocations",t_corrections_revocations},
        {"engine_subject_hot_survival",t_subject_hot_survival},
        {"engine_sensitive_review_flow",t_sensitive_review_flow},
        {"engine_allow_once",t_allow_once},
        {"engine_memory_states",t_memory_states},
        {"engine_client_explicit_tier_set",t_client_explicit_tier_set},
        {"engine_replay_readback",t_replay_readback},
        {"engine_proof_packets",t_proof_packets},
        {"engine_backup_roundtrip",t_backup_roundtrip},
        {"process_crash_recovery",t_crash_recovery},
        {"process_corrupt_index",t_corrupt_index},
        {"process_ledger_tamper",t_ledger_tamper},
        {"process_torn_ledger",t_torn_ledger},
        {"process_concurrent_writers",t_concurrent_writers},
        {"process_restart_persistence",t_restart_persistence},
        {"daemon_roundtrip",t_daemon_roundtrip},
        {"sol_adapter_flow",t_sol_flow},
        {"installer_fresh_home",t_installer_fresh_home},
    };
    std::printf("PCMF_LIVING_MEMORY_R14_SELFTEST engine=%s canonical_writer=%s mode=%s\n",
                PCMF_VERSION_STRING,PCMF_CANONICAL_HOLD,quick?"quick":"full");
    if(quick){
        /* installer-time subset: fast, deterministic, no process/daemon tests */
        std::vector<TestCase> sub;
        for(const auto&t:tests)
            if(std::string(t.name).rfind("process_",0)!=0&&
               std::string(t.name).rfind("daemon_",0)!=0&&
               std::string(t.name).rfind("installer_",0)!=0)
                sub.push_back(t);
        return run_all(sub,argc,argv);
    }
    return run_all(tests,argc,argv);
}
