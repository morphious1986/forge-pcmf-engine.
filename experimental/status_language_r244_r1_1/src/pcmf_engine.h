#ifndef PCMF_ENGINE_H
#define PCMF_ENGINE_H
/*
 * PCMF Living Memory R14 - native C++20 memory engine.
 *
 * Lineage preserved from the verified R10 writer (R55 format):
 *   - canonical event schema  pcmf.deterministic.event.v2
 *   - canonical index schema  pcmf.deterministic.collection_index.v1
 *   - per-stream sequence ids, GENESIS anchor, sha256 event_id/event_hash
 *   - writer.lock (flock) single-writer fencing
 *   - ledger-then-index atomic commits with fsync; interrupted pair fails
 *     closed; index is always derivable from the verified ledger
 *   - canonical Library writer hold: HOLD_R241_R242 (no code path exists to
 *     any canonical store; the hold constant is echoed in every response)
 *
 * The engine operates on ONE initialized PCMF data root containing the
 * marker file .pcmf_root. It never touches /tmp/forge-r10-clone-* fixtures,
 * the historical live R55 store, or any canonical Library ledger.
 */
#include "pcmf_json.h"

#include <map>
#include <string>
#include <vector>

#define PCMF_VERSION_STRING "PCMF_LIVING_MEMORY_R14"
#define PCMF_PROTOCOL       "PCMF_IPv1"
#define PCMF_CANONICAL_HOLD "HOLD_R241_R242"
#define PCMF_CANONICAL_AUTH "AUTHORIZED_R243_RECONCILED_SINGLE_WRITER"

namespace pcmf {

struct ClientRecord {
    std::string client_id;
    std::string role;            /* owner|forge|sol|test            */
    bool enabled=false;
    std::string created_at, revoked_at;
    J scopes;                    /* profiles/projects/subjects/classes/max_privacy */
    J raw;                       /* full record for round-tripping  */
};

struct ObserveOutcome {
    std::string status;          /* OK | DUPLICATE_NOOP | REVIEW_REQUIRED | REJECT | HOLD_INTEGRITY_OR_AUTHORITY */
    std::string reason;
    std::string event_id;
    long long events_post=0;
    std::string review_token;
    bool reword_required=false;
    bool stored=false;
};

class Engine {
public:
    explicit Engine(std::string root);              /* requires initialized root */
    static void init_root(const std::string&root,
                          const std::string&profile,
                          const std::string&project);
    static bool looks_initialized(const std::string&root);

    /* PCMF_IPv1 entry point: authenticate and dispatch one signed frame. */
    std::string request(const std::string&payload_line,const std::string&sig_hex);
    /* Convenience: build a signed frame as a client would and dispatch it. */
    std::string call(const std::string&client_id,const std::string&op,const J&params,
                     const std::string&nonce_hex="");

    /* Non-protocol owner utilities (used by CLI/menu/installer). */
    std::string status_json();
    std::string client_key_for(const std::string&client_id) const; /* loads raw key */
    std::string root_id() const { return root_id_; }
    std::string root() const { return root_; }
    std::string canonical_writer_state() const;
    bool writer_authorized() const;

private:
    std::string root_;
    std::string root_id_;
    std::map<std::string,std::string> conf_;   /* root config/pcmf.conf   */
    J profiles_;                               /* config/profiles.json    */

    /* ---------- paths ---------- */
    std::string p(const std::string&rel) const;

    /* ---------- config ---------- */
    void load_config();
    long long conf_ll(const char*k,long long dflt) const;
    bool conf_on(const char*k,bool dflt) const;

    /* ---------- store primitives (R55 lineage) ---------- */
    struct Stream { long long seq=0; std::string last="GENESIS"; };
    std::vector<J> read_events(const std::string&bytes) const;
    void verify_rows(const std::vector<J>&rows) const;
    J make_index(const std::vector<J>&events,const std::string&ledger_sha) const;
    struct Loaded {
        std::string ledger_bytes, index_bytes;
        std::vector<J> rows;
        std::map<std::string,Stream> streams;
        bool chain_ok=false, index_ok=false;
        std::string error;
    };
    Loaded load_locked();
    J build_event(const J&params,const ClientRecord&client,const std::string&nonce,
                  long long issued,const std::string&note_hash,
                  const std::string&privacy_class);
    void commit_event(Loaded&st,const J&event);   /* atomic ledger+index */

    /* ---------- admission pipeline ---------- */
    struct ObserveOptions {
        std::string force_privacy;   /* used by owner review-resolve flow   */
        std::string review_token;    /* recorded in content when resolving  */
        bool skip_policy=false;      /* owner-resolved content              */
    };
    ObserveOutcome observe_impl(const J&params,const ClientRecord&client,
                                const std::string&nonce,long long issued,
                                const ObserveOptions&opt);
    ObserveOutcome observe(const J&params,const ClientRecord&client,
                           const std::string&nonce,long long issued);
    J normalize_observe_params(const J&params) const;   /* default profile */
    static void check_subject_binding(const Loaded&st,const J&params);
    bool content_duplicate(const Loaded&st,const J&params,
                           const std::string&note_hash) const;
    J admit_event(Loaded&st,const J&params,const ClientRecord&client,
                  const std::string&nonce,long long issued,
                  const std::string&privacy,const std::string&review_token);

    /* ---------- memory states / retrieval ---------- */
    struct SubjectState {
        std::string profile,project,domain,subject;
        std::string state;                        /* HOT|WARM|COLD|DORMANT|EMPTY */
        long long last_epoch=0;long long effective=0,total=0,revoked=0,superseded=0;
        std::string last_event_id;
    };
    void derive_sets(const std::vector<J>&rows,
                     std::map<std::string,bool>&revoked_effective,
                     std::map<std::string,std::string>&superseded_by) const;
    std::vector<SubjectState> subject_states(const std::vector<J>&rows) const;
    std::string state_for_age(long long age_seconds) const;
    J hot_retrieve(const J&params,const ClientRecord&client);

    /* ---------- admin op helpers ---------- */
    J op_client_register(const J&params);
    J op_client_revoke(const J&params);
    J op_client_list();
    J op_review_list();
    J op_review_resolve(const J&params);
    J op_review_submit(const J&params,const ClientRecord&client,
                       const std::string&nonce,long long issued);
    J op_store_verify();
    J op_store_replay();
    J op_store_recover();
    J op_proof_get(const J&params);
    J op_backup_create(const J&params);
    J op_backup_verify(const J&params);
    J op_backup_restore(const J&params);
    J op_config_set(const J&params);
    J op_sol_set(bool enable);
    J op_profiles_add(const J&params);

    /* ---------- clients ---------- */
    ClientRecord load_client(const std::string&client_id,bool&found) const;
    void require_scope(const ClientRecord&c,const J&params,bool hot) const;

    /* ---------- nonce ledger (replay prevention) ---------- */
    struct NonceRec { std::string nonce,client,content_hash;long long ts=0; };
    std::vector<NonceRec> load_nonces();
    void save_nonces(const std::vector<NonceRec>&recs);
    std::vector<NonceRec> nonces_;               /* cached during request */

    /* ---------- misc ---------- */
    long long window_past() const;long long window_future() const;
    J ok(const std::string&op,J data) const;
    J resp(const std::string&op,const std::string&status,
           const std::string&reason,J data) const;
    static std::string dump_line(const J&v);
};

/* Client-side frame builder (used by CLI, daemon tests, Forge/Sol adapters). */
struct Frame {
    static std::string build(const std::string&key,const std::string&client_id,
                             const std::string&op,const J&params,
                             const std::string&nonce_hex,long long ts);
    /* Parses "payload\nsig\n"; verifies sig with key; returns payload. */
    static std::string parse_and_verify(const std::string&key,const std::string&frame);
};

} // namespace pcmf
#endif
