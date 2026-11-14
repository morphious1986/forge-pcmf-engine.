#include "pcmf_policy.h"
#include <ctype.h>
#include <stddef.h>
#include <string.h>

/*
 * R14 stand-alone C11 deterministic admission classifier.
 * Derived from R9 (verified passing baseline) with order-stable extensions.
 * The actual authenticated canonical Library writer is NOT activated here
 * and this unit has no code path to any canonical store.
 */
static pcmf_verdict make(pcmf_decision d,const char *r){
    pcmf_verdict v={d,r,0,0};return v;
}
const char *pcmf_status(pcmf_decision d) {
    switch(d){
        case PCMF_AUTO:return "AUTO_ADMIT_ELIGIBLE";
        case PCMF_DUPLICATE:return "DUPLICATE_NOOP";
        case PCMF_REVIEW:return "QUARANTINE_REVIEW_REQUIRED";
        case PCMF_REJECT:return "REJECT";
        default:return "HOLD_INTEGRITY_OR_AUTHORITY";
    }
}
static int name_ok(const char *s) {
    if(!s || !isalpha((unsigned char)*s))return 0;
    size_t n=0;
    while(s[n] && n<=95) {
        unsigned char c=(unsigned char)s[n];
        if(!(isalnum(c)||c=='_'))return 0;
        n++;
    }
    return n>=2 && n<=95 && s[n]=='\0';
}
static int among(const char *s,const char *const *items,size_t n) {
    if(!s)return 0;
    for(size_t i=0;i<n;i++)if(strcmp(s,items[i])==0)return 1;
    return 0;
}
static int ci_equal_n(const char *a,const char *b,size_t n){
    for(size_t i=0;i<n;i++){
        if(!a[i] || tolower((unsigned char)a[i])!=tolower((unsigned char)b[i]))return 0;
    }
    return 1;
}
static int boundary_before(const char *base,const char *p){
    return p==base || (!isalnum((unsigned char)p[-1]) && p[-1]!='_');
}
static int boundary_after(const char *p,size_t n){
    unsigned char c=(unsigned char)p[n];
    return c=='\0' || (!isalnum(c) && c!='_');
}
static const char *ci_find_bounded_from(const char *base,const char *from,const char *needle){
    if(!base||!from||!needle)return NULL;
    size_t n=strlen(needle);
    if(n==0)return NULL;
    for(const char *p=from;*p;p++){
        if(!boundary_before(base,p))continue;
        if(ci_equal_n(p,needle,n) && boundary_after(p,n))return p;
    }
    return NULL;
}
static int ci_contains_bounded(const char *text,const char *needle){
    return ci_find_bounded_from(text,text,needle)!=NULL;
}
static int ci_starts_word(const char *p,const char *word){
    while(*p && isspace((unsigned char)*p))p++;
    size_t n=strlen(word);
    return ci_equal_n(p,word,n) && boundary_after(p,n);
}
static int ci_contains_any_bounded(const char *text,const char *const *items,size_t n){
    for(size_t i=0;i<n;i++)if(ci_contains_bounded(text,items[i]))return 1;
    return 0;
}
static int has_email_shape(const char *s){
    if(!s)return 0;
    for(size_t i=1;s[i];i++){
        if(s[i]!='@')continue;
        size_t l=i;
        while(l>0){
            unsigned char c=(unsigned char)s[l-1];
            if(isalnum(c)||c=='.'||c=='_'||c=='%'||c=='+'||c=='-')l--;
            else break;
        }
        if(l==i)continue;
        size_t j=i+1;int dot=0,domain_chars=0;
        while(s[j]){
            unsigned char c=(unsigned char)s[j];
            if(isalnum(c)||c=='-'){domain_chars++;j++;continue;}
            if(c=='.'){dot=1;j++;continue;}
            break;
        }
        if(domain_chars>=3 && dot)return 1;
    }
    return 0;
}
static int has_known_secret_shape(const char *s){
    static const char *const prefixes[]={
        "sk-","sk_","col_","ghp_","github_pat_","xoxb-","xoxp-","xoxa-"
    };
    if(!s)return 0;
    for(size_t i=0;i<sizeof prefixes/sizeof *prefixes;i++){
        const char *p=s;size_t n=strlen(prefixes[i]);
        while(*p){
            if(boundary_before(s,p) && strncmp(p,prefixes[i],n)==0){
                size_t k=n;
                while(p[k] && !isspace((unsigned char)p[k]) &&
                      p[k]!=',' && p[k]!=';' && p[k]!=')' && p[k]!=']')k++;
                if(k>=n+6)return 1;
            }
            p++;
        }
    }
    for(const char *p=s;*p;p++){
        if(!boundary_before(s,p))continue;
        if(ci_equal_n(p,"bearer",6) && boundary_after(p,6)){
            p+=6;while(*p && isspace((unsigned char)*p))p++;
            size_t n=0;while(p[n] && !isspace((unsigned char)p[n]) && p[n]!=',' && p[n]!=';')n++;
            if(n>=8)return 1;
        }
    }
    if(strstr(s,"-----BEGIN PRIVATE KEY-----") ||
       strstr(s,"-----BEGIN OPENSSH PRIVATE KEY-----"))return 1;
    return 0;
}
static int explicit_safe_follow(const char *p){
    static const char *const safe[]={
        "not","never","none","absent","missing","redacted","masked","stored",
        "managed","protected","rotated","rotation","present","exists","handled",
        "disabled","boundary","storage","policy","prompt","refresh","exchange"
    };
    while(*p && (isspace((unsigned char)*p)||*p==':'||*p=='='||*p=='-'))p++;
    for(size_t i=0;i<sizeof safe/sizeof *safe;i++)if(ci_starts_word(p,safe[i]))return 1;
    return 0;
}
static int disclosure_after_label(const char *text,const char *label){
    static const char *const danger[]={
        "supplied","provided","attached","pasted","copied","exposed","leaked",
        "logged","printed","revealed","disclosed","appeared","noted","captured"
    };
    size_t ln=strlen(label);
    const char *p=text;
    while((p=ci_find_bounded_from(text,p,label))){
        const char *after=p+ln;
        while(*after && isspace((unsigned char)*after))after++;

        if((*after==':' || *after=='=') && !explicit_safe_follow(after+1))return 1;

        if(ci_starts_word(after,"is") || ci_starts_word(after,"was")){
            const char *q=after;
            while(*q && !isspace((unsigned char)*q))q++;
            if(!explicit_safe_follow(q))return 1;
        }

        size_t span=0;
        for(const char *q=after;*q && span<64;q++,span++){
            if(*q==';' || *q=='.')break; /* do not let one clause taint another */
            if(!boundary_before(text,q))continue;
            for(size_t i=0;i<sizeof danger/sizeof *danger;i++){
                size_t dn=strlen(danger[i]);
                if(ci_equal_n(q,danger[i],dn) && boundary_after(q,dn)){
                    /*
                     * Treat an explicit nearby negation as safe metadata:
                     * "not logged", "never persisted", "no key value captured".
                     */
                    const char *lo=q;
                    size_t back=0;
                    while(lo>after && back<24){lo--;back++;}
                    int negated=0;
                    for(const char *z=lo;z<q;z++){
                        if(!boundary_before(text,z))continue;
                        if((ci_equal_n(z,"no",2) && boundary_after(z,2)) ||
                           (ci_equal_n(z,"not",3) && boundary_after(z,3)) ||
                           (ci_equal_n(z,"never",5) && boundary_after(z,5))){
                            negated=1;break;
                        }
                    }
                    if(negated)continue;
                    return 1;
                }
            }
        }
        p=after;
    }
    return 0;
}
int pcmf_note_is_sensitive(const char *s) {
    static const char *const credential_labels[]={
        "password","passcode","secret","private key","api key","api_key",
        "access token","token","passphrase","recovery code","one-time code",
        "one time code","otp","two-factor","2fa","pin number","security question"
    };
    static const char *const private_labels[]={
        "ssn","social security","passport","bank","credit card","account number",
        "home address","address","medical","diagnosis","medication","therapy",
        "birthdate","date of birth","personal identifier","health","phone number",
        "email","routing number","dob","cvv"
    };
    if(!s)return 0;

    /* Actual value-shaped evidence always wins over metadata context. */
    if(has_known_secret_shape(s) || has_email_shape(s))return 1;

    /*
     * Some authority-bearing object names are high-risk even without a value
     * unless the note explicitly describes safe storage/non-persistence.
     */
    if(ci_contains_bounded(s,"private key") &&
       !ci_contains_bounded(s,"private key storage") &&
       !ci_contains_bounded(s,"private key is not stored") &&
       !ci_contains_bounded(s,"private key not stored") &&
       !ci_contains_bounded(s,"private key is never stored") &&
       !ci_contains_bounded(s,"private key never stored") &&
       !ci_contains_bounded(s,"private key policy"))return 1;

    /*
     * Authentication factors and clearly personal medical content remain
     * review-gated even without a literal value in the note.
     */
    if(ci_contains_bounded(s,"otp") ||
       ci_contains_bounded(s,"one-time code") ||
       ci_contains_bounded(s,"one time code") ||
       ci_contains_bounded(s,"recovery code") ||
       ci_contains_bounded(s,"prescription medication"))return 1;

    /* Explicitly private semantic contexts remain review-gated. */
    if(ci_contains_bounded(s,"patient health") ||
       ci_contains_bounded(s,"patient medical") ||
       ci_contains_bounded(s,"medical record"))return 1;

    /* A security/privacy label is review-worthy when the note indicates a value/disclosure. */
    for(size_t i=0;i<sizeof credential_labels/sizeof *credential_labels;i++)
        if(disclosure_after_label(s,credential_labels[i]))return 1;
    for(size_t i=0;i<sizeof private_labels/sizeof *private_labels;i++)
        if(disclosure_after_label(s,private_labels[i]))return 1;

    /*
     * Conservative unlabeled numeric-identifier screening.
     * Only treat a bounded numeric-shaped token as sensitive: decimal digits
     * separated by common human formatting characters, with non-identifier
     * boundaries. Technical timestamps/hash fragments remain eligible.
     */
    for(size_t i=0;s[i];i++){
        if(!isdigit((unsigned char)s[i]))continue;
        if(i>0 && (isalnum((unsigned char)s[i-1]) || s[i-1]=='_'))continue;
        size_t j=i,digits=0,span=0,last_digit=i;
        while(s[j] && span<20){
            unsigned char c=(unsigned char)s[j];
            if(isdigit(c)){
                digits++;last_digit=j;j++;span++;continue;
            }
            if((c=='-'||c==' '||c=='.'||c=='/'||c=='('||c==')'||c=='+') &&
               s[j+1] && isdigit((unsigned char)s[j+1])){
                j++;span++;continue;
            }
            break;
        }
        if(digits>=9){
            unsigned char after=(unsigned char)s[last_digit+1];
            if(after=='\0' || (!isalnum(after) && after!='_'))return 1;
        }
    }

    /*
     * Non-disclosing security metadata is ordinary local project state.
     * Examples: key storage location, token refresh architecture, password
     * prompt behavior, redaction policy. These words alone are not secrets.
     */
    (void)ci_contains_any_bounded;
    return 0;
}
static int is_sensitive(const char *s){return pcmf_note_is_sensitive(s);}
pcmf_verdict pcmf_decide(const pcmf_input *p){
    /* R9 domains kept first; everyday-life domains appended for R14 (gate #2). */
    static const char *const domains[]={
        "MEMORY_SYSTEM","BUILD_PROJECT","OPERATIONAL_CONTROL",
        "LIBRARY_GOVERNANCE","SHARED_GOVERNANCE",
        "DAILY_ROUTINE","PERSONAL_PREFERENCE","SCHEDULE_COMMITMENT",
        "LEARNING_CONTEXT","ENVIRONMENT_CONTEXT","RELATIONSHIP_CONTEXT",
        "GENERAL_CONTEXT"
    };
    /* R9 event classes kept first; R14 appended classes follow. */
    static const char *const events[]={
        "PREFERENCE","PROJECT_STATE","WORKFLOW_STATE","FAILURE_GOTCHA",
        "OBSERVATION","ROUTINE_STATE","COMMITMENT","CORRECTION","REVOCATION"
    };
    if(!p)return make(PCMF_REJECT,"INVALID_ENVELOPE");
    if(!name_ok(p->project)||!name_ok(p->subject)||
       !among(p->domain,domains,sizeof domains/sizeof *domains)||
       !among(p->event_class,events,sizeof events/sizeof *events)||
       !p->scope_confirmed)
       return make(PCMF_REJECT,"INVALID_OR_UNCONFIRMED_SCOPE");
    if(!p->note)return make(PCMF_REVIEW,"UNCLASSIFIED_CONTENT");
    size_t n=0;
    while(n<702 && p->note[n])n++;
    if(n<3||n>700)return make(PCMF_REVIEW,"CONTENT_SIZE_OR_UNCERTAIN");
    for(size_t i=0;i<n;i++){
        unsigned char c=(unsigned char)p->note[i];
        if(c<32 || c==127)return make(PCMF_REVIEW,"NONPRINTABLE_CONTENT");
    }
    if(is_sensitive(p->note))return make(PCMF_REVIEW,"POTENTIALLY_SENSITIVE_CONTENT");
    if(!p->integrity_healthy)return make(PCMF_HOLD,"DETERMINISTIC_STATE_UNVERIFIED");
    if(!p->source_authenticated)return make(PCMF_HOLD,"SOURCE_PROVENANCE_UNVERIFIED");
    if(!p->writer_authorized)return make(PCMF_HOLD,"WRITER_AUTHORITY_UNVERIFIED");
    if(p->unresolved_correction)return make(PCMF_REVIEW,"CORRECTION_REQUIRES_RECONCILIATION");
    if(p->known_duplicate)return make(PCMF_DUPLICATE,"IDEMPOTENT_DUPLICATE");
    /* ---- R14 appended privacy-class gate (order-stable extension) ---- */
    if(p->privacy_class && p->privacy_class[0]){
        if(strcmp(p->privacy_class,"INTERNAL_PROJECT")==0){
            /* ordinary governed class: auto-eligible */
        } else if(strcmp(p->privacy_class,"PERSONAL_PRIVATE")==0 ||
                  strcmp(p->privacy_class,"PUBLIC_SHARED")==0 ||
                  strcmp(p->privacy_class,"REVIEWED_SENSITIVE")==0){
            return make(PCMF_REVIEW,"PRIVACY_CLASS_REVIEW_REQUIRED");
        } else {
            return make(PCMF_REJECT,"INVALID_PRIVACY_CLASS");
        }
    }
    return make(PCMF_AUTO,"ORDINARY_GOVERNED_ELIGIBLE");
}
