#include "pcmf_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
 const char *name,*note;
 pcmf_decision expected_shadow;
 int expected_baseline_sensitive;
} tc;
static const tc cases[]={
 {"labelled_numeric_sha256","Artifact checksum_sha256: 1234567890123456789012345678901234567890123456789012345678901234.",PCMF_AUTO,0},
 {"labelled_hex_sha256","Artifact sha256: abcdef12345678901234567890123456789012345678901234567890abcdef12.",PCMF_AUTO,0},
 {"labelled_build_timestamp","Build build_timestamp=20261113171530 verified with reproducible compiler.",PCMF_AUTO,1},
 {"numeric_build_id","Build build_id=12345678901234 passed artifact verification.",PCMF_AUTO,1},
 {"ci_run_id","Pipeline ci_run_id:12345678901234 completed reproducibly.",PCMF_AUTO,1},
 {"unlabelled_long_number","Unlabelled identifier 12345678901234 retained from unknown source.",PCMF_REVIEW,1},
 {"phone_like_number","The raw number 2155550199 was supplied without a technical identifier label.",PCMF_REVIEW,1},
 {"person_account_disclosure","Account number: 1234567890123456789012345678901234567890123456789012345678901234.",PCMF_REVIEW,1},
 {"secret_label_disclosure","Password: 1234567890123456789012345678901234567890123456789012345678901234.",PCMF_REVIEW,1},
 {"timestamp_bad_month","Build build_timestamp=20261313171530 was reported.",PCMF_REVIEW,1},
 {"timestamp_no_label","Timestamp 20261113171530 was reported.",PCMF_REVIEW,1},
 {"numeric_sha256_no_label","Checksum 1234567890123456789012345678901234567890123456789012345678901234.",PCMF_AUTO,0},
 {"technical_id_with_account","Build build_id=12345678901234 succeeded. Account number: 98765432109876.",PCMF_REVIEW,1},
 {"technical_id_with_password","Build build_id=12345678901234 succeeded. Password: temporary-password-material.",PCMF_REVIEW,1},
 {"technical_id_with_email","Build build_id=12345678901234 succeeded. Contact dev@example.test.",PCMF_REVIEW,1},
 {"technical_id_with_private_key","Build build_id=12345678901234 exposed private key in a log.",PCMF_REVIEW,1},
 {"prefix_collision","Field xbuild_id=12345678901234 must not qualify as a trusted label.",PCMF_REVIEW,1},
 {"invalid_timestamp_hour","Build build_timestamp=20261113251530 was rejected by validator.",PCMF_REVIEW,1},
 {"ordinary_project_note","The dashboard refresh completed with no pending writer changes.",PCMF_AUTO,0},
 {"private_key_mention","A private key was exposed during the build.",PCMF_REVIEW,1},
 {"metadata_about_secret","The password prompt is disabled and no secret was recorded.",PCMF_REVIEW,1}
};
int main(int argc,char **argv){
 int shadow=argc>1&&strcmp(argv[1],"shadow")==0;
 int failures=0;
 for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
   const tc *t=&cases[i];
   pcmf_input in={0};
   in.project="test_project";in.subject="SHADOW_TECHNICAL";
   in.domain="BUILD_PROJECT";in.event_class="PROJECT_STATE";
   in.note=t->note;in.scope_confirmed=1;
   in.source_authenticated=1;in.writer_authorized=1;in.integrity_healthy=1;
   in.privacy_class="INTERNAL_PROJECT";
   pcmf_verdict v=pcmf_decide(&in);
   int sensitive=pcmf_note_is_sensitive(t->note);
   printf("%s|%s|%s|sensitive=%d\n",t->name,shadow?"shadow":"baseline",
          pcmf_status(v.decision),sensitive);
   if(shadow&&(v.decision!=t->expected_shadow||sensitive!=(t->expected_shadow==PCMF_REVIEW)))failures++;
   if(!shadow&&sensitive!=t->expected_baseline_sensitive)failures++;
 }
 if(failures){fprintf(stderr,"FAILURES=%d\n",failures);return 1;}
 printf("R11_%s_%zu_PASS\n",shadow?"SHADOW":"BASELINE",sizeof(cases)/sizeof(cases[0]));
 return 0;
}
