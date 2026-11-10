#include <stdio.h>
#include <string.h>
#include "pcmf_policy.h"

static int expect_decision(const char *name,const char *note,pcmf_decision want){
    pcmf_input p={
        "general","ForgePublicCollaboration","BUILD_PROJECT","PROJECT_STATE",note,
        1,1,1,1,0,0,"INTERNAL_PROJECT",NULL
    };
    pcmf_verdict v=pcmf_decide(&p);
    if(v.decision!=want){
        fprintf(stderr,"FAIL %s expected=%d got=%d reason=%s\n",
                name,(int)want,(int)v.decision,v.reason?v.reason:"");
        return 0;
    }
    printf("PASS %s decision=%s reason=%s\n",
           name,pcmf_status(v.decision),v.reason?v.reason:"");
    return 1;
}

int main(void){
    int ok=1;
    ok&=expect_decision(
        "sanitized_colony_architecture",
        "Colony API key is stored only in desktop keyring; secret value is not stored in Library or PCMF; JWT token refresh is handled by the official SDK and token value is not persisted",
        PCMF_AUTO);
    ok&=expect_decision(
        "password_prompt_metadata",
        "Password prompt path repaired; password value is never logged",
        PCMF_AUTO);
    ok&=expect_decision(
        "actual_api_key_value",
        "api key: col_FAKEVALUE123456789",
        PCMF_REVIEW);
    ok&=expect_decision(
        "actual_password_value",
        "password is synthetic-example-value",
        PCMF_REVIEW);
    ok&=expect_decision(
        "otp_material",
        "Enter the 6-digit otp code",
        PCMF_REVIEW);
    ok&=expect_decision(
        "private_key_material",
        "private key -----BEGIN PRIVATE KEY-----",
        PCMF_REVIEW);
    ok&=expect_decision(
        "medical_private_state",
        "Prescription medication reminder set for 8am",
        PCMF_REVIEW);
    ok&=expect_decision(
        "ordinary_project_state",
        "Objective scout completed with read-only proposals and no external action",
        PCMF_AUTO);
    if(ok)puts("PASS_PCMF_R16_SOL_LOCAL_ADMISSION_MATRIX checks=8");
    return ok?0:1;
}
