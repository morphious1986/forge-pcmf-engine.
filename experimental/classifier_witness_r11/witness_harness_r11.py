"""Reproducible SHADOW evidence; never changes production policy or canonical memory.

This Python program is only the research harness. The evaluated classifiers
themselves are the native C11 baseline and isolated C11 shadow sources.
"""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(__file__).resolve().parent
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def run(label):
    path=root/("test_"+label)
    result=subprocess.run([str(path),label],capture_output=True,text=True,timeout=15,check=True)
    values={}
    for line in result.stdout.splitlines():
        parts=line.split("|")
        if len(parts)==4:
            name,source,decision,flag=parts
            assert source==label and flag.startswith("sensitive=")
            values[name]={"verdict":decision,"sensitive":flag=="sensitive=1"}
    return values
baseline=run("baseline")
shadow=run("shadow")
assert baseline.keys()==shadow.keys()
allow_changes=[]
witnesses=[]
for case in sorted(baseline):
    before=baseline[case];after=shadow[case]
    changed=before!=after
    if changed:
        allow_changes.append(case)
        assert before["verdict"]=="QUARANTINE_REVIEW_REQUIRED" and after["verdict"]=="AUTO_ADMIT_ELIGIBLE"
    # Test cases only. No production note text, tokens, credentials or plaintext.
    witnesses.append({
        "case_id":case,"source":"SYNTHETIC_UNIT_TEST",
        "baseline_verdict":before["verdict"],
        "shadow_verdict":after["verdict"],
        "decision_changed":changed,
        "witness_status":"REPRODUCIBLE_TEST_NOT_OWNER_APPROVAL",
        "policy_promotion":"NOT_AUTHORIZED",
    })
summary={
    "schema":"PCMF_SHADOW_WITNESS_R11",
    "native_engine":"C11",
    "baseline_c_sha256":sha(root/"pcmf_policy_baseline.c"),
    "shadow_c_sha256":sha(root/"pcmf_policy.c"),
    "test_c_sha256":sha(root/"test_shadow_r11.c"),
    "samples":len(witnesses),
    "candidate_reduced_reviews":len(allow_changes),
    "changed_case_ids":allow_changes,
    "unmodified_sensitive_cases":sum(1 for w in witnesses if w["baseline_verdict"]=="QUARANTINE_REVIEW_REQUIRED" and not w["decision_changed"]),
    "deployment":"SHADOW_ONLY",
    "canonical_pending_notes_examined":False,
    "owner_verified_production_labels":0,
    "policy_promoted":False,
    "promotion_gate":"OWNER_REVIEW_REQUIRED_WITH_LABELED_WITNESSES",
}
(root/"WITNESS_REPORT_R11.json").write_text(json.dumps({"summary":summary,"witnesses":witnesses},indent=2,sort_keys=True)+"\n")
print(json.dumps(summary,sort_keys=True))
