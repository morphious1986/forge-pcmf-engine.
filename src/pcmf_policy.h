#ifndef PCMF_NATIVE_POLICY_R14_H
#define PCMF_NATIVE_POLICY_R14_H
/*
 * PCMF Living Memory R14 - deterministic admission classifier (C11).
 *
 * Lineage: derived from pcmf_native_policy_r9.c (R9, verified baseline,
 * sha256 bdca0003...6d3d3d) with ORDER-STABLE extensions:
 *   - the original nine R9 checks and their order are unchanged;
 *   - everyday-life domains and event classes were appended to the
 *     allowlists (original entries kept first);
 *   - a privacy-class gate and two appended input fields were added at the
 *     END of the struct so legacy positional initializers remain valid.
 *
 * Governance preserved: memory truth belongs to PCMF. No filesystem, shell,
 * dynamic loading, network, or third-party dependencies in this unit.
 * The canonical Library writer hold (HOLD_R241_R242) is enforced by callers.
 */
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PCMF_AUTO=0, PCMF_DUPLICATE, PCMF_REVIEW, PCMF_REJECT, PCMF_HOLD
} pcmf_decision;

typedef struct {
    const char *project, *subject, *domain, *event_class, *note;
    int scope_confirmed;
    /* Trusted authority flags are bound by a caller outside untrusted input. */
    int source_authenticated, writer_authorized, integrity_healthy;
    int known_duplicate, unresolved_correction;
    /* ---- R14 appended fields (order-stable; legacy initializers valid) ---- */
    const char *privacy_class;   /* NULL = INTERNAL_PROJECT               */
    const char *ref_event_id;    /* CORRECTION/REVOCATION target, or NULL */
} pcmf_input;

typedef struct {
    pcmf_decision decision;
    const char *reason;
    int approved, stored;
} pcmf_verdict;

pcmf_verdict pcmf_decide(const pcmf_input *input);
/* Authenticated GPT connector: length-neutral, otherwise identical policy. */
pcmf_verdict pcmf_decide_gpt(const pcmf_input *input);
const char *pcmf_status(pcmf_decision decision);

/* Sensitivity screening exposed for the review-queue stub builder. */
int pcmf_note_is_sensitive(const char *s);

#ifdef __cplusplus
}
#endif
#endif
