"""PCMF R2: deterministic, metadata-only review advisor.

This module intentionally has no file I/O, persistence, credentials, network
access, or automatic policy mutations. Production admission is governed by
the native PCMF authority, not by these suggestions.
"""
from collections.abc import Mapping, Sequence

REVIEW_OUTCOMES = frozenset({
    "ADMITTED", "REVIEW_REQUIRED", "REJECTED", "DEFERRED", "NO_RESPONSE"
})
PROTECTED_REASONS = (
    "privacy_class_review_required",
    "credential",
    "secret",
    "medical",
    "personal_health",
    "password",
    "token",
    "payment",
)


def memory_and_execution(
    memory_outcome: str,
    *,
    execution_authorized: bool,
    independent_gates: Sequence[str] = (),
) -> dict:
    """A memory decision does not grant or revoke execution permission."""
    if memory_outcome not in REVIEW_OUTCOMES:
        raise ValueError("unknown memory outcome")
    return {
        "memory_admitted": memory_outcome == "ADMITTED",
        "memory_outcome": memory_outcome,
        "project_may_continue": bool(execution_authorized)
        and not bool(independent_gates),
        "independent_gates": tuple(independent_gates),
    }


def _metadata_key(item: Mapping) -> tuple[str, ...]:
    return tuple(
        str(item.get(field) or "").casefold()
        for field in ("subject", "domain", "event_class", "reason")
    )


def advise_review(item: Mapping, history: Mapping) -> dict:
    """Suggest human classifier review; never declassify or admit."""
    key = _metadata_key(item)
    count = lambda state: sum(
        _metadata_key(row) == key for row in history.get(state, ())
    )
    approved = count("approved")
    rejected = count("rejected")
    authorized = count("authorized")
    reason = str(item.get("reason") or "").casefold()
    protected = any(label in reason for label in PROTECTED_REASONS)
    if protected:
        suggestion = "retain_per_item_owner_review"
    elif approved >= 3 and rejected == 0:
        suggestion = "propose_human_classifier_review"
    elif rejected:
        suggestion = "retain_review_consider_prior_rejections"
    else:
        suggestion = "insufficient_evidence"
    return {
        "matching_approved": approved,
        "matching_rejected": rejected,
        "matching_authorized": authorized,
        "protected_reason": protected,
        "suggestion": suggestion,
        "auto_admit": False,
        "auto_declassify": False,
        "create_persistent_rule": False,
    }


def reject_once_capability() -> dict:
    """Reflect production status until a separately verified native cutover."""
    return {
        "available_in_production": False,
        "isolated_candidate_tested": True,
        "existing_broad_reject_is_not_equivalent": True,
    }
