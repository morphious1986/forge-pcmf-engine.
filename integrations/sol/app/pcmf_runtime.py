"""Sol continuity orchestration over authoritative PCMF Living Memory.

Design:
- personal continuity lane: profile=<configured-profile>, project=general
- project continuity lane: profile=<configured-profile>, explicitly selected project
- pre-turn: HOT + WARM recall from both lanes
- post-turn: bounded structured proposal -> PCMF deterministic admission
- REVIEW_REQUIRED is a hard stop
- no local Sol memory store is used as authority
- current R241/R242 writer hold is fail-closed
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

try:
    from app.pcmf_client import PcmfClient
except ModuleNotFoundError:
    from pcmf_client import PcmfClient


PERSONAL_PROJECT = (
    os.environ.get("SOL_PCMF_PERSONAL_PROJECT", "general").strip() or "general"
)
MIN_CONFIDENCE = 0.90
SUBJECT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,94}")

PERSONAL_CLASSES = {
    "PREFERENCE",
    "ROUTINE_STATE",
    "COMMITMENT",
    "OBSERVATION",
}
PERSONAL_DOMAINS = {
    "PERSONAL_PREFERENCE",
    "DAILY_ROUTINE",
    "SCHEDULE_COMMITMENT",
    "GENERAL_CONTEXT",
    "ENVIRONMENT_CONTEXT",
    "LEARNING_CONTEXT",
}
PROJECT_CLASSES = {
    "PROJECT_STATE",
    "WORKFLOW_STATE",
    "FAILURE_GOTCHA",
    "OBSERVATION",
}
PROJECT_DOMAINS = {
    "BUILD_PROJECT",
    "OPERATIONAL_CONTROL",
    "MEMORY_SYSTEM",
    "LIBRARY_GOVERNANCE",
    "SHARED_GOVERNANCE",
    "ENVIRONMENT_CONTEXT",
    "GENERAL_CONTEXT",
}


@dataclass(frozen=True)
class PcmfPreparedContext:
    block: str
    personal_count: int
    project_count: int
    project: str | None
    status: str
    canonical_writer: str


class PcmfProposalProvider:
    """Proposal-only extractor. PCMF remains the admission authority."""

    SYSTEM_PROMPT = """You classify a single user turn into durable PCMF memory candidates.

Return exactly one JSON object with key "events" whose value is an array of
zero, one, or two objects. No markdown and no commentary.

Each event must contain exactly:
lane, evidence_quote, subject, domain, event_class, note, confidence, project_lifecycle

Rules:
- lane is "personal" or "project".
- Only propose stable cross-session facts explicitly stated in the current
  user message. Do not infer from assistant text.
- Personal lane is for stable preferences, routines, commitments, and general
  personal continuity.
- Project lane is only for the explicitly supplied selected_project and is for
  project state, milestones, workflow state, user-stated gotchas, or stable
  project observations.
- A project milestone is PROJECT_STATE.
- project_lifecycle must be null normally.
- project_lifecycle may be "COMPLETE" only when the user explicitly states
  that the selected project itself is completed/finished, not merely a
  milestone or one task. A COMPLETE event must use PROJECT_STATE and
  BUILD_PROJECT.
- Do not store transient tasks, ordinary questions, commands, temporary
  requests, credentials, secrets, raw private identifiers, health/legal/
  financial details, or third-party private information.
- evidence_quote must be an exact non-empty substring of current_user_message.
- subject must be concise and stable and match [A-Za-z0-9][A-Za-z0-9_.-]{0,94}.
- note must be a concise restatement supported only by evidence_quote, 3-700
  printable characters.
- confidence must be 0.90 through 1.0.
- personal event_class must be one of:
  PREFERENCE, ROUTINE_STATE, COMMITMENT, OBSERVATION
- personal domain must be one of:
  PERSONAL_PREFERENCE, DAILY_ROUTINE, SCHEDULE_COMMITMENT, GENERAL_CONTEXT,
  ENVIRONMENT_CONTEXT, LEARNING_CONTEXT
- project event_class must be one of:
  PROJECT_STATE, WORKFLOW_STATE, FAILURE_GOTCHA, OBSERVATION
- project domain must be one of:
  BUILD_PROJECT, OPERATIONAL_CONTROL, MEMORY_SYSTEM, LIBRARY_GOVERNANCE,
  SHARED_GOVERNANCE, ENVIRONMENT_CONTEXT, GENERAL_CONTEXT
- If selected_project is null, emit no project event.
- When uncertain, emit no event.
"""

    def __init__(
        self,
        adapter: Any,
        *,
        profile_name: str | None = None,
        max_tokens: int = 520,
        timeout_seconds: int = 60,
    ) -> None:
        self.adapter = adapter
        self.profile_name = profile_name
        self.max_tokens = int(max_tokens)
        self.timeout_seconds = int(timeout_seconds)

    @staticmethod
    def _parse(text: str) -> dict[str, Any]:
        candidate = str(text or "").strip()
        fence = chr(96) * 3
        if candidate.startswith(fence):
            lines = candidate.splitlines()
            if lines and lines[0].strip().startswith(fence):
                lines = lines[1:]
            if lines and lines[-1].strip() == fence:
                lines = lines[:-1]
            candidate = "\n".join(lines).strip()
        value = json.loads(candidate)
        if not isinstance(value, dict) or set(value) != {"events"}:
            raise ValueError("pcmf_proposal_invalid_envelope")
        if not isinstance(value["events"], list) or len(value["events"]) > 2:
            raise ValueError("pcmf_proposal_invalid_event_count")
        return value

    def propose(
        self,
        *,
        user_message: str,
        selected_project: str | None,
    ) -> dict[str, Any]:
        request = {
            "current_user_message": " ".join(str(user_message).split()),
            "selected_project": selected_project,
        }
        result = self.adapter.generate(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        request,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            ],
            profile_name=self.profile_name,
            max_tokens=self.max_tokens,
            timeout_seconds=self.timeout_seconds,
            allow_fallback=False,
        )
        return self._parse(result.text)


class PcmfContinuityRuntime:
    def __init__(
        self,
        client: PcmfClient,
        *,
        proposal_provider: PcmfProposalProvider | None = None,
    ) -> None:
        self.client = client
        self.proposal_provider = proposal_provider

    def status(self, selected_project: str | None = None) -> dict[str, Any]:
        health = self.client.health()
        return {
            "enabled": True,
            "engine": health.get("engine"),
            "status": health.get("status"),
            "canonical_writer": health.get("canonical_writer"),
            "personal_project": PERSONAL_PROJECT,
            "project": selected_project,
            "personal_recall_enabled": True,
            "project_recall_enabled": bool(selected_project),
            "writes_requested": self.client.writes_requested,
            "writes_available": self.client.writes_available,
            "writer_hold": self.client.writer_hold,
            "mode": (
                "full_contract_writer_hold"
                if not self.client.writes_available
                else "full"
            ),
        }

    def prepare_context(
        self,
        *,
        selected_project: str | None,
        limit_per_lane: int = 5,
    ) -> PcmfPreparedContext:
        blocks: list[str] = []
        personal_count = 0
        project_count = 0
        canonical_writer = self.client.writer_hold

        personal = self.client.recall(
            project=PERSONAL_PROJECT,
            include_warm=True,
            limit=limit_per_lane,
        )
        personal_count = len(personal.items)
        canonical_writer = personal.canonical_writer
        personal_block = self.client.prompt_block(
            personal,
            lane="personal continuity",
        )
        if personal_block:
            blocks.append(personal_block)

        clean_project = str(selected_project or "").strip() or None
        if clean_project and clean_project != PERSONAL_PROJECT:
            project = self.client.recall(
                project=clean_project,
                include_warm=True,
                limit=limit_per_lane,
            )
            project_count = len(project.items)
            canonical_writer = project.canonical_writer
            project_block = self.client.prompt_block(
                project,
                lane=f"project continuity: {clean_project}",
            )
            if project_block:
                blocks.append(project_block)

        return PcmfPreparedContext(
            block="\n\n".join(blocks),
            personal_count=personal_count,
            project_count=project_count,
            project=clean_project,
            status="ok",
            canonical_writer=canonical_writer,
        )

    @staticmethod
    def _validate_event(
        event: dict[str, Any],
        *,
        user_message: str,
        selected_project: str | None,
    ) -> dict[str, Any]:
        required = {
            "lane",
            "evidence_quote",
            "subject",
            "domain",
            "event_class",
            "note",
            "confidence",
            "project_lifecycle",
        }
        if not isinstance(event, dict) or set(event) != required:
            raise ValueError("pcmf_proposal_event_schema")

        lane = str(event["lane"]).strip()
        quote = str(event["evidence_quote"]).strip()
        subject = str(event["subject"]).strip()
        domain = str(event["domain"]).strip()
        event_class = str(event["event_class"]).strip()
        note = str(event["note"]).strip()
        confidence = float(event["confidence"])
        lifecycle_raw = event["project_lifecycle"]
        lifecycle = None if lifecycle_raw is None else str(lifecycle_raw).strip().upper()
        if lifecycle not in {None, "COMPLETE"}:
            raise ValueError("pcmf_project_lifecycle_invalid")

        if not quote or quote not in user_message:
            raise ValueError("pcmf_evidence_not_exact")
        if not SUBJECT_RE.fullmatch(subject):
            raise ValueError("pcmf_subject_invalid")
        if not 3 <= len(note) <= 700 or not note.isprintable():
            raise ValueError("pcmf_note_invalid")
        if not MIN_CONFIDENCE <= confidence <= 1.0:
            raise ValueError("pcmf_confidence_too_low")

        if lane == "personal":
            if lifecycle is not None:
                raise ValueError("pcmf_personal_lifecycle_invalid")
            if event_class not in PERSONAL_CLASSES or domain not in PERSONAL_DOMAINS:
                raise ValueError("pcmf_personal_class_or_domain_invalid")
            project = PERSONAL_PROJECT
        elif lane == "project":
            if not selected_project:
                raise ValueError("pcmf_project_lane_without_project")
            if event_class not in PROJECT_CLASSES or domain not in PROJECT_DOMAINS:
                raise ValueError("pcmf_project_class_or_domain_invalid")
            if lifecycle == "COMPLETE" and (
                event_class != "PROJECT_STATE" or domain != "BUILD_PROJECT"
            ):
                raise ValueError("pcmf_project_completion_scope_invalid")
            project = selected_project
        else:
            raise ValueError("pcmf_lane_invalid")

        return {
            "lane": lane,
            "project": project,
            "subject": subject,
            "domain": domain,
            "event_class": event_class,
            "note": note,
            "confidence": confidence,
            "project_lifecycle": lifecycle,
        }

    def post_turn(
        self,
        *,
        user_message: str,
        selected_project: str | None,
    ) -> dict[str, Any]:
        if not self.client.writes_available:
            return {
                "status": "writer_hold",
                "writer_hold": self.client.writer_hold,
                "proposal_attempted": False,
                "admission_attempted": False,
                "stored": 0,
                "review_required": 0,
            }
        if not self.client.writes_requested:
            return {
                "status": "writes_disabled",
                "proposal_attempted": False,
                "admission_attempted": False,
                "stored": 0,
                "review_required": 0,
            }
        if self.proposal_provider is None:
            return {
                "status": "proposal_provider_disabled",
                "proposal_attempted": False,
                "admission_attempted": False,
                "stored": 0,
                "review_required": 0,
            }

        proposed = self.proposal_provider.propose(
            user_message=user_message,
            selected_project=selected_project,
        )
        events = [
            self._validate_event(
                row,
                user_message=user_message,
                selected_project=selected_project,
            )
            for row in proposed["events"]
        ]

        outcomes: list[dict[str, Any]] = []
        stored = 0
        reviews = 0
        for event in events:
            response = self.client.observe(
                project=event["project"],
                subject=event["subject"],
                domain=event["domain"],
                event_class=event["event_class"],
                note=event["note"],
                project_lifecycle=event["project_lifecycle"],
            )
            status = str(response.get("status") or "UNKNOWN")
            data = response.get("data") or {}
            if status == "OK" and data.get("stored") is True:
                stored += 1
            elif status == "REVIEW_REQUIRED":
                reviews += 1
            outcomes.append(
                {
                    "lane": event["lane"],
                    "project": event["project"],
                    "subject": event["subject"],
                    "event_class": event["event_class"],
                    "status": status,
                    "reason": response.get("reason"),
                    "stored": bool(data.get("stored")),
                    "review_token": (
                        data.get("review_token")
                        if status == "REVIEW_REQUIRED"
                        else None
                    ),
                }
            )

        return {
            "status": "complete",
            "proposal_attempted": True,
            "admission_attempted": bool(events),
            "proposed": len(events),
            "stored": stored,
            "review_required": reviews,
            "outcomes": outcomes,
        }

    def submit_project_milestone(
        self,
        *,
        project: str,
        subject: str,
        note: str,
        domain: str = "BUILD_PROJECT",
    ) -> dict[str, Any]:
        return self.client.observe(
            project=project,
            subject=subject,
            domain=domain,
            event_class="PROJECT_STATE",
            note=note,
        )

    def complete_project(
        self,
        *,
        project: str,
        note: str,
        subject: str = "ProjectLifecycle",
    ) -> dict[str, Any]:
        """Write an explicit project-completion state; PCMF derives COLD."""
        return self.client.observe(
            project=project,
            subject=subject,
            domain="BUILD_PROJECT",
            event_class="PROJECT_STATE",
            note=note,
            project_lifecycle="COMPLETE",
        )

    def set_memory_tier(
        self,
        *,
        project: str,
        subject: str,
        domain: str,
        tier: str,
        reason: str,
    ) -> dict[str, Any]:
        """Apply an explicit governed HOT/WARM/COLD tier change to an existing subject."""
        return self.client.tier_set(
            project=project,
            subject=subject,
            domain=domain,
            tier=tier,
            reason=reason,
        )
