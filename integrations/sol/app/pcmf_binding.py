"""Persisted PCMF project binding for Sol.

PCMF memories are project-scoped. Sol's identity session currently carries a
profile id but no project pointer, so recall must never guess or blend projects.
This module persists one explicit project selection for the next/live Sol
runtime once PCMF integration is enabled.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = PROJECT_ROOT / "runtime_state" / "pcmf"
STATE_PATH = STATE_DIR / "selection.json"
PROJECT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")

DEFAULT_KNOWN_PROJECTS = (
    "AdaneliLearning",
    "FORGE_GPT_LIBRARY",
    "KnowledgeDrive",
    "MINI_ANVIL_COMMANDER_PROVING",
    "PCMFDevelopment",
)


def known_projects() -> tuple[str, ...]:
    raw = os.environ.get("SOL_PCMF_KNOWN_PROJECTS", "").strip()
    if raw:
        values = tuple(
            item.strip()
            for item in raw.split(",")
            if item.strip() and PROJECT_RE.fullmatch(item.strip())
        )
        if values:
            return tuple(dict.fromkeys(values))
    return DEFAULT_KNOWN_PROJECTS


def _secure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE_DIR, 0o700)


def get_selected_project() -> str | None:
    try:
        raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    if not isinstance(raw, dict):
        return None
    project = raw.get("project")
    if not isinstance(project, str) or not PROJECT_RE.fullmatch(project):
        return None
    return project


def set_selected_project(project: str | None) -> dict[str, Any]:
    _secure_state_dir()

    if project is None or not str(project).strip():
        try:
            STATE_PATH.unlink()
        except FileNotFoundError:
            pass
        return {"project": None, "configured": False}

    cleaned = str(project).strip()
    if not PROJECT_RE.fullmatch(cleaned):
        raise ValueError("invalid_pcmf_project")

    payload = {
        "schema": 1,
        "project": cleaned,
    }

    fd, tmp_name = tempfile.mkstemp(
        prefix=".selection.",
        suffix=".tmp",
        dir=str(STATE_DIR),
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, STATE_PATH)
        os.chmod(STATE_PATH, 0o600)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

    return {"project": cleaned, "configured": True}
