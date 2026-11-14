#!/usr/bin/env python3
"""Intentionally naive negative-control baseline. NOT an endorsed memory policy."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
events = [json.loads(line) for line in (ROOT / "data/events.jsonl").read_text(encoding="utf-8").splitlines() if line]
tasks = [json.loads(line) for line in (ROOT / "data/tasks.jsonl").read_text(encoding="utf-8").splitlines() if line]
by_id = {event["event_id"]: event for event in events}

for task in tasks:
    # Ignores source authority, corrections, revocation, subject and conflicts.
    latest = max((by_id[eid] for eid in task["event_ids"]), key=lambda e: (e["timestamp"], e["event_id"]))
    value = latest["value"]
    row = {"case_id": task["case_id"],
           "decision": "ABSTAIN" if value is None else "ANSWER",
           "value": value,
           "evidence_ids": [] if value is None else [latest["event_id"]]}
    print(json.dumps(row, sort_keys=True, ensure_ascii=False))
