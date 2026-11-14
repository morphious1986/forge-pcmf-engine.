#!/usr/bin/env python3
"""Memory Integrity Challenge R1: stdlib-only deterministic scorer.

All input records are fictional and public. No production memory writer is invoked.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVENTS = ROOT / "data" / "events.jsonl"
TASKS = ROOT / "data" / "tasks.jsonl"
GOLD = ROOT / "data" / "gold.jsonl"
PREDICTION_KEYS = frozenset({"case_id", "decision", "value", "evidence_ids"})
MAX_LINE_BYTES = 100_000


class SubmissionError(ValueError):
    pass


def _unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise SubmissionError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def read_jsonl(path):
    records = []
    with Path(path).open("rb") as stream:
        for line_no, raw in enumerate(stream, 1):
            if len(raw) > MAX_LINE_BYTES:
                raise SubmissionError(f"{path}:{line_no}: record too large")
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise SubmissionError(f"{path}:{line_no}: invalid UTF-8/JSON") from exc
            if not isinstance(obj, dict):
                raise SubmissionError(f"{path}:{line_no}: expected JSON object")
            records.append(obj)
    return records


def load_fixture(events_path=EVENTS, tasks_path=TASKS, gold_path=GOLD):
    ev_rows, task_rows = read_jsonl(events_path), read_jsonl(tasks_path)
    gold_rows = read_jsonl(gold_path)
    keyed_gold = {}
    for g in gold_rows:
        cid = g.get("case_id")
        if not isinstance(cid, str) or cid in keyed_gold:
            raise SubmissionError("duplicate/invalid gold case_id")
        keyed_gold[cid] = {k: v for k, v in g.items() if k != "case_id"}
    if not ev_rows or not task_rows:
        raise SubmissionError("empty fixture")
    events = {}
    for ev in ev_rows:
        eid = ev.get("event_id")
        if not isinstance(eid, str) or eid in events:
            raise SubmissionError("duplicate/invalid fixture event_id")
        if ev.get("authority") not in {"verified", "approved", "unverified", "pending"}:
            raise SubmissionError("unsupported fixture authority")
        events[eid] = ev
    tasks = {}
    for row in task_rows:
        cid = row.get("case_id")
        if not isinstance(cid, str) or cid in tasks:
            raise SubmissionError("duplicate/invalid fixture case_id")
        ids = row.get("event_ids")
        gold = keyed_gold.get(cid)
        if not isinstance(ids, list) or not ids or any(i not in events for i in ids):
            raise SubmissionError(f"{cid}: missing reference event")
        if len(set(ids)) != len(ids):
            raise SubmissionError(f"{cid}: duplicate reference event")
        if any(events[i]["case_id"] != cid for i in ids):
            raise SubmissionError(f"{cid}: cross-case reference")
        if not isinstance(gold, dict):
            raise SubmissionError(f"{cid}: missing gold")
        validate_response(gold, cid, set(ids), require_case_id=False)
        if gold["decision"] == "ANSWER":
            evidence = gold["evidence_ids"]
            if not evidence or not any(events[eid]["value"] == gold["value"] for eid in evidence):
                raise SubmissionError(f"{cid}: gold answer lacks support")
            if any(events[eid]["authority"] not in {"verified", "approved"} for eid in evidence):
                raise SubmissionError(f"{cid}: gold answer uses unverified evidence")
        else:
            if gold["value"] is not None or gold["evidence_ids"]:
                raise SubmissionError(f"{cid}: invalid abstention gold")
        tasks[cid] = dict(row, gold=gold)
    if set(keyed_gold) != set(tasks):
        raise SubmissionError("mismatched gold/tasks case IDs")
    if set(events) != {eid for row in tasks.values() for eid in row["event_ids"]}:
        raise SubmissionError("unreferenced event in fixture")
    return events, tasks


def validate_response(row, case_id, allowed_event_ids, *, require_case_id=True):
    keys = set(row)
    expected_keys = PREDICTION_KEYS if require_case_id else PREDICTION_KEYS - {"case_id"}
    if keys != expected_keys:
        raise SubmissionError(f"{case_id}: wrong fields")
    if require_case_id and row["case_id"] != case_id:
        raise SubmissionError(f"{case_id}: id mismatch")
    if row["decision"] not in ("ANSWER", "ABSTAIN"):
        raise SubmissionError(f"{case_id}: decision must be ANSWER or ABSTAIN")
    if row["decision"] == "ANSWER" and (not isinstance(row["value"], str) or not row["value"]):
        raise SubmissionError(f"{case_id}: ANSWER must contain nonempty string value")
    if row["decision"] == "ABSTAIN" and row["value"] is not None:
        raise SubmissionError(f"{case_id}: ABSTAIN must contain JSON null value")
    ids = row["evidence_ids"]
    if not isinstance(ids, list) or any(not isinstance(x, str) for x in ids):
        raise SubmissionError(f"{case_id}: evidence_ids must be string list")
    if len(ids) != len(set(ids)):
        raise SubmissionError(f"{case_id}: duplicate evidence ID")
    if not set(ids) <= allowed_event_ids:
        raise SubmissionError(f"{case_id}: unknown/cross-case evidence ID")
    if row["decision"] == "ABSTAIN" and ids:
        raise SubmissionError(f"{case_id}: ABSTAIN must have empty evidence_ids")


def score_rows(rows, tasks, events):
    predictions = {}
    for row in rows:
        cid = row.get("case_id")
        if not isinstance(cid, str) or cid not in tasks:
            raise SubmissionError("unknown or missing case_id")
        if cid in predictions:
            raise SubmissionError(f"{cid}: duplicate submission")
        validate_response(row, cid, set(tasks[cid]["event_ids"]))
        predictions[cid] = row
    results = []
    for cid, task in tasks.items():
        gold = task["gold"]
        pred = predictions.get(cid)
        decision_match = pred is not None and pred["decision"] == gold["decision"]
        value_match = decision_match and pred["value"] == gold["value"]
        evidence_match = value_match and set(pred["evidence_ids"]) == set(gold["evidence_ids"])
        points = (2 if decision_match else 0) + (2 if value_match else 0) + (1 if evidence_match else 0)
        results.append({"case_id": cid, "points": points, "max_points": 5,
                        "decision_correct": bool(decision_match),
                        "value_correct": bool(value_match),
                        "evidence_correct": bool(evidence_match),
                        "submitted": pred is not None})
    return {"score": sum(r["points"] for r in results),
            "max_score": len(tasks)*5,
            "submitted_cases": len(predictions), "total_cases": len(tasks),
            "perfect_cases": sum(r["points"] == 5 for r in results),
            "case_results": results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--answers", required=True, help="UTF-8 JSONL predictions")
    parser.add_argument("--json", action="store_true", help="machine-readable result")
    args = parser.parse_args(argv)
    try:
        events, tasks = load_fixture()
        result = score_rows(read_jsonl(args.answers), tasks, events)
    except (SubmissionError, OSError) as exc:
        print(f"INVALID_SUBMISSION: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"SCORE {result['score']}/{result['max_score']} | "
              f"submitted {result['submitted_cases']}/{result['total_cases']} | "
              f"perfect cases {result['perfect_cases']}")
        for r in result["case_results"]:
            print(f"{r['case_id']}: {r['points']}/5 "
                  f"({'submitted' if r['submitted'] else 'missing'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
