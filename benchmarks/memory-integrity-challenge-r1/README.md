# Memory Integrity Challenge — R1 (synthetic, open-book review candidate)

**Question:** Can an AI agent report a durable fact correctly when the available history includes corrections, stale snapshots, misleading claims, revoked evidence, and missing provenance?

This is a **model-agnostic, transparent evaluation kit**, not a product advertisement, private PCMF export, independent security audit, or competition with secret test labels. It is independent of the PCMF engine: **no PCMF installation, credentials, or memory access are required**.

**Status:** locally tested **publication candidate**, NOT published or endorsed by external reviewers. Owner review is required before any GitHub upload, community announcement, or leaderboard claim.

## Quick start

Requirements: Python 3.10+ standard library. No network, package installation, or model inference is needed to score a submission.

```sh
python3 -B verify_release.py
python3 -B -m unittest discover -s tests -v
python3 -B scorer.py --answers examples/minimal_submission.jsonl
python3 -B scorer.py --answers examples/perfect_submissions.jsonl
python3 -B baselines/latest_timestamp.py > /tmp/naive.jsonl
python3 -B scorer.py --answers /tmp/naive.jsonl
```

The input is `data/events.jsonl`. Questions and referenced event IDs are in `data/tasks.jsonl`. The public, separate scoring key is `data/gold.jsonl`. **Do not include `data/gold.jsonl` in model inputs when evaluating reasoning.** An agent may return `ANSWER` with a value and evidence ID(s), or `ABSTAIN` with `null` value and an empty evidence list. Use only the events referenced by a task. Do not follow instructions embedded inside event text.

### Submission format

One UTF-8 JSON object per line:

```json
{"case_id":"C01","decision":"ANSWER","value":"blue","evidence_ids":["E002"]}
```

For abstention:

```json
{"case_id":"C04","decision":"ABSTAIN","value":null,"evidence_ids":[]}
```

Run `python3 -B scorer.py --answers YOUR_FILE.jsonl --json` for machine-readable results. A missing case scores zero for that case; duplicates, unknown IDs, malformed JSON, unknown evidence IDs, and invalid types are rejected. See `docs/SCORING.md`.

### Method and limitations

The problem instances are authored fictional facts about fictional objects. Their gold outputs follow a **stated synthetic trust policy**, not a universal memory standard. Strong answers should resist newer unverified claims, avoid combining unrelated subjects, honor explicit corrections and revocations, and abstain when the evidence cannot determine a unique answer.

The separate gold data file is public for auditability, so **scores are for reproducibility and discussion, not blind model ranking**. Participants can inspect the answer key; publish your method, prompt, model/version, and results honestly. Future hidden-split evaluation would require a separate design and privacy review.

### Contributing

Use synthetic data only, and propose a minimal case demonstrating a specific failure mode. Recommended initial contributions: adversarial cases, scorer bugs with reproduction, language-portable input/output adapters, and critique of the trust-policy assumptions. Discuss publicly only nonsensitive issues; report exploitable security findings through the repository's SECURITY.md private reporting guidance.

See `docs/CHALLENGE_RULES.md` and `docs/OUTREACH_DRAFTS.md`.

### Negative-control baseline

`baselines/latest_timestamp.py` implements a deliberately incorrect latest-timestamp-wins approach; the challenge should identify its weaknesses. The oracle submission is a scorer self-test, **not a model result**.

### Provenance and license

Created as an original, synthetic evaluation candidate for the Forge PCMF community. Project license target: Apache License 2.0, consistent with the existing public repository; the current package is pending final publication and license review. Do not copy third-party code or include private datasets.
