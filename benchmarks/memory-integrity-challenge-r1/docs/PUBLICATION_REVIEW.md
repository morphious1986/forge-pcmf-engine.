# Publication review and release gate — R1

**State:** source-only **candidate**, not published. No claim of external review, production integration, security certification, or general model ranking.

## Proposed scope for public review

New path inside the existing public GitHub repository `morphious1986/forge-pcmf-engine.`:
`benchmarks/memory-integrity-challenge-r1/`.

This would be a separately reviewable branch/PR after specific owner authorization and an exact file/hash review. It must not be merged into `main` or deployed merely because the package passes isolated tests.

## Inclusion manifest

- `README.md`: introduction and commands
- `LICENSE`: standard Apache License 2.0 text
- `scorer.py`: reproducible Python 3 standard-library scorer
- `data/events.jsonl`: fictional event records
- `data/tasks.jsonl`: participant-visible questions
- `data/gold.jsonl`: separate **public** answer key; **exclude from prompts**
- `examples/*.jsonl`: submission examples, oracle self-test, naive negative control
- `baselines/latest_timestamp.py`: intentionally weak comparison baseline
- `tests/test_challenge.py`: reproducibility/negative-path tests
- `docs/*.md`: scoring, participation, outreach drafts and safety/review notes
- `SHA256SUMS` and `VALIDATION_REPORT.json`: independently checkable local receipts

## Required review before GitHub publication

- Confirm no private/project-origin dataset or host/machine identifiers.
- Inspect license and avoid third-party sources without compatible rights.
- Check score invariants, JSON input fail-closed rules, and full test transcript.
- Audit question wording for answer leakage; `gold.jsonl` is separate from `tasks.jsonl`.
- Verify every file byte-equal after any GitHub upload, with SHA-256.
- Confirm benchmark limitations are prominent, and that no unmeasured model performance is claimed.
- Owner approves the exact repository, review branch, paths, files, license and public text.
- Leave existing PCMF main and native installed writer unchanged.

## Known limitations / deliberate simplifications

1. **Synthetic authority annotations are trusted as inputs.** The benchmark does not cryptographically verify a publisher, prove a signature, or establish real provenance.
2. **Open source answer key is public.** Scores are transparent regression signals, not blind competition standings.
3. **Twelve small handcrafted cases** cannot characterize broad language-model memory behavior, long-term retention, scaling, or tool execution.
4. Correct resolution policy is context-specific; other policies can reasonably dispute the gold cases.
5. The scorer checks responses against reference labels; it does not determine if an agent truly reasoned, retrieved data appropriately, or copied labels.
6. No network, production memory service, owner review API, persistent state, deployment or memory updates are exercised.
7. External reviewers have not validated the suite; initial test results are local only.

## Owner review status

- Local code and synthetic fixtures: staged
- Isolated tests: see `VALIDATION_REPORT.json`
- Independent USB archive: see outer USB checksum receipt
- Public GitHub push/PR: **not authorized in this package**
- Colony outreach: **draft only**, not published
