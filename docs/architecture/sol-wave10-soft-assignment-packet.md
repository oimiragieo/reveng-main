# Sol audit packet — Wave 10 soft-assign + tombstones

**Branch:** `feat/wave10-soft-assignment`  
**PR:** #150  
**Plan / research:** `docs/architecture/research-wave10-soft-assignment-2026-08-10.md`  
**CEO:** `docs/architecture/ceo-update-2026-08-10-wave10.md`  
**Thinktank (2026-08-21):** Option 1 — close Wave 10 before any all-backlog / Wave 11 work (L33).

## Must verify

1. `soft_assignment.py` — `scipy.optimize.linear_sum_assignment` (Hungarian) on blended word/char TF-IDF cosines + margin gate; notes include `soft_assignment_hungarian`.
2. Wired in `iterative_defrag.py` via `soft_assign_sources_to_bundle` / `_soft_assign_unlock`.
3. `tombstone.py` — unique-token residue tombstones + `recoverable_oracle_coverage`; wired in `pipeline.py` stage `tombstone`.
4. Unit: `tests/unit/test_wave10_soft_assignment.py` — 5 hermetic tests (Hungarian beats greedy; margin; tombstone shared/absent; soft_assign match).
5. Honesty framing intact: unlockable/survivor ship bar **1.0**; full-oracle 100% on stale-map SEA with unique-token tombstones is **not** honest; R-RALPH-2 / enterprise GA / Phase 6 exe decode stay **open**.
6. tip2 is pin-only vs tip1 (L47). Merge bar = honesty-unit + lint-python + this Sol verdict (L50); matrix soft-reds are L42 unless wave-scoped.

## Forbidden claims

- “Complete all backlog” / enterprise GA / world-class product closeout
- Full-oracle 100% on ~874 unique-token tombstones without same-era map / embedded SerializedSourceMap
- Fake `ghidramcp>=0.1.0` pin

## Exa re-verify (2026-08-21, closeout)

Prior art cited in research doc remains the inspiration set (Sinkhorn lifted assignment; unsupervised clone similarity ensembles). Exact Hungarian on bipartite TF-IDF blend is the hermetic ship; Sinkhorn/neural stay optional research lanes.

## Verdict file

`docs/architecture/sol-wave10-soft-assignment-verdict.md`
