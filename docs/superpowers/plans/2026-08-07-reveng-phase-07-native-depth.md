# REVENG Phase 7 — Native depth → partial_equivalence + multi-file (2026-08-07)

> **Authorization:** Phase 7 **only**. **Unauthorized** until Phase 6 stop/go = **go**.
> Prior gate: Phase 4 is currently **partial** — phases 5–13 remain unauthorized.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Advance native reconstruction from fixture/preview depth to measured entry-reachable **partial_equivalence** and multi-file synthesis (P5-NATIVE-EQ) without hollow `required: true`.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 6 stop/go | **go** | catalog |
| R-NATIVE-1 | **done** | research doc |
| M1-NATIVE-FAM | open until analyze ≤120s without Ghidra on tracked fixtures | backlog C |
| P5-NATIVE-EQ | open | backlog F |
| DF-5 | **done** — process `completed` ≠ native GA | backlog H |
| Probe ≥1.3 | stream attribution honest | Phase 4 |

## Exit criteria (evidence predicates)

- [ ] Tracked native subject(s): entry→helper chain yields `partial_equivalence` (or named grade) in opened JSON — not process-exit alone.
- [ ] Multi-file synthesis evidenced on ≥1 tracked multi-TU fixture; single-file-only path must **fail** the multi-file predicate (control).
- [ ] `required: true` flip only if analyze ≤120s **without** Ghidra on the fixture set; else stay `required: false` / `fixture_only`.
- [ ] Customer-path: `python -m reveng analyze` on fixtures; stamp ≡ `latest.json` where probe used.
- [ ] Backlog P5-NATIVE-EQ / M1-NATIVE-FAM rows match measured state.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “Native **partial_equivalence** measured on named fixtures.” | “Native GA / full binary↔source equivalence” |
| Limited / preview rebuild language | Hollow `required: true` from DF-5 `completed` |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Analyze timeout / Ghidra-only path | Keep preview; do not flip required |
| Semantic fields empty under process green | **Kill** claim; cite DF-5 |
| Wrong matrix language | Rollback support_matrix / CEO text |

## Explicit non-goals

MCP installable product; orchestration ports; workers; SEC sandbox proofs; Track J exploit; T3-KERNEL/PACKED/ANTI; phases 8–13 product work.
