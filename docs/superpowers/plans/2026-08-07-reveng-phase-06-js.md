# REVENG Phase 6 — JS close: RALPH-2 + bundler graph (2026-08-07)

> **Authorization:** Phase 6 **only**. **Unauthorized** until Phase 5 stop/go = **go**.
> Prior gate: Phase 4 is currently **partial** — phases 5–13 remain unauthorized.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Close JS product exits for RALPH-2 engine recall and P4 bundler-aware import-graph scoring — measured, not harness-only.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 5 stop/go | **go** | catalog |
| Phase 3 BP-1..4 | **done** | backlog B |
| R-RALPH-2-BASELINE | **done** | `research-r-ralph-2-baseline.md` |
| R-RALPH-2 | **open** — must close or waive with tracked rationale before large engine build | backlog D |
| RALPH-1 | partial OK; domain recall separate | backlog C |
| RALPH-2 / P4-BUNDLER | open | backlog F/J |

## Exit criteria (evidence predicates)

- [ ] R-RALPH-2 wedge chosen + implemented; tracked `cli.js` recall moves toward **0.8+** with before/after numbers in a named report path.
- [ ] Control: unchanged harness / no-wedge arm does **not** meet the exit number (bidirectional).
- [ ] P4-BUNDLER: precision/recall (or documented proxy) on tracked bundler fixture; empty graph ≠ pass.
- [ ] Customer-path: `reveng-js` / app RE path exercises scoring (not unit-only).
- [ ] Backlog RALPH-2 / P4-BUNDLER / R-RALPH-2 rows match measured state.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “JS RALPH-2 / bundler graph **measured** at reported recall/precision.” | “Full JS deobfuscation GA”, Scope C complete |
| Behavior-backed preview language already shipped in Phase 3 | Claiming BP work as Phase 6 |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| R-RALPH-2 still open with no waiver | **Do not authorize** large engine PR |
| Recall gain unmeasurable (`could_not_measure`) | Keep RALPH-2 open; no fake 0.8 |
| Wrong claim | Rollback CEO/backlog language |

## Explicit non-goals

Native partial_equivalence; MCP productization; workers; SEC proofs; Track J; T3-*; V6 frontend futures; phases 7–13 product work.
