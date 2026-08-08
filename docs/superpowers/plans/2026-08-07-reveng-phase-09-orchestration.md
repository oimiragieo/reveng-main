# REVENG Phase 9 — Orchestration + modular monolith / ports (2026-08-07)

> **Authorization:** Phase 9 **only**. **Unauthorized** until Phase 8 stop/go = **go**.
> Prior gate: Phase 4 is currently **partial** — phases 5–13 remain unauthorized.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Reconcile orchestration layers and extract ports for analyze/decomp/AI/recon/validate/report — with `result_contracts` threaded uniformly (P6-PLATFORM) — without claiming microservice completion.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 8 stop/go | **go** | catalog |
| R-PIPE-1 | **done** — permanent documented split (merge optional) | `decision-r-pipe-1-pipeline-packages.md` |
| M5 / M5-PIPE | open / partial | backlog C |
| EPIC-3 / EPIC-4 / P6-PLATFORM | open | backlog J |
| M0–M4 | M4 should be **go** from Phase 5; residual must be named if waived | backlog |

## Exit criteria (evidence predicates)

- [ ] Documented boundary: `pipeline/` vs `pipelines/` matches R-PIPE-1; any merge has bidirectional tests.
- [ ] At least one ported bounded context callable from CLI/API with `result_contracts` fields present; missing contract fails.
- [ ] Import-linter contracts updated/green for new boundaries (`lint-imports --no-cache`).
- [ ] P6-PLATFORM: MCP/API path shows uniform evidence fields vs CLI on one golden fixture.
- [ ] Backlog M5 / EPIC-3/4 / P6-PLATFORM rows match measured state.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “Orchestration / ports **measured** under named boundaries.” | “Full microservices extraction”, Scope C complete |
| Permanent split freeze language (already decided) | Treating disposition as capability `done` |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Import cycle / contract break | **Kill** merge; restore boundaries |
| Port exists only in unit tests | Do not claim productized |
| Wrong architecture claim | Rollback CEO/backlog |

## Explicit non-goals

Heavy worker extraction (Phase 10); SEC sandbox proofs; Track J; customer packaging GA-P4; blue-ocean; T3-*; phases 10–13 product work.
