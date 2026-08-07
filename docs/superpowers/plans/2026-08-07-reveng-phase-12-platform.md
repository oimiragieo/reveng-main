# REVENG Phase 12 — Platform depth (IR, Ralph opt, RAG, KG start) (2026-08-07)

> **Authorization:** Phase 12 **only**. **Unauthorized** until Phase 11 stop/go = **go**.
> Prior gate: Phase 4 is currently **partial** — phases 5–13 remain unauthorized.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Advance platform depth — IR/whole-program context, retrieval-augmented binary context, fingerprint/KG/state starts, recompilation developer kit — as **measured previews**, with honest `deferred`/`parked` dispositions when not release-blocking.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 11 stop/go | **go** | catalog |
| FEAT-3 / FEAT-10 | open | backlog J |
| REV-STATE / REV-FINGERPRINT / REV-KG / REV-VARIANT / REV-SELF-IMPROVE | open | backlog J |
| REV-P1-WHOLE-PROGRAM | open | backlog J |
| Thinktank note | Phase 12–13 may close as `wontfix`/`parked`/`deferred` with rationale — never hollow GA | master plan audit |

## Exit criteria (evidence predicates)

- [ ] Each claimed slice has a tracked artifact (report/JSON/schema) with non-empty measured fields; empty RAG/KG stub fails bidirectional check.
- [ ] Customer-path or documented opt-in CLI for each shipped slice; unit-only helpers do not count.
- [ ] Items not shipped this phase receive explicit `deferred`/`parked`/`wontfix` with reconsideration trigger — disposition ≠ `done`.
- [ ] No exploit-surface or T3-* claims.
- [ ] Backlog rows for chosen slices match measured state; others dispositioned honestly.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “Platform depth **preview** on named slices (IR/RAG/KG/…).” | “Full platform / v6 GA”, Scope C complete |
| Deferred disposition language | Treating deferred as capability done |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Slice cannot be measured | Park/defer with rationale; no fake green |
| Overclaim in matrix/CEO | Rollback claim text |
| Exploit scaffolding appears | **Kill** — cite Phase 10 SEC proofs + charter |

## Explicit non-goals

Blue-ocean futures (Phase 13); Track J; T3-* unpark; mandatory Neo4j/Kuzu production; phases 13 product work.
