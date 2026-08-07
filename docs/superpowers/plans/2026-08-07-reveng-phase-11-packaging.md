# REVENG Phase 11 — Analyst / governance / packaging (GA-P4) (2026-08-07)

> **Authorization:** Phase 11 **only**. **Unauthorized** until Phase 10 stop/go = **go**.
> Prior gate: Phase 4 is currently **partial** — phases 5–13 remain unauthorized.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Ship customer packaging and analyst governance surfaces — support matrix, troubleshooting, RELEASE_CHECKLIST, review/policy hooks — matched to measured capability grades.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 10 stop/go | **go** (includes SEC proofs if exploit language is touched) | catalog |
| GA-P4 / EPIC-9 / FEAT-5 / FEAT-7 | open | backlog J |
| REV-ANNOTATE / PROF-SHIM-4 | open (optional; declare in stop/go) | backlog J |
| `support_matrix` honesty | claims must match matrix grades | release-honesty skill |

## Exit criteria (evidence predicates)

- [ ] Live support matrix + RELEASE_CHECKLIST paths exist and are linked from docs; stale “GA” strings for experimental surfaces **fail** a honesty grep/test.
- [ ] Analyst/governance path: ≥1 review or policy gate wired from product path; missing auth/policy fails closed where claimed.
- [ ] Troubleshooting notes cite measured grades (preview / limited / experimental), not aspirational GA.
- [ ] Bidirectional: fixture claiming GA for exploits or T3-* must fail the packaging honesty check.
- [ ] Backlog GA-P4 / EPIC-9 / FEAT-5/7 rows match measured state.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “Customer packaging / governance **shipped** aligned to support matrix.” | “Full Scope C GA”, native/exploit GA without evidence |
| Preview packaging language | Unparking T3-* via docs |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Matrix overclaims capability | **Kill** release language; fix matrix first |
| Shim retirement without API policy | Park PROF-SHIM-4 |
| Exploit docs without SEC proofs | Revert; cite Phase 10 gate |

## Explicit non-goals

Platform IR/RAG/KG depth (Phase 12); blue-ocean (Phase 13); Track J unless separately authorized post-SEC proofs; T3-* depth; phases 12–13 product work.
