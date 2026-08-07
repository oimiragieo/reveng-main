# REVENG Phase 5 — Equivalence product gates + CI corpus (2026-08-07)

> **Authorization:** Phase 5 **only**. **Unauthorized** until Phase 4 stop/go = **go**.
> Phase 4 is currently **partial** (M2 **partial** — Track A honesty only; VRL LLM `could_not_measure`) — do not execute this plan.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Close equivalence product gates and full CI/PR/nightly corpus enforcement (M4 residual) without hollow GA flips or Scope C blanket claims.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 4 stop/go | **go** (not partial) | backlog §E; VRL-LLM-1 measured |
| M4 | thin honesty workflow landed; corpus residual **open** | backlog C/J |
| EPIC-7 / FEAT-2 | open — equivalence validation service | backlog J |
| REV-P1-CI-CORPUS | open — regression-gated corpus | backlog J |
| R-SEC-1 | decision only; **no exploit expansion** | `decision-r-sec-1-sandbox-class.md` |
| M1-NATIVE-FAM | may remain open; no hollow `required: true` | DF-5 |

## Exit criteria (evidence predicates)

- [ ] Nightly/PR corpus gate **blocks** on tracked corpus miss (not honesty-only); workflow path + failing control job recorded.
- [ ] Equivalence path writes a real grade/status into a tracked report (`reports/` or `.reveng/`); empty fixture **fails** the gate (bidirectional).
- [ ] Customer-path wiring: CLI or enrich invokes equivalence helper (not unit-only stub).
- [ ] `verify_ga_readiness.py --profile baseline` **and** `--profile ga` green with opened JSON fields matching claims.
- [ ] Backlog M4 / EPIC-7 / FEAT-2 / REV-P1-CI-CORPUS rows match measured state.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “Equivalence + CI corpus gates **measured** under named workflows/corpus.” | “Scope C complete”, phases 6–13 done |
| Preview / non-GA where matrix says so | Native GA from process `completed` alone |
| Exploits remain EXPERIMENTAL / non-GA | Any exploit-surface expansion |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Gate passes empty evidence | **Kill** — hollow; fix oracle before merge |
| Corpus assets absent in CI | Loud skip / local-only; never claim CI measured |
| Wrong CEO/backlog claim | Rollback claim text; restore honest status |

## Explicit non-goals

RALPH-2 → 0.8; P5-NATIVE-EQ product depth; MCP installable product; workers extraction; SEC sandbox **proofs**; Track J; T3-* unpark; phases 6–13 product work.
