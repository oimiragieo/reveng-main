# REVENG Phase 5 — Equivalence product gates + CI corpus (2026-08-07)

> **Authorization:** Phase 5 **thin honesty slice** Sol-`APPROVE` 2026-08-07
> (`docs/architecture/decision-phase-05-thin-honesty-auth.md`). Full Phase 5 exit
> criteria remain **partial/open** (nightly corpus residual).
> Phase 4 honesty go: `decision-phase-04-honesty-go-waiver.md` (M2 remains partial).
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Close equivalence product gates and full CI/PR/nightly corpus enforcement (M4 residual) without hollow GA flips or Scope C blanket claims.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 4 stop/go | **go** (honesty) — landed | backlog §E; waiver |
| M4 | thin honesty + Phase 5 evidence gate landed; corpus residual **open** | backlog C/J |
| EPIC-7 / FEAT-2 | **partial** — thin helper/report/CI; full service open | backlog J |
| REV-P1-CI-CORPUS | **partial** — thin evidence CI; full corpus residual | backlog J |
| R-SEC-1 | decision only; **no exploit expansion** | `decision-r-sec-1-sandbox-class.md` |
| M1-NATIVE-FAM | may remain open; no hollow `required: true` | DF-5 |
| M2 | remains **partial** — entry dep for hexyl/native-equivalence depth | backlog |

## Exit criteria (evidence predicates)

- [x] Thin CI evidence gate **blocks** on missing/empty equivalence report (`.github/workflows/wave-c-phase5-honesty.yml`); empty fixture fails bidirectional.
- [ ] Nightly/PR **full corpus** gate blocks on tracked corpus miss (not honesty-only) — **open** (M4 residual).
- [x] Equivalence path writes a real grade/status into a tracked report (`reports/equivalence_honesty/latest.json`); empty fixture **fails** the gate (bidirectional).
- [x] Customer-path wiring: `scripts/verify_equivalence_honesty.py` (+ Makefile `verify-equivalence-honesty`) invoked by CI (not unit-only stub).
- [ ] `verify_ga_readiness.py --profile baseline` **and** `--profile ga` green with opened JSON fields matching claims (dogfood each PR).
- [x] Backlog M4 / EPIC-7 / FEAT-2 / REV-P1-CI-CORPUS rows match measured **partial** state (full product/nightly still open).

## Permitted release claim vs forbidden

| Permitted after thin go | Forbidden |
| --- | --- |
| “Phase 5 thin equivalence honesty gate **measured** under named workflow/report.” | “Scope C complete”, phases 6–13 done, Phase 5 full exit |
| Preview / non-GA where matrix says so | Native GA from process `completed` alone; M2 done |
| Exploits remain EXPERIMENTAL / non-GA | Any exploit-surface expansion |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Gate passes empty evidence | **Kill** — hollow; fix oracle before merge |
| Corpus assets absent in CI | Loud skip / local-only; never claim CI measured |
| Wrong CEO/backlog claim | Rollback claim text; restore honest status |

## Explicit non-goals

RALPH-2 → 0.8; P5-NATIVE-EQ product depth; MCP installable product; workers extraction; SEC sandbox **proofs**; Track J; T3-* unpark; phases 6–13 product work; full nightly corpus; native `required: true`.
