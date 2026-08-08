# REVENG Phase 10 — Workers + external-tool CI + SEC-1 sandbox proofs (2026-08-07)

> **Authorization:** Phase 10 **only**. **Unauthorized** until Phase 9 stop/go = **go**.
> Prior gate: Phase 4 is currently **partial** — phases 5–13 remain unauthorized.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Extract heavy workers (Ghidra/dynamic/compile) with retries/timeouts/retention, land external-tool CI lanes (GA-P3), and **prove** Docker sandbox isolation class before any exploit-surface work.

## SEC sandbox proof prerequisite (hard stop)

**No exploit-surface expansion** — including scaffolding that creates an operational surface (new generators, CLI paths, watermark relaxation) — until all four Docker sandbox proofs pass as tests with failing control arms:

1. Process / FS isolation (canary outside scratch survives; write inside succeeds)
2. Network egress denied by default (specific errno; outside control succeeds)
3. Wall-clock and memory caps (infinite loop killed; short job completes)
4. No host credential inheritance (absent inside; present outside)

Cite: [`decision-r-sec-1-sandbox-class.md`](../../architecture/decision-r-sec-1-sandbox-class.md). R-SEC-1 decision alone is **not** proof.

**Track J** (exploit-development layer) is **forbidden** in this phase until those proofs land. Even after proofs, Track J requires a **separate** stop/go — do not auto-authorize exploit product work from green sandbox tests.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 9 stop/go | **go** | catalog |
| R-SEC-1 | decision done; **proofs open** | decision doc + Wave C exits |
| EPIC-8 / FEAT-4 / REV-SANDBOX | open | backlog J |
| GA-P3 | open — external-tool CI | backlog J |
| SEC-EXP-1 | watermark remains EXPERIMENTAL / non-GA | backlog A |

## Exit criteria (evidence predicates)

- [ ] Worker path: ≥1 heavy tool behind worker with timeout/retry fields in tracked logs/JSON; hung-job control fails closed.
- [ ] GA-P3: CI lane(s) for supported external tools with loud skip when tool absent (not silent green).
- [ ] **All four SEC sandbox proofs** green with documented bidirectional controls.
- [ ] Exploit tree / CLI watermark **unchanged** unless a later authorized Track J phase says otherwise.
- [ ] Backlog EPIC-8 / GA-P3 / REV-SANDBOX rows match measured state; Track J stays gated.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “Workers + external-tool CI **measured**; Docker sandbox **proofs** landed.” | “Exploit GA”, Track J shipped, watermark removal |
| Isolation class honesty for preview | Firecracker/gVisor required as Phase 10 exit |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Any exploit PR before four proofs | **Kill** + revert; cite R-SEC-1 |
| Sandbox check passes both arms | Broken oracle — park proofs |
| Tool absent claimed as capability | Rollback; use `tool_absent` / skip |

## Explicit non-goals

Track J product features; Phase 13 exploit demos; T3-* unpark; analyst packaging (Phase 11); blue-ocean; watermark relaxation; phases 11–13 product work beyond worker/CI/sandbox scope.
