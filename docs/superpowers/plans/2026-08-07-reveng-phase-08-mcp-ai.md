# REVENG Phase 8 — MCP + AI ops productization (2026-08-07)

> **Authorization:** Phase 8 **only**. **Unauthorized** until Phase 7 stop/go = **go**.
> Prior gate: Phase 4 is currently **partial** — phases 5–13 remain unauthorized.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **Catalog:** [`docs/architecture/scope-c-phase-catalog-contracts.md`](../../architecture/scope-c-phase-catalog-contracts.md)

**Goal:** Stabilize MCP as an installable product surface and harden Ollama/AI routing with measured schemas, auth/rate/audit hooks — without inventing GA for experimental AI paths.

## Entry dependencies / research blockers

| Dep | Required state | Source |
| --- | --- | --- |
| Phase 7 stop/go | **go** | catalog |
| M3 / EPIC-1–2 residuals | schemas/evidence may still be partial — close or scope explicitly | backlog C/J |
| EPIC-5 / REV-MCP / FEAT-8 | open | backlog J |
| EPIC-6 / FEAT-9 | open — Ollama profiles/routing | backlog J |
| REV-SUBAGENTS / REV-JOURNAL | open (optional slice; declare in stop/go) | backlog J |
| R-VRL-1 | decision stands (`min_seeds: 3`, ollama) | decision doc |

## Exit criteria (evidence predicates)

- [ ] Install/smoke path for MCP server documented + tested (`pip`/entry point); missing auth config **fails** closed where claimed.
- [ ] Top-level `validation_grade` / `capability_report` (or successor contract) present on customer MCP responses; empty stub fails bidirectional check.
- [ ] Ollama routing: provider identity + latency/fallback fields recorded; no-provider control ≠ `measured` success.
- [ ] Customer-path wiring from `reveng.agent_sdk.mcp` (not unit-only mocks).
- [ ] Backlog EPIC-5/6, REV-MCP, FEAT-8/9 rows match measured state.

## Permitted release claim vs forbidden

| Permitted after go | Forbidden |
| --- | --- |
| “MCP + AI ops **preview/productized** under named schemas/auth.” | “AI reconstruction GA”, Scope C complete |
| Experimental watermark where matrix requires | Ungating exploits via MCP tools |

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Schema drift vs `result_contracts` | Park product claim; fix contract first |
| Live provider unreachable | `could_not_measure`; do not fake grades |
| Exploit tool surface appears | **Kill** — cite R-SEC-1 |

## Explicit non-goals

Modular-monolith ports (Phase 9); heavy workers (Phase 10); SEC proofs; Track J; packaging GA-P4; T3-*; phases 9–13 product work.
