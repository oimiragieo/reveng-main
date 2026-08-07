# Scope C phase catalog contracts (2026-08-07)

Normative index of Scope C phases 1–13 with stop/go status and plan links.
Ops: root [`backlog.md`](../../backlog.md) §E. Governance:
[`scope-c-execution-charter.md`](scope-c-execution-charter.md).

**Rule:** each phase needs an independent stop/go. Disposition
(`deferred` / `wontfix` / `parked`) ≠ capability `done`. Phases 5–13 are
**planned stubs only** — not authorized for product execution.

## Status legend

| Status | Meaning |
| --- | --- |
| done | Phase stop/go = go on `main` (preview residuals may remain noted) |
| partial | Authorized work in flight; stop/go not yet go |
| planned / unauthorized | Stub plan exists; **no** execute until prior phase stop/go = go |

## Catalog

| Phase | Focus | Status | Plan |
| --- | --- | --- | --- |
| 1 | Honesty + known_gaps + GA gate integrity | **done** | (shipped; see backlog §A) |
| 2 | Managed recompile + GA report honesty (preview) | **done** (preview; native corpus residuals open) | (shipped; see backlog §A / M1) |
| 3 | Behavior-backed JS validation | **done** | (shipped; see backlog §B) |
| 4 | Hexyl frontier + VRL LLM round-trip honesty | **partial** | [`2026-08-07-reveng-phase-04-hexyl-vrl.md`](../superpowers/plans/2026-08-07-reveng-phase-04-hexyl-vrl.md) |
| 5 | Equivalence product gates + CI corpus enforcement | planned / **unauthorized** | [`2026-08-07-reveng-phase-05-equiv-ci.md`](../superpowers/plans/2026-08-07-reveng-phase-05-equiv-ci.md) |
| 6 | JS close: RALPH-2 + bundler graph (P4) | planned / **unauthorized** | [`2026-08-07-reveng-phase-06-js.md`](../superpowers/plans/2026-08-07-reveng-phase-06-js.md) |
| 7 | Native depth → partial_equivalence + multi-file | planned / **unauthorized** | [`2026-08-07-reveng-phase-07-native-depth.md`](../superpowers/plans/2026-08-07-reveng-phase-07-native-depth.md) |
| 8 | MCP + AI ops productization | planned / **unauthorized** | [`2026-08-07-reveng-phase-08-mcp-ai.md`](../superpowers/plans/2026-08-07-reveng-phase-08-mcp-ai.md) |
| 9 | Orchestration + modular monolith / ports | planned / **unauthorized** | [`2026-08-07-reveng-phase-09-orchestration.md`](../superpowers/plans/2026-08-07-reveng-phase-09-orchestration.md) |
| 10 | Workers + external-tool CI + SEC-1 sandbox proofs | planned / **unauthorized** | [`2026-08-07-reveng-phase-10-workers.md`](../superpowers/plans/2026-08-07-reveng-phase-10-workers.md) |
| 11 | Analyst / governance / packaging (GA-P4) | planned / **unauthorized** | [`2026-08-07-reveng-phase-11-packaging.md`](../superpowers/plans/2026-08-07-reveng-phase-11-packaging.md) |
| 12 | Platform depth (IR, Ralph opt, RAG, KG start) | planned / **unauthorized** | [`2026-08-07-reveng-phase-12-platform.md`](../superpowers/plans/2026-08-07-reveng-phase-12-platform.md) |
| 13 | Blue-ocean / v6.1+ futures (post SEC-1 for exploits) | planned / **unauthorized** | [`2026-08-07-reveng-phase-13-blue-ocean.md`](../superpowers/plans/2026-08-07-reveng-phase-13-blue-ocean.md) |

## Cross-cutting gates

| Gate | Applies | Rule |
| --- | --- | --- |
| Prior phase stop/go = go | 5–13 | Phase N unauthorized while N−1 is partial/open |
| Phase 4 partial today | 5–13 | VRL LLM half `could_not_measure` — do not execute 5–13 |
| SEC-1 sandbox **proofs** | 10 (exit), 13 (before exploit), Track J | Decision doc alone insufficient; four bidirectional proofs required |
| Track J exploit layer | after SEC proofs + separate stop/go | Not auto-authorized by Phase 10 or 13 stubs |
| T3-* | Phase 13 | **parked** — honesty guards only; never claim `done` |

## Pointers

- Charter: [`scope-c-execution-charter.md`](scope-c-execution-charter.md)
- SEC decision: [`decision-r-sec-1-sandbox-class.md`](decision-r-sec-1-sandbox-class.md)
- Wave C exits: [`wave-c-exit-criteria.md`](wave-c-exit-criteria.md)
- Thinktank REJECT of blanket 4–13: [`thinktank-scope-c-master-verdict.md`](thinktank-scope-c-master-verdict.md)
- CEO (charter): [`ceo-update-2026-08-07-scope-c-charter.md`](ceo-update-2026-08-07-scope-c-charter.md)
