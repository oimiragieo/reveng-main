# Scope C execution charter (2026-08-07)

Normative governance for remaining Scope C work after Thinktank REJECT of a
blanket phases 4–13 clearance. Ops index: root [`backlog.md`](../../backlog.md).

## One sentence

Scope C is **sequential and honesty-first** — not one clearance wave for phases
4–13. Each phase needs an independent stop/go authorization.

## What this charter is / is not

| Is | Is not |
| --- | --- |
| Sequential phase gates with evidence predicates | Permission to “close Scope C” in one PR |
| Separation of roadmap disposition from capability `done` | Treating `deferred` / `wontfix` / `parked` as shipped |
| Explicit SEC stop before exploit-surface expansion | Calendar-driven exploit scaffolding |
| Authorization for **Phase 4 only** as the next executable slice | Authorization for phases 5–13 |

## Per-phase stop/go contract (required before execute)

Before authorizing any phase, preregister all of:

1. **Entry dependencies** — research blockers closed or explicitly waived with
   tracked rationale; prior phase stop/go recorded.
2. **Positive + negative evidence** — measured success arm and a control that
   must fail (bidirectional oracle).
3. **Customer-path wiring tests** — helpers used from CLI / enrich / product
   path, not unit-only stubs.
4. **Tracked artifacts / fields** — exact paths and JSON/YAML fields that must
   change; stamp ≡ `latest.json` hygiene where probes apply.
5. **Permitted release claim** — the only ship language allowed after exit
   (preview / measured / non-GA / etc.).
6. **Kill / park + rollback** — when to stop, how disposition is recorded, and
   how to roll back claims without inventing capability `done`.

## Disposition ≠ capability

Backlog statuses `deferred`, `wontfix`, and `parked` resolve **roadmap
decisions**. They never equal capability `done` and must not support “full
Scope C delivered” language.

| Status | Meaning |
| --- | --- |
| `deferred` | Intentionally postponed; reconsideration trigger required |
| `wontfix` | Explicitly declined for this program; claim impact recorded |
| `parked` | Tier-3 / non-claimable depth (e.g. T3-*) |

## SEC stop gate

**No exploit-surface expansion** — including scaffolding that creates an
operational surface (new generators, CLI paths, watermark relaxation, Phase 13
exploit demos) — until Docker sandbox proofs pass.

Cite: [`decision-r-sec-1-sandbox-class.md`](decision-r-sec-1-sandbox-class.md)
(Docker-only preview class; decision only until proofs; EXPERIMENTAL / non-GA
unchanged). Wave C exit criteria carry the same gate.

## Lifecycle (every authorized phase)

```
plan → TDD → Sol audit → fix / re-audit → merge → dogfood on main
  → evidence integrity → backlog / CEO update → stop/go
```

- Interpreter: `/usr/bin/python3.9`.
- Named-path git only; author from `git log -1`; no stash across worktrees.
- Never trust a green GA verifier alone — open tracked JSON (baseline **and**
  ga profiles).
- Fixture ≠ capability; process `completed` ≠ native GA (DF-5).

## Program position (2026-08-07)

| Phase | Status |
| --- | --- |
| 1–3 | Done / preview on `main` (native corpus residuals remain open under Phase 2 preview) |
| 4 | **Next executable authorization only** — see Phase 4 plan |
| 5–13 | Not authorized; require fresh per-phase plans under this charter |

Phase 4 plan:
[`docs/superpowers/plans/2026-08-07-reveng-phase-04-hexyl-vrl.md`](../superpowers/plans/2026-08-07-reveng-phase-04-hexyl-vrl.md)

## Pointers

- Lessons: [`lessons-learned-scope-c-2026-08.md`](lessons-learned-scope-c-2026-08.md) (L1–L24)
- Wave B / C exits: [`wave-b-exit-criteria.md`](wave-b-exit-criteria.md),
  [`wave-c-exit-criteria.md`](wave-c-exit-criteria.md)
- Thinktank REJECT: [`thinktank-scope-c-master-verdict.md`](thinktank-scope-c-master-verdict.md)
- CEO (charter reconciliation):
  [`ceo-update-2026-08-07-scope-c-charter.md`](ceo-update-2026-08-07-scope-c-charter.md)
