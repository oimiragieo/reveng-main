# CEO update — REVENG (2026-08-07, Scope C charter)

Plain English. **Supersedes as latest briefing:**
[`ceo-update-2026-08-06-wave3.md`](ceo-update-2026-08-06-wave3.md)
(wave 2/1 remain historical).

## Bottom line (one sentence)

Thinktank **REJECT**ed a blanket Scope C master plan; we are clearing must-fixes
with an **execution charter**, a **Phase 4-only** plan, and a probe honesty fix —
not authorizing phases 5–13.

## Reconciliation (stale wave-3 vs current)

| ID | Wave-3 CEO said | Current (this briefing) |
| --- | --- | --- |
| **R-HEX-1** | blocked (`tool_absent`) | **done (measured)** — hexyl subject timed probe `completed` ≈4.68s in `reports/native_analyze_probe/latest.json` |
| **DF-5** | open / honesty gap | **done** — documented + tested; process `completed` ≠ native GA |
| **M2** | open | **still open** — R-HEX-1 measurement alone does not close hexyl frontier hardening |
| Probe semantic gap | (called out by Thinktank) | **fixed this wave** — probe **v1.3** attributes `pipeline_partial_success` / `native_fallback_empty` from stdout/stderr tails |
| Master plan | — | Thinktank first pass **REJECT** → charter + Phase 4 plan for **re-audit** (not blanket 4–13 clearance) |

## What this wave ships

1. **Execution charter** —
   [`scope-c-execution-charter.md`](scope-c-execution-charter.md): sequential
   honesty-first gates; disposition ≠ capability; SEC stop (R-SEC-1); lifecycle
   plan→…→stop/go; Phase 4 only next.
2. **Phase 4 plan** —
   [`docs/superpowers/plans/2026-08-07-reveng-phase-04-hexyl-vrl.md`](../superpowers/plans/2026-08-07-reveng-phase-04-hexyl-vrl.md):
   M2 hexyl + VRL LLM honesty (`min_seeds: 3`, ollama); measured vs open marked;
   no hollow `required: true`.
3. **Probe v1.3** — stream semantic attribution so DF-5 markers are not null when
   the process exits 0 with `partial_success` / empty native fallback.
4. **Backlog legend** — adds `deferred` / `wontfix` (roadmap disposition only).

## What “ship” means today

| Surface | Claim |
| --- | --- |
| CLI + app RE (JS / JVM / Python managed) | Supported **preview** |
| Native PE/ELF deep rebuild | **Limited** — fixtures + probe; not hermetic GA |
| Exploits | Experimental / non-GA (Docker-only decision; **no expansion** until sandbox proofs) |
| Scope C phases 1–3 | Done / preview on `main` |
| Scope C Phase 4 | **Authorized next** — not yet exited |
| Scope C phases 5–13 | **Not authorized** |

## Still open (before big builds)

| ID | Status | Plain question |
| --- | --- | --- |
| **M2** | open | Hexyl frontier hardening beyond the timed probe? |
| **VRL-LLM-1** | open | Measured ollama round-trip with min_seeds 3 + failing no-LLM control? |
| **R-RALPH-2** | open | Smallest engine wedge for cli.js → 0.8+? |
| **M1-NATIVE-FAM** | open | Analyze ≤120s without Ghidra before any `required: true`? |
| **M4 corpus** | partial | Nightly/blocking corpus beyond thin honesty CI? |

## Ask of leadership

Re-audit the master plan under the charter: approve **Phase 4 execution** only;
keep phases 5–13 gated on fresh stop/go packets.

## Pointers

- Ops index: [`backlog.md`](../../backlog.md)
- Charter: [`scope-c-execution-charter.md`](scope-c-execution-charter.md)
- Thinktank REJECT: [`thinktank-scope-c-master-verdict.md`](thinktank-scope-c-master-verdict.md)
- Wave C exits: [`wave-c-exit-criteria.md`](wave-c-exit-criteria.md)
