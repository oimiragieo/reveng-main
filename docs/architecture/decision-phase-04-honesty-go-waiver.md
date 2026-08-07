# Decision: Phase 4 honesty go (M2 split) — 2026-08-07

## Decision
**APPROVE** Phase 4 stop/go = **go** for the *honesty* exits only, with world-class M2 split out.

Sol: `APPROVE_WITH_NITS` (inline packet 2026-08-07).

## Split
| Exit | Status | Notes |
| --- | --- | --- |
| Track A — probe v1.3 attribution / DF-5 semantics | **met** | `reports/native_analyze_probe/latest.json` |
| Track B — VRL-LLM-1 load-bearing measured | **met** | corpus `vrl_llm_micro_go`; gate exit 0 |
| World-class M2 (hexyl analyze/recompile/behavior) | **open / partial** | remains backlog M2; NOT required for Phase 4 honesty go |

## Permitted claim
“Phase 4 honesty gate passed.”

## Forbidden claims
- M2 done / world-class hexyl frontier closed
- Native GA from process completed
- Hexyl PE C refine measured
- Scope C complete / phases 5–13 done
- Blanket Phase 5 execution (Phase 5 still needs its own Sol stop/go)

## Effects
- Backlog Phase 4 → `done (honesty go)`; M2 stays `partial`
- `scope-c-hold-prep-policy.md` → HOLD lifted for Phase 5+ *authorization*, not auto-execution
- Phases 5–13 leave `blocked_on_phase_4`; become `open` / planned pending per-phase Sol
