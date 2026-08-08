# Wave C exit criteria (remaining poles after Wave B honesty slice)

Wave B lands a **thin** PR honesty gate (probe / evidence / backlog invariants) and
closes DF-5 / M0 reporting-discipline rows where evidence already exists. Wave C
is the gated product queue below. Items here are **not** claimed done by Wave B.

## Normative carry-forwards

| key | value | source |
| --- | --- | --- |
| `min_seeds` | `3` | `decision-r-vrl-1-seeds-and-provider.md` |
| `provider` | `ollama` | same |
| process `completed` ≠ native GA | DF-5 / L22 | `lessons-learned-scope-c-2026-08.md` |
| fixture build ≠ analyze capability | Wave A/B global | probe README |

Policy integers and honesty docs are **not** a substitute for measured product exits.

## Remaining poles (Wave C — open unless noted)

| id / theme | exit criterion (summary) | Wave B status |
| --- | --- | --- |
| RALPH-2 | Measured engine wedge moves tracked `cli.js` recall toward 0.8+ | **open** |
| R-RALPH-2 | Smallest engine wedge chosen + implemented (baseline already recorded) | **open** |
| M1-NATIVE-FAM | ≥5 native / ≥3 families hermetic; flip `required: true` only after analyze ≤120s **without** Ghidra on tracked fixtures | **open** (`required` stays false) |
| M2 | Hexyl frontier hardening **beyond** a single timed probe (R-HEX-1 measurement alone does not close M2; probe v1.3 honesty attribution alone does not close world-class M2) | **partial** — Phase 4 Track A honesty attribution evidenced (`phase-04-m2-hexyl-frontier.md`); deeper analyze/recompile/behavior still open |
| R-HEX-1 | Bounded timed `reveng analyze` on hexyl **subject** ELF; status must match probe JSON (`completed` / `timeout` / `could_not_measure`) | **done** (measured) — `hexyl_subject` `completed` ≈4.68s in `latest.json`; M2 remains **partial** (honesty attribution ≠ world-class closeout) |
| M4 corpus residual | CI/PR/**nightly corpus** gates blocking (thin honesty workflow is **partial** only) | **partial** (honesty gate); corpus still open |
| VRL LLM measured | `min_seeds: 3` × tracked corpus under `ollama`, no-LLM control fails, `runtime_status: measured` | **done** (VRL-LLM-1 via `vrl_llm_micro_go`); hexyl PE C refine residual
| M5-PIPE | Optional merge under criteria **or** keep permanent split | partial (split freeze) |
| Scope C phases 4–13 | Per-phase product exits | **open** |
| P4-BUNDLER / P5-NATIVE-EQ / P6-PLATFORM | Capability hardening leftovers | **open** |
| T3-* | Kernel / packed / JIT / anti / GUI depth | **parked** — no claim |
| SEC sandbox proofs | Docker-only preview class decided; proofs/expansion still gated | decision only; no exploit expansion |

## Explicit non-goals carried into Wave C

- No hollow `required: true` flips from process `completed` alone (DF-5).
- No claim that Wave B honesty CI equals full M4 corpus enforcement.
- T3-* stay parked; no exploit-surface expansion.
- Hexyl ELF binaries remain gitignored artifacts — CI must not require them.

## Pointers

- Ops index: [`backlog.md`](../../backlog.md)
- Wave B gates (historical): [`wave-b-exit-criteria.md`](wave-b-exit-criteria.md)
- Thin honesty workflow: `.github/workflows/wave-b-honesty.yml`
- Probe evidence: `reports/native_analyze_probe/`
