# Wave B exit criteria (gated queue)

Wave A freezes honesty/ops/research artifacts only. Wave B is the gated product queue below. Items are **not** claimed done by Wave A.

## Normative policy copies (from Wave A decisions)

| key | value | source |
| --- | --- | --- |
| `min_seeds` | `3` | `docs/architecture/decision-r-vrl-1-seeds-and-provider.md` |
| `provider` | `ollama` | same |

Wave B VRL work must copy `min_seeds: 3` verbatim. Policy integers are not a substitute for `runtime_status: measured`.

## M5-PIPE (optional in Wave B)

Wave A decided a **permanent documented split** (`reveng.pipeline` vs `reveng.pipelines`). A Wave B **code merge is optional later migration**, not required by that freeze. If merge is attempted, it must meet M5-PIPE exit criteria (shims, sliced migration, import-linter). If merge is not attempted, the split remains the product shape.

## Gated queue (Wave B — not Wave A)

| id / theme | exit criterion (summary) | Wave A status |
| --- | --- | --- |
| RALPH-2 | Measured engine wedge moves tracked `cli.js` recall toward 0.8+ (baseline already recorded or `could_not_measure`) | open |
| R-HEX-1 / M2 | Hexyl binary present + bounded timed analyze with honest process/semantic fields | **blocked** (tool absent) |
| M1-NATIVE-FAM | ≥5 native / ≥3 families hermetic; flip `required: true` only after analyze ≤120s without Ghidra | open |
| M4 | CI/PR/nightly corpus gates blocking | open |
| M5-PIPE | Optional merge under criteria **or** keep permanent split with explicit contract | partial (split freeze) |
| VRL LLM gate | `min_seeds: 3` × tracked corpus under `ollama`, no-LLM control fails, `runtime_status: measured` | decision only |
| Scope C phases 5–13 | Per-phase product exits | open |
| SEC sandbox proofs | Docker-only preview class already decided; proofs/expansion still gated | decision only; no exploit expansion |

## Explicit non-goals carried from Wave A

No `src/reveng/**` authorization in Wave A; fixture build ≠ analyze capability; T3-* stay parked.
