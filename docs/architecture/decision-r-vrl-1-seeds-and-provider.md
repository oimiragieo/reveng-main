# R-VRL-1 — Minimum seeds and provider for an honest VRL LLM gate (2026-08-06)

Wave A records **policy integers** and a provider choice even when a live VRL round-trip cannot be measured on the dogfood host. Policy is not the same as runtime proof.

## Policy (normative)

| key | value |
| --- | --- |
| `min_seeds` | `3` |
| `provider` | `ollama` |
| `runtime_status` | `could_not_measure` |

Wave B exit criteria and backlog Phase 4 must copy `min_seeds: 3` verbatim from this table.

## Measured state

- `scripts/run_vrl.py` flags (3.9 `--help`): `--binary` (default `hexyl`), `--max-iterations` (default 3), `--workspace`.
- Provider wiring: environment `REVENG_AI_PROVIDER` accepts `ollama` | `anthropic` | `openai`; default **ollama** (`scripts/run_vrl.py` docstring line 15; runtime read at line 417).
- `.reveng/benchmarks/corpus.yaml`: exists (`schema_version`, `binaries`, …). Binary `hexyl` already lists **3** `seed_inputs` (`--help`, `--version`, fixture path). Several other binaries list 0 seeds today — the gate policy still requires `min_seeds: 3` before claiming an honest LLM round-trip.
- Oracle contract (unchanged): corpus seed tokens pass as **argv**, not stdin (`_classify_seeds` / refine call in `scripts/run_vrl.py`).

### Runtime probe

- `curl` to local Ollama (`http://127.0.0.1:11434/api/tags`) → connection refused.
- Therefore `runtime_status: could_not_measure` — reason: `ollama_unreachable: connection refused on 127.0.0.1:11434`. Policy values above still stand.

## Decision rationale

- **`min_seeds: 3`** — smallest count that can show disagreement between seeds in a recorded `ValidationGrade`; a single seed cannot separate real convergence from a lucky draw. Matches the existing hexyl corpus entry length.
- **`provider: ollama`** — default in `run_vrl.py`, local/free for dogfood, avoids cloud key coupling for the honesty gate. Anthropic/OpenAI remain available via `REVENG_AI_PROVIDER` but are not the Wave A gate provider.

## What makes the gate HONEST

1. Every scored run records a real `ValidationGrade` into `.reveng/benchmarks/corpus.yaml`. A run with no grade is `could_not_measure`, never a pass.
2. A no-LLM control arm must FAIL the gate. If the gate passes with the provider disabled, it is measuring something else.
3. Provider identity is recorded per run. Numbers attributed to the wrong provider are worse than no number.
4. Missing measurement stays labelled `could_not_measure` — never numeric fake success.

## Exit criterion for Phase 4 (VRL half)

Phase 4's VRL half closes when at least `min_seeds: 3` seeds × the tracked corpus produce recorded grades under provider `ollama`, with the no-LLM control arm failing, and `runtime_status: measured`. Not in Wave A.
