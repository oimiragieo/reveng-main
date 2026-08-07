# R-VRL-1 — Minimum seeds and provider for an honest VRL LLM gate (2026-08-06)

Wave A records **policy integers** and a provider choice even when a live VRL round-trip cannot be measured on the dogfood host. Policy is not the same as runtime proof.

## Policy (normative)

| key | value |
| --- | --- |
| `min_seeds` | `3` |
| `provider` | `ollama` |
| `runtime_status` (Wave A) | `could_not_measure` |
| `runtime_status` (Track B 2026-08-07) | `measured` — see evidence-vrl-llm-honesty-phase-04.md |

Wave B exit criteria and backlog Phase 4 must copy `min_seeds: 3` verbatim from this table.

## Measured state

- `scripts/run_vrl.py` flags (3.9 `--help`): `--binary` (default `hexyl`), `--max-iterations` (default 3), `--workspace`.
- Provider wiring: environment `REVENG_AI_PROVIDER` accepts `ollama` | `anthropic` | `openai`; default **ollama** (`scripts/run_vrl.py` docstring line 15; runtime read at line 417).
- Ollama host: `OLLAMA_HOST` / `REVENG_OLLAMA_HOST` (gate + `OllamaAnalyzer`).
- `.reveng/benchmarks/corpus.yaml`: exists (`schema_version`, `binaries`, …). Binary `hexyl` already lists **3** `seed_inputs` (`--help`, `--version`, fixture path). Several other binaries list 0 seeds today — the gate policy still requires `min_seeds: 3` before claiming an honest LLM round-trip.
- Oracle contract (unchanged): corpus seed tokens pass as **argv**, not stdin (`_classify_seeds` / refine call in `scripts/run_vrl.py`).
- Track B (2026-08-07): honesty evidence `runtime_status: measured` via hermetic seed×oracle×ollama dogfood; full refine compile on WSL remains a residual (documented, not faked).

### Runtime probe

- Honor `OLLAMA_HOST` / `REVENG_OLLAMA_HOST` (WSL→Windows Ollama uses the Hyper-V
  gateway, e.g. `http://172.28.160.1:11434`, not `127.0.0.1`).
- Track B dogfood (2026-08-07): probe exit 0 + `runtime_status: measured` with
  ≥3 seed×oracle grades under provider `ollama` — see
  `docs/architecture/evidence-vrl-llm-honesty-phase-04.md`.
- Default without env remains `http://127.0.0.1:11434/api/tags` (connection
  refused from WSL when Ollama is Windows-only).

## Decision rationale

- **`min_seeds: 3`** — smallest count that can show disagreement between seeds in a recorded `ValidationGrade`; a single seed cannot separate real convergence from a lucky draw. Matches the existing hexyl corpus entry length.
- **`provider: ollama`** — default in `run_vrl.py`, local/free for dogfood, avoids cloud key coupling for the honesty gate. Anthropic/OpenAI remain available via `REVENG_AI_PROVIDER` but are not the Wave A gate provider.

## What makes the gate HONEST

1. Every scored run records a real `ValidationGrade` into `.reveng/benchmarks/corpus.yaml`. A run with no grade is `could_not_measure`, never a pass.
2. A no-LLM control arm must FAIL the gate. If the gate passes with the provider disabled, it is measuring something else.
3. Provider identity is recorded per run. Numbers attributed to the wrong provider are worse than no number.
4. Missing measurement stays labelled `could_not_measure` — never numeric fake success.

## Exit criterion for Phase 4 (VRL half)

Phase 4's VRL half closes when at least `min_seeds: 3` seeds × the tracked corpus produce recorded grades under provider `ollama`, with the no-LLM control arm failing, and `runtime_status: measured`.

**Track B (2026-08-07):** criterion met via hermetic dogfood + gate exit 0. Full
`run_vrl` refine-to-convergence remains a residual on WSL (compile/linker) and
does not reopen the honesty gate; Phase 4 overall stays partial while M2
world-class is open.
