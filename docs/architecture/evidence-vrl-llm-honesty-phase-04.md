# Evidence: VRL LLM honesty gate — Phase 4 (2026-08-07)

**runtime_status:** `could_not_measure`  
**provider (policy):** `ollama`  
**min_seeds (policy):** `3`  
**Gate script:** `scripts/verify_vrl_llm_honesty.py`  
**Tracked JSON:** `reports/vrl_llm_honesty/latest.json`

## Why measured is refused

Local Ollama at `http://127.0.0.1:11434/api/tags` → connection refused.

```text
/usr/bin/python3.9 scripts/verify_vrl_llm_honesty.py --probe-ollama
# → {"ollama_reachable": false, ...}  exit 2
```

Per R-VRL-1 / Phase 4 kill rule: do **not** fake ValidationGrade rows; leave the
VRL half `could_not_measure`. Phase 4 overall stays **partial** / open until a
live ollama round-trip records grades under `min_seeds: 3` with the no-LLM
control failing.

## What did ship (gate honesty)

| Predicate | Status |
| --- | --- |
| Gate requires `min_seeds >= 3` when claiming `measured` | tested |
| Missing / invalid ValidationGrade never passes | tested |
| No-LLM control `passed: true` ⇒ gate fail (bidirectional) | tested |
| `runtime_status: measured` only when `ollama_actually_ran` | tested |
| Unreachable ollama ⇒ exit 2 + tracked CNM evidence | dogfood + tests |
| Customer path `scripts/run_vrl.py` exercised | attempted (see below) |

Unit suite: `tests/unit/test_vrl_llm_honesty_gate.py` (`--no-cov`).

## Customer-path dogfood (`scripts/run_vrl.py`)

```text
PYTHONPATH=src REVENG_AI_PROVIDER=ollama \
  /usr/bin/python3.9 scripts/run_vrl.py --binary hexyl --max-iterations 1
# exit 1 — Original binary for 'hexyl' not found
# (corpus binary_path → external/ga_binaries/hexyl/hexyl.exe absent here)
# Ollama also unreachable — would not have produced a measured LLM round-trip
```

`run_vrl.py` now records `provider` / `min_seeds_policy` / `seed_argv_count` on
successful run logs for the honesty gate to consume later. No corpus grade was
written on this failed dogfood (correct — never invent a pass).

## Control arm (bidirectional)

Evidence stamps `control_arm.llm_enabled: false` and `control_arm.passed: false`.
A fixture with `passed: true` fails the gate in unit tests — the gate cannot go
green without an LLM simply because grades are absent.

## Exit remaining for VRL half

1. Ollama up on dogfood host.
2. ≥3 seeds × tracked corpus under `REVENG_AI_PROVIDER=ollama`.
3. Real ValidationGrade(s) in `.reveng/benchmarks/corpus.yaml`.
4. No-LLM control still fails; `runtime_status: measured` in evidence.
