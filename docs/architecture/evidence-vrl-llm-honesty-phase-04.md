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
live ollama round-trip records **≥3 executed** seed grades under `min_seeds: 3`
with an *executed* no-LLM control failing.

## What did ship (gate honesty)

| Predicate | Status |
| --- | --- |
| Gate requires non-empty `seed_runs` with ≥3 distinct executed `seed_id`s + valid grades when claiming `measured`; legacy grades-only never unlocks exit 0 | tested (`seed_runs_required`) |
| `min_seeds: 3` with a single grade ⇒ gate fail | tested (`test_measured_with_min_seeds_field_but_one_grade_fails`) |
| Preferred `seed_runs[]` schema; derive grades from executed rows | tested + `run_vrl.build_seed_runs_for_log` |
| Missing / invalid ValidationGrade never passes | tested |
| Measured requires control `executed: true` + `passed: false` + `llm_enabled: false` | tested |
| Unexecuted control (`executed: false`) is CNM — no phantom `passed: false` | tested + stamped |
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

`run_vrl.py` emits gate-consumable `seed_runs` / `grades` on successful run logs
via `build_seed_runs_for_log` (does not invent grades to pad `min_seeds`). No
corpus grade was written on this failed dogfood (correct — never invent a pass).

## Control arm (bidirectional)

CNM evidence stamps `control_arm.executed: false` and `passed: null` — do not
claim a failed control that never ran. Measured pass requires `executed: true`
and `passed: false` with `llm_enabled: false`. A fixture with `passed: true`
(executed) fails the gate in unit tests.

## Exit remaining for VRL half

1. Ollama up on dogfood host.
2. ≥3 **executed** seed runs × tracked corpus under `REVENG_AI_PROVIDER=ollama`.
3. Real ValidationGrade(s) in evidence `seed_runs` / `grades` and corpus.yaml.
4. No-LLM control **executed** and fails; `runtime_status: measured` in evidence.
