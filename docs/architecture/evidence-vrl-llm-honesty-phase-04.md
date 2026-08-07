# Evidence: VRL LLM honesty gate — Phase 4 (2026-08-07)

**runtime_status:** `measured` (load-bearing Go micro path)  
**provider:** `ollama`  
**min_seeds:** `3`  
**Gate script:** `scripts/verify_vrl_llm_honesty.py`  
**Dogfood:** `scripts/dogfood_vrl_llm_honesty.py`  
**Tracked JSON:** `reports/vrl_llm_honesty/latest.json` (stamp `2026-08-07.json`, byte-identical)

## Sol REJECT correction (hollow → load-bearing)

Prior Track B stamped `measured` from an Ollama **ACK ping** plus
`DifferentialOracle(hexyl.exe, sample.exe)` with identical control/treatment
`launches_but_divergent` grades. LLM output never touched the candidate.
`run_vrl.py` stayed compile-blocked (`llm_error`, 0 iterations, 0 tokens).
That pattern is now a **hard gate fail**
(`hollow_ack_ping_identical_grades` / `llm_not_load_bearing`).

## Measured result (load-bearing)

| Field | Value |
| --- | --- |
| `runtime_status` | `measured` |
| Subject | `test_samples/vrl_llm_micro_go` (`CGO_ENABLED=0`) |
| Loop | broken Go → Ollama revise → `go build` → DifferentialOracle × 3 argv |
| Control grades | `launches_but_divergent` × 3 |
| Treatment grades | `behavior_matched` × 3 |
| `treatment_differs_from_control` | `true` |
| `candidate_hash_changed` | `true` |
| `seed_runs[].llm_influenced` | `true` (LLM text applied before grade) |
| `tokens_used` / `vrl_iterations` | >0 / 1 |
| Gate | `verify_vrl_llm_honesty.py --evidence …/latest.json` → **exit 0** |

### WSL → Windows Ollama

```bash
export OLLAMA_HOST=http://172.28.160.1:11434
/usr/bin/python3.9 scripts/verify_vrl_llm_honesty.py --probe-ollama
# → exit 0 when reachable
```

### Customer path residual (`scripts/run_vrl.py` hexyl)

Hexyl/PE C refine remains **`vrl_compile_toolchain_broken`** on this WSL
(glibc RELR / `cl` PermissionError; `tokens_used=0`, `iterations=0`). Dogfood
records that under `run_vrl_customer_path` as infra residual — it does **not**
substitute for the load-bearing micro loop. Phase 4 overall stays **partial**
(M2 world-class still open; hexyl C refine not green).

## Gate load-bearing contract (TDD)

`runtime_status: measured` requires at least one of:

* `treatment_differs_from_control: true` **and** different grade lists
* `candidate_hash_changed: true` after LLM source applied
* any `seed_runs[].llm_influenced: true`
* refine `tokens_used > 0` with `vrl_iterations > 0` and not compile-blocked

Rejects ACK-ping + identical control/treatment grades.

Unit suite: `tests/unit/test_vrl_llm_honesty_gate.py` (`--no-cov`).
