# Evidence: VRL LLM honesty gate — Phase 4 (2026-08-07)

**runtime_status:** `measured` (load-bearing Go micro path)  
**provider:** `ollama`  
**min_seeds:** `3`  
**corpus_entry:** `vrl_llm_micro_go` (`.reveng/benchmarks/corpus.yaml`)  
**Gate script:** `scripts/verify_vrl_llm_honesty.py`  
**Dogfood:** `scripts/dogfood_vrl_llm_honesty.py`  
**Tracked JSON:** `reports/vrl_llm_honesty/latest.json` (stamp `2026-08-07.json`, byte-identical)

## Sol REJECT corrections

1. **Hollow ACK-ping** — prior Track B stamped `measured` from Ollama ACK +
   identical control/treatment grades without applying LLM text. Hard fail:
   `hollow_ack_ping_identical_grades` / `llm_not_load_bearing`.
2. **Untracked corpus subject** — `vrl_llm_micro_go` must be a tracked corpus
   entry; dogfood loads `seed_inputs` from that entry (not hard-coded-only).
3. **Forgeable booleans** — `candidate_hash_changed: true` alone is insufficient.
   Gate requires `control_candidate_sha256` + `treatment_candidate_sha256` (or
   legacy before/after) and **derives** change as present-and-unequal. Missing
   or equal hashes with a true boolean → fail. `llm_influenced` requires
   `applied_source_path` or `applied_source_sha256`.

## Measured result (load-bearing)

| Field | Value |
| --- | --- |
| `runtime_status` | `measured` |
| `corpus_entry` | `vrl_llm_micro_go` |
| Subject | `test_samples/vrl_llm_micro_go` (`CGO_ENABLED=0`; `build_recipe` → `micro.bin`) |
| Seeds | corpus `seed_inputs`: `--help`, `--version`, `sample` |
| Loop | broken Go → Ollama revise → `go build` → DifferentialOracle × 3 argv |
| Control grades | `launches_but_divergent` × 3 |
| Treatment grades | `behavior_matched` × 3 |
| `treatment_differs_from_control` | `true` |
| SHA pair | `control_candidate_sha256` ≠ `treatment_candidate_sha256` |
| `candidate_hash_changed` | **derived** from SHA pair (not trusted alone) |
| `applied_source_*` | path + sha256 receipt present |
| `seed_runs[].llm_influenced` | `true` |
| `tokens_used` / `tokens_used_estimated` | >0 / `true` when approximated |
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
substitute for the load-bearing micro loop. Phase 4 overall stays **partial** /
**HOLD** (M2 world-class still open; hexyl C refine not green; phases 5–13
remain blocked).

## Gate load-bearing contract (TDD)

`runtime_status: measured` requires:

* SHA pair present (`control_candidate_sha256` / `treatment_candidate_sha256`
  or legacy before/after)
* at least one of:
  * `treatment_differs_from_control: true` **and** different grade lists
  * **derived** hash change (SHA present and unequal)
  * any `seed_runs[].llm_influenced: true` **with** applied-source receipt
  * refine `tokens_used > 0` with `vrl_iterations > 0` and not compile-blocked
* Rejects ACK-ping + identical grades
* Rejects self-asserted `candidate_hash_changed: true` with missing/equal hashes

Unit suite: `tests/unit/test_vrl_llm_honesty_gate.py` (`--no-cov`).
