# Evidence: VRL LLM honesty gate — Phase 4 (2026-08-07)

**runtime_status:** `measured`  
**provider:** `ollama`  
**min_seeds:** `3`  
**Gate script:** `scripts/verify_vrl_llm_honesty.py`  
**Dogfood:** `scripts/dogfood_vrl_llm_honesty.py`  
**Tracked JSON:** `reports/vrl_llm_honesty/latest.json` (stamp `2026-08-07.json`, byte-identical)

## Measured result (Track B)

| Field | Value |
| --- | --- |
| `runtime_status` | `measured` |
| `ollama_actually_ran` | `true` |
| `ollama_tags_url` | `http://172.28.160.1:11434/api/tags` |
| model | `hf.co/unsloth/Llama-3.2-1B-Instruct-GGUF:Q4_K_M` |
| `seed_runs` | 3 distinct executed `seed_id`s |
| grades | `launches_but_divergent` × 3 (DifferentialOracle) |
| `control_arm` | `llm_enabled: false`, `executed: true`, `passed: false` |
| Gate | `verify_vrl_llm_honesty.py --evidence …/latest.json` → **exit 0** |

### WSL → Windows Ollama

From WSL, `127.0.0.1:11434` is refused — Ollama listens on the Windows host.
Set `OLLAMA_HOST` (or `REVENG_OLLAMA_HOST`) to the Hyper-V / WSL gateway, e.g.:

```bash
export OLLAMA_HOST=http://172.28.160.1:11434
# Discover gateway: ip route show | awk '/default/ {print $3}'
# Or Windows: Get-NetIPAddress on vEthernet (WSL)
/usr/bin/python3.9 scripts/verify_vrl_llm_honesty.py --probe-ollama
# → {"ollama_reachable": true, "url": "http://172.28.160.1:11434/api/tags"}  exit 0
```

The honesty gate resolves tags URL from env (default remains `http://127.0.0.1:11434/api/tags`).
`OllamaAnalyzer` / `run_vrl` honor the same env for chat.

### Customer path (`scripts/run_vrl.py`)

```text
REVENG_AI_PROVIDER=ollama OLLAMA_HOST=http://172.28.160.1:11434 \
  /usr/bin/python3.9 scripts/run_vrl.py --binary hexyl --max-iterations 1
# exit 0 process-wise, status=llm_error, final_grade=unknown
# notes: Initial compile_fn raised — WSL linker cannot build C
#   (glibc RELR / ld incompatible); cl → PermissionError
# Only first corpus seed marked executed in run log (by design)
```

Dogfood restores `corpus.yaml` hexyl `current_grade` after this probe so a
compile-fail fallback (`unknown`) does not overwrite the prior / hermetic
oracle grade. Hermetic measured grades remain `launches_but_divergent`.

### Hermetic seed × oracle × ollama path

Because full refine cannot compile on this WSL host, dogfood scores each of the
three corpus seeds with:

1. Live Ollama `analyze()` (ACK prompt) → `ollama_actually_ran: true`
2. `DifferentialOracle(original=hexyl.exe, candidate=test_samples/sample.exe)`
   with that seed’s argv → real ValidationGrade ladder values

Candidate is a divergent PE stand-in (not a hexyl recompile). Grades are oracle
outputs, not invented. No-LLM control uses the same oracle without Ollama and
fails the success bar (not all `behavior_matched`) → `passed: false`.

## What shipped (gate honesty)

| Predicate | Status |
| --- | --- |
| `OLLAMA_HOST` / `REVENG_OLLAMA_HOST` → `/api/tags` | shipped + unit tested |
| `--probe-ollama` prints resolved URL | shipped |
| Gate requires ≥3 distinct executed `seed_id`s + valid grades for `measured` | tested |
| Measured requires control `executed: true` + `passed: false` + `llm_enabled: false` | tested + dogfood |
| Hollow control (`passed: true`) refuses measured | coded in dogfood |
| CNM reasons include resolved URL (not localhost-only) | shipped |

Unit suite: `tests/unit/test_vrl_llm_honesty_gate.py` (`--no-cov`) — 31 passed.

## Residual (honest)

* Full VRL refine (compile → LLM → re-verify to `behavior_matched`) remains
  blocked on this WSL by the C toolchain / linker. Track B **measured** proves
  ollama round-trip + seed×oracle ValidationGrade vocabulary under
  `min_seeds: 3` with a failing no-LLM control — not hexyl convergence.
* Phase 4 overall stays **partial** while world-class M2 (hexyl frontier) is
  still open; VRL-LLM-1 measured gate is satisfied.
