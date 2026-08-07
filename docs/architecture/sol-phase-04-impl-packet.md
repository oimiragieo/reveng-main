# Sol audit packet — Phase 4 impl (hexyl frontier + VRL honesty)

Inline packet for `codex exec --model gpt-5.6-sol`. Prefer this file over sandbox
greps that hang on DrvFS.

## Ask

Re-audit / APPROVE / APPROVE_WITH_NITS / REJECT Phase 4 implementation on branch
`feat/phase-04-hexyl-vrl` against
`docs/superpowers/plans/2026-08-07-reveng-phase-04-hexyl-vrl.md` and
`docs/architecture/scope-c-execution-charter.md`. Honesty-first.

## Sol REJECT → must-fix summary (re-audit)

Prior Sol REJECT called out hollow measured predicates. Fixes landed (TDD):

| Severity | Issue | Fix |
| --- | --- | --- |
| CRITICAL (R3) | Legacy bare `grades` (≥3) could unlock measured exit 0 without `seed_runs` | Measured requires non-empty `seed_runs` with ≥3 distinct executed `seed_id`s + valid grades; missing/empty ⇒ `seed_runs_required` — `test_measured_legacy_grades_only_fails` |
| CRITICAL | Three identical `seed_id`s could pad measured | Measured via `seed_runs` requires ≥3 executed rows with **distinct** non-empty `seed_id` + valid grades (`seed_ids_not_distinct`) — `test_measured_three_duplicate_seed_ids_fails` / `test_measured_three_distinct_seed_ids_passes` |
| HIGH 1 | `min_seeds: 3` with one grade could pass | Measured requires `len(grades) >= MIN_SEEDS` (`grades_below_min_seeds`) — `test_measured_with_min_seeds_field_but_one_grade_fails` |
| HIGH 2 | Run log not gate-consumable | Evidence must carry `seed_runs[{seed_id,grade,argv,executed}]` for measured; gate derives grades from executed rows; legacy `grades` is informational only (never exit 0 alone). `run_vrl.build_seed_runs_for_log` writes **one row per declared corpus seed** (unrun → `executed:false`); a single refine() must not claim 3 measured |
| MEDIUM | CNM stamped phantom `passed: false` | `control_arm.executed` required; unexecuted → CNM only; measured needs `executed:true` + `passed:false` + `llm_enabled:false`; CNM writer sets `executed:false`, `passed:null` |
| LOW | R-HEX-1 still said M2 open | `wave-c-exit-criteria.md` R-HEX-1 row notes M2 closed by Phase 4 frontier; VRL/Phase4 overall remain partial. Timed-run doc is the timing receipt only |

Validation:

```bash
PYTHONPATH=src /usr/bin/python3.9 -m pytest --no-cov \
  tests/unit/test_vrl_llm_honesty_gate.py -q
# expect: 25 passed
```

Tracked CNM stamp: `reports/vrl_llm_honesty/latest.json` →
`runtime_status: could_not_measure`, `control_arm.executed: false`,
`passed: null`, `seed_runs: []`. Gate exit 2.

## Expected Phase 4 stop/go

**Must stay `partial` / open** — VRL half is `could_not_measure` (Ollama down).
Track A (M2 frontier attribution slice) is evidenced. Do **not** authorize
phases 5–13. Do **not** treat disposition as capability `done`.

## Files touched (impl + Sol must-fix)

| Path | Role |
| --- | --- |
| `scripts/verify_vrl_llm_honesty.py` | VRL LLM honesty gate (grades length, seed_runs, control.executed) |
| `scripts/run_vrl.py` | `build_seed_runs_for_log` + emit `seed_runs` / `grades` on run log |
| `tests/unit/test_vrl_llm_honesty_gate.py` | Bidirectional + policy + Sol must-fix unit tests |
| `tests/unit/test_hexyl_fixture_provenance.py` | Pin Phase 4 rebuild sha256 |
| `tests/unit/test_backlog_wave_a_invariants.py` | Phase 4 may be `partial`; hexyl sha pin |
| `reports/native_analyze_probe/latest.json` | Probe v1.3 re-stamp |
| `reports/native_analyze_probe/2026-08-07T191850Z.json` | Sole stamp ≡ latest |
| `reports/vrl_llm_honesty/latest.json` | CNM evidence (executed:false control) |
| `docs/architecture/phase-04-m2-hexyl-frontier.md` | M2 frontier slice doc |
| `docs/architecture/evidence-vrl-llm-honesty-phase-04.md` | VRL CNM evidence doc |
| `docs/architecture/research-r-hex-1-hexyl-timed-run.md` | Timing record + M2 post-date note |
| `docs/architecture/sol-phase-04-impl-packet.md` | This packet |
| `docs/superpowers/plans/2026-08-07-reveng-phase-04-hexyl-vrl.md` | Checkboxes |
| `backlog.md` | M2 / VRL-LLM-1 / Phase 4 status |
| `reports/vrl_llm_honesty/README.md` | Evidence dir contract |

## Commands (validation)

```bash
cd /mnt/c/dev/projects/reveng-main/.worktrees/scope-c-wave-c

# Gate unit tests
PYTHONPATH=src /usr/bin/python3.9 -m pytest --no-cov \
  tests/unit/test_vrl_llm_honesty_gate.py -v

# Related honesty / provenance
PYTHONPATH=src /usr/bin/python3.9 -m pytest --no-cov \
  tests/unit/test_probe_native_analyze_timeout.py \
  tests/unit/test_evidence_dir_hygiene.py \
  tests/unit/test_df5_process_completed_honesty.py \
  tests/unit/test_hexyl_fixture_provenance.py \
  tests/unit/test_backlog_wave_a_invariants.py -v

# Ollama reachability + CNM evaluate (expect exit 2 when down)
/usr/bin/python3.9 scripts/verify_vrl_llm_honesty.py --probe-ollama
/usr/bin/python3.9 scripts/verify_vrl_llm_honesty.py \
  --evidence reports/vrl_llm_honesty/latest.json

# Probe re-stamp (local ELFs required; gitignored)
PYTHONPATH=src /usr/bin/python3.9 scripts/probe_native_analyze_timeout.py \
  --job reports/native_analyze_probe/wave_b_job.json \
  --out-dir reports/native_analyze_probe
```

## Expected evidence predicates

1. `reports/native_analyze_probe/latest.json` has `probe_version: "1.3"`.
2. Exactly one `20*.json` stamp byte-identical to `latest.json`.
3. `hexyl_subject` + `hello_go_analyze` present; `analyze_cmd` uses
   `/usr/bin/python3.9 -m reveng analyze`.
4. When streams show empty native fallback / partial_success, semantic fields are
   populated (`native_fallback_empty: true`, `semantic_reason` non-null).
5. No native `required: true` flips; M1-NATIVE-FAM still open.
6. `reports/vrl_llm_honesty/latest.json` → `runtime_status: could_not_measure`
   with honest reason; `control_arm.executed: false`; gate exit 2.
7. Unit tests prove: one-grade + `min_seeds:3` fails; duplicate `seed_id`s
   fail; three distinct seed_ids pass; legacy grades-only fails
   (`seed_runs_required`); no-LLM control pass ⇒ gate fail;
   unexecuted control cannot unlock measured.
8. Backlog: Phase 4 `partial`; M2 evidenced/`done` or `partial` with notes;
   VRL-LLM-1 not `done`.

## Non-goals / kill checks

* No exploit-surface expansion (R-SEC-1).
* No “Scope C complete” language.
* No fake ValidationGrade when Ollama is down.
