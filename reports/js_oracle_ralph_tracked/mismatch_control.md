# Mismatch control — Wave 3 tracked Ralph surface

**Date:** 2026-08-09  
**Interpreter:** `/usr/bin/python3.9`

## Arms

| Arm | Input | Oracle | `best_project_file_recall` | Notes |
| --- | --- | --- | --- | --- |
| Treatment | `test_samples/js_tracked_bundle_artifact/bundle.js` | `test_samples/js_tracked_bundle_source` | `0.0` | `no_recovered_root`, `no_recovered_project_files` |
| Mismatch | same bundle | `test_samples/native/hello_go` | `0.0` | same notes |

## Interpretation

Both arms fail before filename-set matching because the JS adapter did not materialize `output_dir/project`. This control is **instrument-limited and non-discriminatory**: it does **not** prove the two oracles are equally hard, and it does **not** prove scorer correctness. It only documents that the interim baseline zero is a **recovery-root gap**.

Positive control for scorecard arithmetic: existing unit tests for `js_oracle_scorecard` / `ralph_js_loop` (see `tests/unit/test_ralph_js_loop.py`).

## Path / report hygiene

`ralph_report.json` keeps harness scoring fields as emitted. Absolute host paths in `input_path` / `oracle_dir` / `output_root` / attempt paths are expected on dogfood hosts. A small `wave3_honesty` sidecar records surface identity + harness exit code `2` — it must not rewrite recall/notes.
