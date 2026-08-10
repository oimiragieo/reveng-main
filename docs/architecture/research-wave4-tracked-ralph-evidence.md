# Wave 4 tracked Ralph evidence — recovered-root materialization

**Date:** 2026-08-09  
**Surface:** `test_samples/js_tracked_bundle_artifact/bundle.js` (+ sibling `bundle.js.map`)  
**Oracle:** `test_samples/js_tracked_bundle_source`

## Results

| Metric | Wave 3 frozen | Wave 4 treatment |
| --- | --- | --- |
| Report | `reports/js_oracle_ralph_tracked/wave3_ralph_report.json` | `reports/js_oracle_ralph_tracked/ralph_report.json` |
| `best_project_file_recall` | `0.0` | `0.4` |
| Notes | `no_recovered_root`, `no_recovered_project_files` | `materialization_mode:source_map`, `sourcemap:bundle.js.map` |
| Match mode | none | `relative_path` (2/5 oracle files) |

Mismatch arm: recall `0.0` vs `hello_go` — see `mismatch_control.md`.

## Mechanism

`materialize_js_project_tree` prefers sibling `.map` `sourcesContent`, writes `output_dir/project/src/**`, expands recovered suffixes to `.ts/.tsx/.jsx`, records `materialization_mode` on the scorecard.

Structural identifier **hints** JSON is emitted under `artifacts/structural_identifier_hints.json` (no rewrite).

## Honesty

- Does **not** close `R-RALPH-2` / product `RALPH-2` / Phase 6 (0.8 target unmet; npm `cli.js` still obsolete).
- No Anthropic IP committed; Claude dogfood remains operator-local (`operator_local_claude.md`).
