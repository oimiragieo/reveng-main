# R-RALPH-2 — Recall baseline before any engine wedge (2026-08-06)

**Question:** What is the smallest engine wedge that reaches 0.8+ recall on tracked `cli.js`?  
**Wave A answer:** Not decidable without a measured baseline. This doc records the baseline attempt only. It does **not** close `R-RALPH-2` / product `RALPH-2`.

## Measured baseline

| field | value |
| --- | --- |
| status | `could_not_measure` |
| recall | `null` (not measured — never substitute numeric 0 for a missing run) |
| Interpreter | `/usr/bin/python3.9` |
| Harness | `scripts/ralph_js_oracle_loop.py` (scores `project_file_recall` via `oracle_recall_precision` in `src/reveng/app_reverse_engineering/ralph_js_loop.py`) |
| Intended command | `/usr/bin/python3.9 scripts/ralph_js_oracle_loop.py --input PATH_TO_TRACKED_CLI_JS --oracle PATH_TO_ORACLE_TREE --output-dir reports/js_oracle_ralph_cli --target-recall 0.80 --max-attempts 1 --no-plateau` |
| Corpus / target | Tracked Anthropic Claude Code `cli.js` vs oracle source tree (see `examples/use-cases/js-oracle-ralph/README.md`) |
| Wall clock | not applicable (run did not score) |

### Attempt log

1. Confirmed harness CLI under 3.9: `/usr/bin/python3.9 scripts/ralph_js_oracle_loop.py --help` → exit 0. Scoring field: `project_file_recall` / report key `best_project_file_recall`; stop threshold flag `--target-recall` (default 0.8).
2. Host search for the tracked input failed: no `@anthropic-ai/claude-code/cli.js` under the usual Roaming npm paths; no prior `reports/js_oracle_ralph_cli` / `ralph_report.json` in this worktree.
3. Oracle tree present at `/mnt/c/dev/projects/claude-code-main`, but without the bundled `cli.js` input the harness cannot produce a recall figure.
4. Probe with a missing input path printed `Input not found: …` and did not write a scored `ralph_report.json`.

**Reason (verbatim class):** `input_absent:tracked cli.js (Anthropic Claude Code bundle) on dogfood host; harness runnable but unscored`.

## Gap to target

Because status is `could_not_measure`, the gap `0.8 − baseline` is **UNKNOWN**. No engine wedge may be scoped or claimed against a fabricated baseline.

## Candidate wedges (unranked, unbuilt)

None of these is authorized or claimed done in Wave A. Each names a file it would touch:

1. **Source-map recovery into reconstructed tree** — expected to move `project_file_recall` when maps exist; evidence: `src/reveng/javascript/source_map_recoverer.py:143` (`recover`), bundler signal `source_map_markers` at `src/reveng/javascript/bundle_reverse_engineer.py:673`.
2. **Richer dependency / path extraction from string literals** — expected to move file-path overlap used by the oracle scorecard; evidence: `src/reveng/javascript/bundle_reverse_engineer.py:690` (`_extract_dependency_candidates`).
3. **Variant schedule / deobfuscator rotation already harnessed** — expected to change artifact surface fed to promotion rules, not magic recall alone; evidence: default `run_webcrack` variants in `src/reveng/app_reverse_engineering/ralph_js_loop.py:129` and optional heavy profiles at lines 181–194. Engine work still required inside `JavaScriptBundleReverseEngineer` (`bundle_reverse_engineer.py:268`).

## Wave B exit criterion for RALPH-2

`RALPH-2` / `R-RALPH-2` close only when the same harness reports `project_file_recall >= 0.8` on the tracked `cli.js` case in a committed report, produced by the command shape recorded above (with real `--input` / `--oracle` paths). The 0.8 engine rewrite is explicitly **not** in Wave A.

## Related backlog split

- `R-RALPH-2-BASELINE` — this measurement doc (closeable when present and honest).
- `R-RALPH-2` — remains open until the smallest 0.8+ wedge is identified **and** implemented.
