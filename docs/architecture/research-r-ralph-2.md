# R-RALPH-2 — Engine wedge research (Wave 3 re-baseline, 2026-08-09)

**Question:** What is the smallest engine wedge that reaches 0.8+ `project_file_recall` on the Phase-6 JS close target?  
**Wave 3 answer:** The historical Anthropic `cli.js` input is **obsolete** on current npm packaging. An interim **tracked micro-bundle** surface was scored. Product `RALPH-2` / research `R-RALPH-2` remain **open**. This does **not** close Phase 6.

Related: [`research-r-ralph-2-baseline.md`](research-r-ralph-2-baseline.md) (BASELINE row stays **done**).

## Packaging shift (dogfood, accessed 2026-08-09)

| field | value |
| --- | --- |
| Package | `@anthropic-ai/claude-code@2.1.226` |
| Host path | `C:/Users/oimir/AppData/Roaming/npm/node_modules/@anthropic-ai/claude-code/` |
| `bin.claude` | `bin/claude.exe` (native) |
| Published `files` | `bin/claude.exe`, `install.cjs`, `cli-wrapper.cjs`, `sdk-tools.d.ts` |
| `cli.js` | **does not ship** — historical Ralph README path is obsolete |

Pinned public index: https://www.npmjs.com/package/@anthropic-ai/claude-code (accessed 2026-08-09).

Oracle source tree still present at `/mnt/c/dev/projects/claude-code-main`, but without a JS bundle entry the large-product RALPH-2 case cannot be scored.

## Phase-6 target redefinition

| layer | target | status |
| --- | --- | --- |
| **Product RALPH-2** (large Anthropic `cli.js`-class bundle) | Legitimate large JS bundle + matching oracle | **blocked** / `input_absent` until such an input exists again |
| **Interim measurement surface** (Wave 3) | `test_samples/js_tracked_bundle_artifact/bundle.js` + oracle `test_samples/js_tracked_bundle_source` | **scored** — see report below |

Do **not** market the micro-bundle score as “cli.js recall” or enterprise JS GA (fixture ≠ capability).

## Measured interim baseline

| field | value |
| --- | --- |
| status | scored (harness exit 2 — target not met) |
| `best_project_file_recall` | `0.0` |
| scorecard notes | `no_recovered_root`, `no_recovered_project_files` |
| Report | [`reports/js_oracle_ralph_tracked/ralph_report.json`](../../reports/js_oracle_ralph_tracked/ralph_report.json) |
| Interpreter | `/usr/bin/python3.9` |
| Command | `python3.9 scripts/ralph_js_oracle_loop.py --input test_samples/js_tracked_bundle_artifact/bundle.js --oracle test_samples/js_tracked_bundle_source --output-dir reports/js_oracle_ralph_tracked --target-recall 0.80 --max-attempts 1 --no-plateau --no-js-behavior-probe` |

Scoring keys live in `src/reveng/app_reverse_engineering/ralph_js_loop.py` (`oracle_recall_precision` / `best_project_file_recall`) and `js_oracle_scorecard.py` (emits `no_recovered_root` when `output_dir/project` is missing — see `adapters/javascript.py` `_project_recovered_root`).

### Noise calibration

1. **Measurement surface:** `project_file_recall` on the interim tracked bundle.  
2. **No-op control:** same input/oracle, unchanged engine, `max_attempts=1`.  
3. **SNR threshold:** later wedge must beat run-to-run control variation with a recovered `project/` tree; do not productize on SPECS-only artifacts.  
4. **Kill condition:** target 0.8, attempt cap, or declared plateau — or keep open if still `no_recovered_root`.

### Bidirectional / control honesty (instrument-limited)

A mismatched-oracle arm (tracked bundle vs `test_samples/native/hello_go`) also scored `0.0` with the same `no_recovered_root` notes. This is an **instrument-limited, non-discriminatory** result: both arms fail **before** filename-set matching, so the pair is **not** evidence that recovery approaches are equally ineffective — only that `project/` never materialized. Positive control for the scorecard math remains the unit tests under `tests/unit/` covering `js_oracle_scorecard` / Ralph loop fixtures — not this dogfood pair.

## Ranked engine wedges (authorized for a later Sol-gated wave only)

Ranked only because a scored interim baseline exists (recall `0.0` with explicit notes — not an invented zero for `input_absent`):

1. **Materialize `output_dir/project`** from source-map / `artifacts/normalized.js` so `_project_recovered_root` is non-`None` (smallest wedge; unblocks nonzero recall). Evidence: `adapters/javascript.py` recovered-root contract; Wave 3 analysis recovered SPECS + `normalized.js` but no `project/`.
2. **Source-map path alias / RALPH-1 carry-through** into the reconstructed tree once `project/` exists.
3. **P4-BUNDLER** import-graph precision/recall on the same tracked surface.

**No** `src/reveng/**` engine edits land in Wave 3.

## Sol stop/go (Phase 6)

| Decision | Verdict |
| --- | --- |
| Large Phase-6 PR aimed at Anthropic `cli.js` 0.8 | **NO-GO** — input obsolete / absent |
| Wave that implements wedge (1) on the tracked surface with bidirectional recovered-tree proof | **GO candidate** (separate wave; not this PR) |
| Claim RALPH-2 / Phase 6 / enterprise JS GA done | **FORBIDDEN** |

## Explicit non-claims

- Not enterprise public / not GA.  
- Not world-class M2 / not M1-NATIVE-FAM.  
- Not MCP productization.  
- `R-RALPH-2` stays **open** until a wedge is implemented and measured on an authorized surface.
