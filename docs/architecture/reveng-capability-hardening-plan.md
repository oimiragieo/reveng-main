# REVENG capability hardening plan

This plan turns the prior “improvement ideas” discussion into phased, measurable work. It aligns with [reveng-system-paper.md](reveng-system-paper.md), [current-platform-status.md](current-platform-status.md), and the corpus/GA discipline in [reveng-world-class-implementation-roadmap.md](reveng-world-class-implementation-roadmap.md).

## Principles

1. **Evidence first** — Every new “capability” claim must serialize to `analysis.json` with explicit dimensions and tool/version notes.
2. **Separate layout from behavior** — Oracle file overlap is not executable correctness; report both when available.
3. **TDD** — Each phase lands with unit or contract tests before expanding scope.

## Phase 1 (implemented in-repo): Capability report + JS smoke

**Goal:** Analysts and agents see a stable `capability_report` object on every app reverse-engineering result, plus optional JavaScript syntax checks on recovered `.js`/`.cjs`/`.mjs` files.

**Deliverables:**

- `capability_report` top-level field in enriched app `analysis.json` (`schema_version` + `dimensions`).
- `dimensions.oracle_alignment` — copies key fields from `benchmark_scorecard` when present (recall/precision, reconstruction mode).
- `dimensions.javascript_smoke` — `package.json` parse, `node` availability, bounded `node --check` results on recovered sources.
- CLI: `--oracle-dir`, `--no-js-syntax-check`; human-readable capability lines after a successful run.
- API: `run_js_syntax_check` kwarg on `framework.reverse_engineer` and `REVENGAPI.reverse_engineer_app`.

**Non-goals for Phase 1:** npm install, runtime behavior tests, native equivalence upgrades.

## Phase 2: Reproducible JS benchmark artifacts (landed)

**Goal:** Remove machine-local-only `cli.js` paths from the critical path for CI.

**Implemented:**

- **Source:** `test_samples/js_tracked_bundle_source/` — minimal multi-file TypeScript, `esbuild@0.21.5`, `package-lock.json` committed.
- **Artifact:** `test_samples/js_tracked_bundle_artifact/bundle.js`, `bundle.js.map`, `build_manifest.json` (schema `reveng.tracked_js_bundle/1`) with per-file SHA-256.
- **Rebuild:** `python scripts/build_tracked_js_bundle.py` (uses `npm install` + local `node_modules/.bin/esbuild`).
- **Verify (no npm):** `python scripts/build_tracked_js_bundle.py --verify-only`
- **Benchmark JSON:** `python scripts/benchmark_tracked_js_bundle.py` (manifest proof + one RE pass + timings). Use `--verify-only --output PATH` for fast CI proof; full run with `--output` writes schema `reveng.tracked_js_bundle_benchmark/1` (manifest + reverse_engineer sections).
- **TDD:** `tests/unit/test_tracked_js_bundle_manifest.py` — hash proof + tamper detection + subprocess CLI proofs + capability/scorecard smoke. Filter: `pytest -m tracked_bundle` for the RE benchmark slice.
- **CI:** `.github/workflows/tests.yml` runs verify-only benchmark JSON under `reports/tracked_js_bundle_benchmark/ci_verify.json`.
- **Corpus:** `javascript-tracked-bundle` in `.reveng/app_reverse_engineering_corpus.json` and `.reveng/app_reverse_engineering_corpus.ga.json`.

**Still separate:** the real installed Claude `cli.js` row remains in local-only configs; this phase adds a **portable, checked-in** esbuild bundle for PR/GA machines.

## Phase 2b: Ralph loop for JS oracle recall (tool-variant retries)

**Goal:** Repeat “run → score → retry” without pretending identical runs improve metrics.

**Implemented:**

- **`src/reveng/app_reverse_engineering/ralph_js_loop.py`** — `run_ralph_js_oracle_loop` cycles composed variants: `default_js_ralph_variants()` (baseline, webcrack, snippet depth, restringer, deobfuscator), optional `load_js_ralph_variants_from_json`, optional `heavy_js_ralph_variants` (wakaru / js-deobfuscator), merged via `compose_ralph_variants`.
- **`scripts/ralph_js_oracle_loop.py`** — CLI: `--target-recall`, `--max-attempts`, `--plateau-attempts`, `--variants-json` / `--variants-json-only` / `--no-default-variants`, `--append-wakaru`, `--append-js-deobfuscator`; writes `ralph_report.json` including `variant_schedule`; exit `2` if target not met.
- **`projects/js-oracle-ralph/README.md`** + **`variants.example.json`** — operator guide and sample JSON profiles.
- **Tests:** `pytest -m ralph_js` → `tests/unit/test_ralph_js_loop.py` (pure logic, JSON load, composition, subprocess CLI smoke).

Hitting **0.80+ recall** on production `cli.js` still requires **engine work**; the loop records the best variant and stops on plateau to save machine time.

## Phase 3: Behavior-backed JS validation

**Goal:** A signal distinct from file recall — e.g. CLI `--help` smoke, later `npm pack` / dry-run.

**Implemented (baseline):**

- **`capability_report.dimensions.javascript_behavior_probe`** — resolves `package.json` `bin` / `main`, runs `node <entry> --help` from the reconstructed project root; records `tier` (0–2), exit code, stdout/stderr tails, `summary`.
- **`capability_report` on enrich** — `enrich_app_analysis_payload` builds the report and may promote `validation.grade` (P3-BP-3).
- **Optional npm pack dry-run** — `javascript_npm_lifecycle_probe` (default off).
- **Size-scaled timeouts** — `resolve_javascript_probe_timeout_sec` (P3-BP-4).
- **Ralph loop** — `ralph_score_key` lexicographic order adds **behavior tier** after recall/precision (see `js_behavior_probe_tier`); attempts log `js_behavior_probe_tier`.

**Still open:** optional `tsx` for true TS entry behavior (smoke stub covers most cases).

## Tracked open items (Phase 3 + Ralph)

Single place to pick up this thread without re-deriving context from chat. Update the **Status** column when something lands.

| ID | Issue | Evidence / artifact | Next step | Status |
| --- | --- | --- | --- | --- |
| **P3-BP-1** | Behavior probe skipped when **`main`** was **TypeScript** (Node cannot run it for `--help`). | Landed: `reveng_behavior_smoke.cjs` written into each reconstructed project + `package.json` field **`reveng.behavior_probe_main`**; `_resolve_package_cli_entry` tries it after `bin`/`main`. | Optional: `tsx`/npm lifecycle probes for “real” entry behavior (still open). | Partial |
| **P3-BP-2** | **`npm pack` / `npm run`**-class probes not implemented. | Phase 3 baseline is only `node <entry> --help`. | Landed: optional `run_javascript_npm_lifecycle_probe` (`npm pack --dry-run --ignore-scripts`, default off) as `javascript_npm_lifecycle_probe` dimension. | Done |
| **P3-BP-3** | Behavior signal does not yet **promote** `validation.grade` (only capability + Ralph tie-break). | `contracts.build_validation_summary` today. | Landed: tier 2 + `all_checked_ok` + sources promotes `partial_recovery`/`structure_only` → `evidence_backed`; `capability_report` attached in `enrich_app_analysis_payload`. | Done |
| **P3-BP-4** | Fixed probe timeouts under/over-serve small vs large trees. | `resolve_javascript_probe_timeout_sec` + `project_tree_stats`. | Auto-scale help/npm timeouts by file_count (skip `node_modules`); explicit timeout still wins. | Done |
| **RALPH-1** | Source-map recovered files lived under **`_/…/src/…`** anchors while the oracle used logical **`index` / `lib/greet`** keys, so **project_file_recall** read **0.0** even when files aligned. | Fixed in `JavaScriptBundleReverseEngineer._project_anchor_match_keys` + `_build_benchmark_scorecard` (alias match set). Tests: `test_benchmark_scorecard_aligns_source_map_mirror_paths_with_oracle`. | **Domain** recall for this corpus may still be **0** (single `lib` oracle vs many synthetic domains); treat separately from file overlap. | Partial |
| **RALPH-2** | Real **`cli.js`** + `claude-code-main` loop still the long pole for **0.8+ recall**; harness is done, engine is not. | `projects/js-oracle-ralph/README.md`, local corpus template / reports per execution backlog. | Continue `bundle_reverse_engineer` module synthesis; use `ralph_report.json` + `variant_schedule` to compare variants. | Open |

**Reference command (smoke):**

`python scripts/ralph_js_oracle_loop.py --input test_samples/js_tracked_bundle_artifact/bundle.js --oracle test_samples/js_tracked_bundle_source --output-dir reports/ralph_tracked_bundle_run --max-attempts 100 --no-plateau --target-recall 0.99` (fixed **100**-attempt budget unless target hit; omit `--no-plateau` to allow plateau early-exit)

## Phase 4: Bundler-aware module recovery

**Goal:** Reduce reliance on ad hoc promotion rules in `bundle_reverse_engineer.py` alone.

**Work:**

- Chunk graph for webpack/esbuild signatures; optional integration with specialized debundlers.
- Feed graph edges into oracle scoring (import-graph precision/recall), not only path overlap.

## Phase 5: Native entry-to-behavior closure

**Goal:** Move required native rows from `launches_but_divergent` toward `partial_equivalence` using existing benchmark harness.

**Work:**

- Prioritize entry-reachable helper chains (`helper_reachability_summary` already in play per system paper).
- Expand strict corpus beyond three Windows CLIs when the harness stabilizes.

## Phase 6: Platform consolidation

**Goal:** Single orchestration story and one evidence pipeline for CLI / API / MCP.

**Work:**

- Resolve `pipeline/` vs `pipelines/` overlap; thread `result_contracts` fields uniformly through MCP tools.

---

**Regeneration note:** After large refactors to app RE, refresh breadcrumbs with `python scripts/generate_claude_md_index.py`.
