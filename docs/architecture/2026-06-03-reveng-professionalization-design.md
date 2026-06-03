# REVENG Professionalization — Design Spec

**Date:** 2026-06-03
**Status:** Approved (design); implementation pending plan
**Scope:** Clean up the working tree, fix all audited bugs, get the test suite green, and re-layer `src/reveng/` into a professional, legible architecture — **without breaking what works**.

## 1. Goal & success gates

Turn REVENG from "works superficially, cluttered tree, hidden defects" into a professional application with a clean package layout. Four gates must be **simultaneously green on a clean checkout** when the work is done, and must be re-run as the safety net after every structural move:

1. **Tests** — `pytest tests/unit tests/integration` green (excluding `requires_external_tools`, `slow`, `requires_network`).
2. **CLI smoke** — `reveng`, `reveng-app`, `reveng-js` resolve and run `--version` / `--help` / a representative subcommand.
3. **VRL** — `scripts/run_vrl.py` runs end-to-end and converges on the hexyl corpus entry **after** the harness argv bug is fixed (i.e. genuine convergence, not the current spurious one).
4. **Lint/type** — `make lint` (black, isort, pylint, mypy) clean on touched code.

**Baseline (2026-06-03):** 1171 tests collect with **zero import errors**; unit run = **867 pass / 46 fail / 9 skip**. The 46 failing node IDs are the regression ledger; pre-existing failures are not counted as regressions once fixed.

## 2. Decisions (locked)

| Decision | Choice |
|---|---|
| Restructure method | **Option A (Conservative Consolidation) + Option C port seams.** Incremental, shim-backed moves into 7 functional domains; introduce `LLMProviderPort` and `OraclePort`/`CompilerPort` where the critical bugs live. Option B (full hexagonal) is recorded as the documented "north star" only. |
| Bug handling | **Fix everything found** (real bugs from triage + the 15 static findings), each with a regression test. |
| `test_local_disassembler.py` (36 failures) | **Skip/xfail the module** with `reason='rich local pseudocode renderer not yet implemented'` + file a tracking issue. The shipped module is a deliberate minimal fallback; do not invent the renderer now. |
| `.reveng/vrl-runs/*.json` | **Gitignore** (`git rm --cached` + add pattern). Treated as regenerable run artifacts. |

## 3. Target architecture (Option A + C)

Seven functional domains, reached **incrementally via re-export shims** so every legacy import path keeps working until Phase 4 retires it:

- **`reveng/` (facade)** — `__init__.py`, `__main__.py`, `version.py`, `api.py` (absorbs `ai_api.py`). `ir.py` and `result_contracts.py` become shims re-exporting from `core/`.
- **`reveng/cli/`** — promoted to a **real package** (`__init__.py` exposing `main()`), split from the 1915-LOC `cli.py` (`parser.py`, `commands/`, single canonical `recompile_command.py`). Orphan `cli/` contents deleted.
- **`reveng/core/`** — foundation: `exceptions`, `error_codes`, `validation`, `config`, `result_contracts` (moved here), shared AI data models (moved here to break the cycle). Depends only on `utils`.
- **`reveng/analysis/`** — `analyzer.py` (REVENGAnalyzer), `analyzers/`, `pe/`, `native/`, `lifting/` (+ `ir.py`), `devirtualization/`, `deobfuscation/`, `diffing/`.
- **`reveng/intelligence/`** — merged `ai/` + `agents/ai/` (one AI home; the swap-word pair renamed `ai_provider_registry.py` / `ai_enhanced_orchestrator.py`), `security/`, `ml/`, `malware/`.
- **`reveng/orchestration/`** — `pipeline/` (dead `pipelines/` deleted), recompile glue, `app_reverse_engineering/`, `javascript/`, `verification/` (VRL behind the ports).
- **`reveng/integrations/` + `reveng/agent_sdk/` + `reveng/tools/`** — Ghidra/external bridges, MCP servers/client/skills, and the `tools/` god-package progressively split by subdomain (`binary`, `languages`, `decompilers`, `threat_intel`, `quality`, `translation`) toward `analysis`/`intelligence`, leaving `tools/` as a shim namespace.

**Port seams (Option C):** `reveng/core/ports.py` defines `LLMProviderPort` and `OraclePort`/`CompilerPort`. AI provider analyzers implement `LLMProviderPort`; the VRL harness/`compile_adapter` consume the oracle/compiler ports — the Phase-1 VRL bug fixes land behind these stable seams.

## 4. Phased plan

Each phase ends with the **full four-gate sweep**. Restructure phases move **one module/sub-package at a time, shim-backed, gate, then proceed** — never a big-bang import rewrite.

### Phase 0 — Cruft removal + gitignore hardening (no `src/reveng` logic touched)
- Record baseline failing node IDs as the regression ledger.
- **Delete:** `_list_analysis.py`; `reports/_tmp_app_corpus_*.json`; the ~170 `reports/app_reverse_engineering_corpus_claude_real_v*.json` + base/`_cli_real`/`_local`/`_loop`/`_loop_smoke` dumps; stray top-level `projects/`.
- **Gitignore (file-level — existing dir-only patterns miss the `.json` files):** `reports/app_reverse_engineering_corpus_claude_*.json`, `reports/_tmp_*.json`, `reports/source_binary_benchmarks*`, `reports/ralph_tracked_bundle_*/`, `reports/app_reverse_engineering_tool_eval_*/`, `reports/app_reverse_engineering_corpus_js_oracle*.json`, `reports/cli_js_user_proof_run/`, `reports/tracked_js_bundle_benchmark/`, `reports/app_reverse_engineering_corpus_javascript_test/`, `external/ga_binaries/`, `external/ghidramcp/`, `.reveng/vrl-runs/*.json` (+ `git rm --cached`).
- **Keep & commit:** all `claude.md` nav files, `HANDOFF.md` + new architecture/IR/roadmap/hardening docs, new source modules + their new unit tests, new maintenance/benchmark scripts.
- Gate: collection still 1171 / same 46 fail. **Verify zero inbound readers before deleting any `reports/` file a generator might read.**

### Phase 1 — Make the suite green (fix real bugs, retire stale tests) BEFORE moving anything
Real bugs (with regression tests):
- **CLI wrapper** (`cli/reveng.py`, 4 tests): force `SRC_ROOT` to `sys.path[0]`, strip the script-dir entry, drop the `not in sys.path` guard. Verify `python src/reveng/cli/reveng.py --version` exits 0.
- **Source-map recoverer** (3 tests): UTF-8 `errors='replace'`; recognize inline `data:` URLs verbatim; fix `Path(str(filepath)+'.map')`; base64-decode inline `data:` URLs; strip `sourceRoot`/`./`/query/hash and dedupe.
- **JS→IR** (1 test): add `ir_file` to `BundleReverseEngineeringResult`, emit `REProjectIR` (`language='javascript'`, cli/auth/mcp nodes) to `artifacts_dir/project.re_project_ir.json`.
- **Fixture**: add `javascript-tracked-bundle` row to both `.reveng/app_reverse_engineering_corpus.json` and `.ga.json`.

Stale tests:
- `claude_cli_analyzer`: drop `--bare` assertion; assert `--no-session-persistence` + `--permission-mode bypassPermissions`.
- `test_local_disassembler.py`: xfail the module + tracking issue.

Static bugs (regression test each):
- **CRITICAL** `verification/differential/harness.py`: thread **argv** through `ExecutionHarness.run()` / `ExecutionResult` / `DifferentialOracle.verify` / `run_vrl` seed handling, so CLI args are passed as argv, not stdin.
- **HIGH** `run_vrl.py`: write a valid **ValidationGrade** (from `result.final_divergence.grade`) into `current_grade`, not the `RefinementStatus`.
- **HIGH** `agent_sdk/client.py`: `ToolError(tool_name, message)` 2-arg calls (184/189/193); add a non-raising registry lookup so `None`-guards work (188/220-224).
- **HIGH** `agent_sdk/tools/reveng/binary_analysis_tool.py`: `REVENGAnalyzer(binary_path=path)` + `analyze_binary()` (no positional path).
- **HIGH** `agent_sdk/skills/builtin/security_audit.py`: `ToolResult.content` (not `.data`).
- **HIGH** `javascript/babel_transformer.py`: callable `re.sub` replacement (no backslash/group-ref injection).
- **MED** `tools/languages/python_bytecode_analyzer.py`: numeric `(major, minor)` version compare.
- **MED** `tools/threat_intel/virustotal_connector.py`: `setdefault("threat_intel", {})` before both branches.
- **MED** `javascript/deobfuscator.py`: init `input_file=None`; guard finally; catch `(OSError, FileNotFoundError)`.
- **MED** `run_vrl.py`: exact corpus-name match (not substring) for `current_grade` rewrite.
- **LOW** `tools/anti_analysis/bun_extractor.py`: `try/finally` + `shutil.rmtree` temp-dir cleanup.
- **LOW** `agent_sdk/mcp/servers/filesystem.py`: path containment via `relative_to`/`commonpath`, not `startswith`.
- **LOW** `verification/refinement/refiner.py` & `compile_adapter.py`: preserve token telemetry on LLM_ERROR; assert binary `exists()`/freshness after compile.
- Gate: unit+integration green; CLI smoke; one `run_vrl` convergence smoke; `make lint` clean.
- **Re-baseline** the hexyl corpus after the argv fix (entries that "converged" spuriously may correctly fail — expected).

### Phase 2 — Resolve duplicates & orphan packages (smallest structural moves, shim-backed)
- Promote `cli.py` → `cli/` package (`__init__.py` re-exports `main`); make `recompile_command.py` the single canonical copy in `cli/`; **delete** duplicate `cli/recompile_command.py` and redundant `cli/reveng.py`.
- **Delete** dead `pipelines/` (zero importers; confirm by grep).
- Rename `ai_analyzer_enhanced.py` → `ai_provider_registry.py`, `ai_enhanced_analyzer.py` → `ai_enhanced_orchestrator.py` (shims at old names).
- Consolidate `ai_api.py` into `api.py` (thin shim left for `test_result_contracts.py`).
- **Delete** `analyzers/business_logic_analyzer.py` only after confirming the `security/corporate_exposure_detector.py` reference is a local class, not an import.
- Gate after **each** deletion/rename.

### Phase 3 — Relocate root modules + introduce the 7 domains (shim-backed)
- Move `result_contracts.py` → `core/`; `ir.py` → `lifting/` (or `core/`) — root shims left.
- **Break `ai`↔`security` cycle**: relocate shared `ai_enhanced_data_models` to a leaf (`core/ai_models.py`); fix the guarded `from ..ai.ai_enhanced_data_models` that targets a nonexistent file. Verify acyclicity with an import-graph check.
- Add `core/ports.py` (`LLMProviderPort`, `OraclePort`/`CompilerPort`); conform AI providers + VRL harness/compile_adapter.
- Introduce `analysis/`, `intelligence/`, `orchestration/` and move sub-packages incrementally, each with a legacy-path shim.
- Begin dissolving `tools/` by subdomain (shim namespace left behind).
- Gate after **each** move; regenerate `claude.md` at phase end.

### Phase 4 — Shim removal + final verification
- Per shim: grep all importers (src + tests + scripts + docs), rewrite to canonical path, delete shim, gate. One shim at a time.
- Add an **import-direction guard** (import-linter contract or a pytest) so layering can't silently regress.
- Regenerate every `claude.md`; update `docs/architecture` with the final 7-domain layout + Option B north star.
- Final four-gate sweep on a clean checkout; verify `pyproject [project.scripts]` and `__main__` resolve identically under editable **and** clean installs.

## 5. Risks & mitigations
- **Big-bang drift** — the primary process risk; mitigation is strict move-one/shim/gate discipline.
- **Incomplete shims** break importers silently → `from .newhome import *` + explicit `__all__` + per-move gate.
- **VRL re-baseline** — argv fix may flip corpus grades red for the right reason; re-baseline `current_grade` and the CI gate after the fix.
- **Cycle break surfaces latent errors** — fixing the masked `ai_enhanced_data_models` import may reveal `NameError`s hidden behind `try/except ImportError`.
- **Lint ceiling** — `analyzer.py` (1945) / `cli.py` (1915) are near `pylint max-module-lines=2000`; splitting is real logic surgery — preserve behavior.
- **Install variance** — verify `reveng.cli` resolution under editable + clean installs after the cli package promotion.
- **Generator inputs** — confirm zero inbound *readers* (not just importers) before deleting `reports/` dumps.

## 6. Execution note
Implementation will be driven by per-phase **workflows** (parallel subagents) under a written implementation plan (next step: `writing-plans`). Each workflow phase ends by running the four gates and reporting results before the next phase begins.
