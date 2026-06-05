# `claude.md` — `cli`

**Repository path:** `src/reveng/cli/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** REVENG Universal Reverse Engineering Platform - CLI Interface
- **Functions / coroutines:**
  - `def create_parser()` — Create the command-line argument parser.
  - `def create_enhanced_features()` — Create enhanced analysis features from command line arguments.
  - `def _detect_bun_executable()` — Return a Bun extractor and detection info for the given binary.
  - `def _maybe_handle_bun_analysis()` — Route Bun executables to bundle extraction instead of native analysis.
  - `def _default_bun_decompile_output()`
  - `def _select_bun_recompilation_input()` — Choose the cleanest recovered Bun artifact for downstream recompilation.
  - `def _normalize_bun_workspace()` — Create a normalized Node-compatible workspace from the preferred Bun source artifact.
  - `def _run_bun_sea_build()` — Shared Bun SEA build workflow used by dedicated and delegated CLI paths.
  - `def _maybe_handle_bun_decompile()` — Route Bun executables to JS extraction instead of native decompilation.
  - `def run_end_to_end_analysis()` — Run the integrated async CLI analysis lifecycle.
  - `def handle_analyze_command()` — Handle the analyze command.
  - `def handle_reverse_engineer_app_command()` — Handle the language-agnostic app reverse-engineering command.
  - `def handle_serve_command()` — Handle the serve command (web interface).
  - `def handle_ask_command()` — Handle the ask command (Natural Language Interface).
  - `def handle_ai_command()` — Handle the ai command (AI Assistant).
  - `def handle_triage_command()` — Handle the triage command (Instant Triage).
  - `def handle_vt_lookup_command()` — Handle the vt-lookup command.
  - `def handle_vt_submit_command()` — Handle the vt-submit command.
  - `def handle_generate_yara_command()` — Handle the generate-yara command.
  - `def handle_scan_yara_command()` — Handle the scan-yara command.
  - `def handle_diff_command()` — Handle the diff command.
  - `def handle_patch_analysis_command()` — Handle the patch-analysis command.
  - `def handle_detect_packer_command()` — Handle the detect-packer command.
  - `def handle_unpack_command()` — Handle the unpack command.
  - `def handle_enhance_code_command()` — Handle the enhance-code command.
  - `def handle_recompile_command()` — Handle the recompile command.
  - `def handle_build_bun_sea_command()` — Handle packaging a recovered Bun executable with Node SEA.
  - `def _flatten_decompiled_output()` — Convert structured decompiler output into a text blob for file export.
  - `def handle_decompile_command()` — Handle the decompile command.
  - `def handle_generate_exploit_command()` — Handle the generate-exploit command.
  - `def main()` — Main CLI entry point.

### `reveng.py`
- **Summary:** Direct CLI wrapper for manual `python src/reveng/cli/reveng.py ...` execution.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
