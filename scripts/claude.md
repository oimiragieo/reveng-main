# `claude.md` — `scripts/`

**Repository path:** `scripts/`

Maintenance and CI helper scripts (not part of the `reveng` import graph unless documented).

## Files

- `benchmark_tracked_js_bundle.py` — Benchmark + integrity gate for the tracked JS bundle corpus artifact.
- `bootstrap_windows.bat`
- `build_tracked_js_bundle.py` — Rebuild the checked-in tracked JS bundle + external source map + SHA-256 manifest.
- `generate_app_corpus_fixtures.py`
- `generate_claude_md_index.py` — Maintenance helper: regenerate per-folder `claude.md` breadcrumbs.
- `generate_release_report.py`
- `generate_sample_dotnet_fixture.py`
- `generate_skip_inventory.py`
- `install_ghidra.py` — Download and install the Ghidra binary distribution for REVENG.
- `provision_ga_assets.py`
- `ralph_js_oracle_loop.py` — Ralph-style loop: re-run JavaScript app reverse-engineering with rotating tool variants
- `run_app_reverse_engineering_corpus.py`
- `run_bun_sample_matrix.py`
- `run_source_binary_benchmark.py`
- `run_vrl.py` — run_vrl.py — End-to-end Verified Recompilation Loop runner.
- `setup_first_run.ps1`
- `start-ghidra-server.py` — REVENG Ghidra Server Starter
- `verify_ga_readiness.py`

---
*Regenerate breadcrumbs: `python scripts/generate_claude_md_index.py`.*
