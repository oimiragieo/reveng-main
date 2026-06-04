# `claude.md` — `native`

**Repository path:** `src/reveng/native/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Native binary reverse-engineering helpers.

### `ghidra_workflow.py`
- **Summary:** Shared native/Ghidra workflow helpers.
- **Functions / coroutines:**
  - `def candidate_ghidra_urls()` — Return candidate Ghidra server URLs in priority order.
  - `def run_native_ghidra_analysis()` — Run native analysis via Ghidra with a local-disassembler fallback.
  - `def _analyze_with_lock_retry()` — Retry once when the Ghidra server reports a transient temp-project lock.
  - `def _is_ghidra_lock_error()` — Identify Ghidra temp-project lock failures that are worth retrying once.
  - `def summarize_native_analysis()` — Return bounded counts for native analysis.
  - `def write_analysis_payload()` — Write JSON payload with stable formatting.
  - `def materialize_decompiled_functions()` — Write decompiled functions to disk and return created files.
  - `def build_native_project_ir()` — Build a shared IR document from native analysis output.
  - `def build_native_source_segments()` — Convert native analysis into snippet-friendly source segments.
  - `def _get_decompiled_functions()`
  - `def _normalize_named_items()`
  - `def _normalize_string_items()`
  - `def _normalize_data_items()`
  - `def _normalize_xref_map()`
  - `def _normalize_xref_record()`
  - `def _render_xref_lines()`
  - `def _build_native_surface_summary()`
  - `def _build_function_detail_summary()`
  - `def _extract_urls()`
  - `def _extract_cli_flags()`
  - `def _infer_domains()`
  - `def _segment_text()`
  - `def _unique()`

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
