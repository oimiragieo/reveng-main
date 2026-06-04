# `claude.md` — `reveng (package root)`

**Repository path:** `src/reveng/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** REVENG Universal Reverse Engineering Platform
- **Functions / coroutines:**
  - `def __getattr__()` — Lazily import top-level exports to avoid eager optional-dependency loading.

### `__main__.py`
- **Summary:** REVENG Universal Reverse Engineering Platform - Entry Point

### `ai_api.py`
- **Summary:** AI-Optimized Python API for REVENG
- **Classes:**
  - `AnalysisMode` — Analysis depth levels
  - `TriageResult` — Results from instant triage analysis.
  - `CryptoDetails` — Cryptography-related findings.
  - `NetworkDetails` — Network-related findings.
  - `TranslationGuide` — C-to-Python translation guide.
  - `REVENG_AI_API` — AI-optimized Python API for REVENG.
- **Functions / coroutines:**
  - `def quick_triage()` — Quick triage of a binary.
  - `def quick_ask()` — Quick natural language query, returns just the answer string.

### `analyzer.py`
- **Summary:** Backwards-compatibility shim — moved to :mod:`reveng.analysis.analyzer`.

### `api.py`
- **Summary:** REVENG Unified API
- **Classes:**
  - `REVENGAPI` — Unified API for programmatic access.
- **Functions / coroutines:**
  - `def _utc_timestamp()`
  - `def analyze_binary()` — Convenience function for binary analysis.
  - `def detect_malware()` — Convenience function for malware detection.
  - `def reconstruct_binary()` — Convenience function for binary reconstruction.
  - `def reverse_engineer_app()` — Convenience function for app reverse engineering.
  - `def run_app_reverse_engineering_corpus()` — Convenience function for the app reverse-engineering corpus.

### `ir.py`
- **Summary:** Backwards-compatibility shim — moved to :mod:`reveng.core.ir`.

### `recompile_command.py`
- **Summary:** Recompile Command - Binary to Source to Binary Pipeline
- **Functions / coroutines:**
  - `def _console_safe_text()` — Return text that can be printed on the active console encoding.
  - `def _safe_print()` — Print text without crashing on narrow Windows console encodings.
  - `async def recompile_command()` — Run the complete binary recompilation pipeline.
  - `def print_reconstruction_summary()` — Print a beautiful summary of reconstruction results.
  - `def generate_reconstruction_report()` — Generate a comprehensive markdown report.
  - `def run_recompile_command()` — Synchronous wrapper for asyncio command.

### `result_contracts.py`
- **Summary:** Backwards-compatibility shim — moved to :mod:`reveng.core.result_contracts`.

### `version.py`
- **Summary:** REVENG Version Information
- **Functions / coroutines:**
  - `def _read_version_from_file()` — Read version from VERSION file in project root.
  - `def get_version()` — Get the current version string.
  - `def get_version_info()` — Get the version as a tuple of integers.
  - `def get_version_string()` — Get a formatted version string with additional information.
  - `def get_build_info()` — Get build information.
  - `def get_system_info()` — Get system compatibility information.
  - `def is_compatible_python()` — Check if the given Python version is compatible.
  - `def get_minimum_requirements()` — Get minimum system requirements.
  - `def read_version_from_file()` — Read version from VERSION file if it exists.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
