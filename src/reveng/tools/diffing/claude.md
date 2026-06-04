# `claude.md` — `tools/diffing`

**Repository path:** `src/reveng/tools/diffing/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Binary Diffing Tools

### `binary_differ.py`
- **Summary:** Binary Diffing Engine for REVENG
- **Classes:**
  - `FunctionMatch` — Represents a match between functions in two binaries
  - `DiffResult` — Result of binary diff operation
  - `BinaryDiffer` — Binary diffing engine for comparing two binaries.
- **Functions / coroutines:**
  - `def quick_diff()` — Quick binary diff

### `patch_analyzer.py`
- **Summary:** Patch Analyzer for REVENG
- **Classes:**
  - `Vulnerability` — Identified vulnerability from patch analysis
  - `PatchAnalyzer` — Security patch analyzer.
- **Functions / coroutines:**
  - `def analyze_patch()` — Quick patch analysis

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
