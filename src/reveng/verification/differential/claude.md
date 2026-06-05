# `claude.md` — `verification/differential`

**Repository path:** `src/reveng/verification/differential/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Differential execution oracle sub-package.

### `harness.py`
- **Summary:** Subprocess-based execution harness for differential binary testing.
- **Classes:**
  - `ExecutionResult` — Captured result from running a binary once.
  - `HarnessError` — Raised when the harness cannot launch the target binary.
  - `ExecutionHarness` — Thin subprocess wrapper that runs a binary with stdin input.

### `oracle.py`
- **Summary:** Differential execution oracle.
- **Classes:**
  - `DifferentialOracle` — Differential execution oracle for the Verified Recompilation Loop.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
