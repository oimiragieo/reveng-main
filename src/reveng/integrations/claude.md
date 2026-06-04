# `claude.md` — `integrations`

**Repository path:** `src/reveng/integrations/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `ghidra/` — [`claude.md`](ghidra/claude.md)

## Python modules

### `__init__.py`
- **Summary:** Connectors and client wrappers for third-party tooling.

### `local_disassembler.py`
- **Summary:** Local Disassembler - Capstone-based fallback when Ghidra is unavailable
- **Classes:**
  - `DisassemblyResult` — Result of local disassembly analysis.
  - `LocalDisassembler` — Capstone-based local disassembler for basic binary analysis.
- **Functions / coroutines:**
  - `def get_local_disassembler()` — Get a local disassembler instance if dependencies are available.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
