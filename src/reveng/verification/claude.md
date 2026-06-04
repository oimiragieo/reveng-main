# `claude.md` — `verification`

**Repository path:** `src/reveng/verification/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `differential/` — [`claude.md`](differential/claude.md)
- `refinement/` — [`claude.md`](refinement/claude.md)
- `symbolic/` — [`claude.md`](symbolic/claude.md)

## Python modules

### `__init__.py`
- **Summary:** reveng.verification — Verified Recompilation Loop Oracle Package

### `models.py`
- **Summary:** Shared data models for the Verified Recompilation Loop verification oracles.
- **Classes:**
  - `VerificationVerdict` — High-level outcome of a verification run.
  - `DivergenceReport` — Result from differential execution of an original vs recompiled binary.
  - `EquivalenceResult` — Result from symbolic equivalence checking of a single function pair.
- **Functions / coroutines:**
  - `def grade_rank()` — Return the ladder rank of *grade*.
  - `def _grade_from_divergence_count()` — Map divergence statistics to a grade string.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
