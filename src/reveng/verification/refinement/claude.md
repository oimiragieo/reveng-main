# `claude.md` — `verification/refinement`

**Repository path:** `src/reveng/verification/refinement/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** reveng.verification.refinement — Iterative LLM Refiner

### `compile_adapter.py`
- **Summary:** Adapter that wraps SmartCompiler into the compile_fn callable expected by IterativeRefiner.
- **Functions / coroutines:**
  - `def make_compile_fn()` — Return a ``compile_fn`` callable compatible with :class:`IterativeRefiner`.

### `models.py`
- **Summary:** Data models for the Iterative LLM Refiner.
- **Classes:**
  - `RefinementStatus` — Terminal state of an IterativeRefiner run.
  - `RefinementBudget` — Constraints that govern how long the refinement loop is allowed to run.
  - `RefinementRound` — Record of a single iteration in the refinement loop.
  - `RefinementResult` — Final outcome returned by IterativeRefiner.refine().

### `oracle_adapter.py`
- **Summary:** Adapter that creates oracle_factory callables for the IterativeRefiner.
- **Functions / coroutines:**
  - `def make_oracle_factory()` — Return a factory: ``(recompiled_binary: Path) -> DifferentialOracle``.

### `prompts.py`
- **Summary:** Prompt templates for the Iterative LLM Refiner.
- **Functions / coroutines:**
  - `def build_refinement_prompt()` — Format REFINEMENT_PROMPT_TEMPLATE with data extracted from *divergence*.
  - `def _decode_output()` — Decode raw bytes to a human-readable string for inclusion in the prompt.

### `refiner.py`
- **Summary:** Iterative LLM-guided recompilation refinement loop.
- **Classes:**
  - `IterativeRefiner` — Iterative LLM-guided recompilation refinement loop.
- **Functions / coroutines:**
  - `def _extract_code_block()` — Extract the first fenced code block from *text*.
  - `def _count_tokens()` — Best-effort extraction of token count from an LLM result object.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
