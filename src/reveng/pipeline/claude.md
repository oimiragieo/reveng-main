# `claude.md` — `pipeline`

**Repository path:** `src/reveng/pipeline/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `steps/` — [`claude.md`](steps/claude.md)

## Python modules

### `__init__.py`
- **Summary:** Pipeline orchestration helpers for the REVENG analyzer.

### `e2e_integration.py`
- **Summary:** End-to-end CLI pipeline orchestration for async analysis integration.
- **Classes:**
  - `EndToEndPipelineRunner` — Run the CLI's end-to-end async analysis lifecycle.

### `pipeline_engine.py`
- **Summary:** REVENG automated analysis pipeline engine.
- **Classes:**
  - `PipelineStatus` — Pipeline execution status
  - `StageStatus` — Pipeline stage status
  - `StageType` — Pipeline stage types
  - `PipelineStage` — Pipeline stage definition
  - `StageResult` — Pipeline stage execution result
  - `Pipeline` — Pipeline definition
  - `PipelineResult` — Pipeline execution result
  - `AnalysisPipeline` — Automated analysis pipeline with tool chaining

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
