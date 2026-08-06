# R-PIPE-1 — `reveng.pipeline` vs `reveng.pipelines` (2026-08-06)

**Wave A decision:** keep the **permanent documented split** (freeze).  
This closes the *research* row `R-PIPE-1` only. Product row `M5-PIPE` stays `partial`.

Wave B may still implement an *optional later migration/merge* under `M5-PIPE` exit criteria. That is not a contradiction: Wave A freezes the documented boundary; Wave B may migrate later if and only if those criteria are met.

## Measured state

| package | module count (`*.py`) | import-site files (src + tests) |
| --- | --- | --- |
| `reveng.pipeline` | 6 | 6 |
| `reveng.pipelines` | 2 | 2 |

Counted on 2026-08-06 in worktree `scope-c-phase-next` with:

- `find src/reveng/pipeline src/reveng/pipelines -name '*.py'`
- `rg -l` for `from reveng.pipeline` / `from reveng.pipelines` under `src/` and `tests/`

### Package docs (responsibility boundary)

- `src/reveng/pipeline/__init__.py` — stage engine + step runners for the analyzer; docstring states it is distinct from `reveng.pipelines` and points at M5-PIPE before any merge.
- `src/reveng/pipelines/__init__.py` — high-level workflow templates; docstring lists the intentional split and forbids merge without an import-linter migration plan (M5-PIPE).
- Navigation breadcrumbs: `src/reveng/pipeline/claude.md`, `src/reveng/pipelines/claude.md`.

### Contract test already locking the split

`tests/unit/test_pipeline_package_split.py` — `test_pipeline_and_pipelines_remain_distinct_packages` asserts distinct package names, cross-docstring mentions, `pipelines.AutomatedAnalysisPipeline`, and `pipeline.steps`.

### Import-linter

`.importlinter` references `reveng.pipeline` (layer/contract inventory).  
`lint-imports --no-cache` could not be executed in this dogfood shell (`Permission denied` on the `lint-imports` binary). That is an environment limit, not evidence for merging the packages.

## Decision

**PERMANENT DOCUMENTED SPLIT (Wave A freeze)** — because:

1. The packages already document different jobs (engine/steps vs opinionated templates).
2. Fan-in is small but real on both sides; a merge without a planned shim+contract wave would churn CLI and tests for no Wave A gain.
3. `test_pipeline_package_split` already encodes the split as a regression gate.

## Consequences

- **Wave A:** no `src/reveng/**` merge work; research `R-PIPE-1` may be marked done (decision recorded) at backlog reconcile.
- **Wave B (optional):** a future merge remains allowed only under `M5-PIPE` exit criteria (alias shims, sliced migration, import-linter contract). Wave A does not require that merge.

## Exit criterion for M5-PIPE

Closes when either (a) the permanent split is locked by an explicit import-linter contract and docs/tests stay green, or (b) a planned merge migration lands with shims + contracts and `lint-imports --no-cache` passes. Wave A does not implement either path beyond this freeze decision.
