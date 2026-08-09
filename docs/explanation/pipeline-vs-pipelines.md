# `pipeline` vs `pipelines` (R-PIPE-1)

> **Maturity:** documentation / architecture decision is **done** (research row R-PIPE-1) · product row M5-PIPE may still track optional future migration
>
> **Do not claim the packages are merged.** The frozen decision is a **permanent documented split**. See [honesty rules](../support/honesty-rules.md).

Two similarly named packages coexist on purpose. Treating them as one module (or “about to merge”) causes wrong imports and wrong reviews.

## Decision

Recorded in `docs/architecture/decision-r-pipe-1-pipeline-packages.md` and `backlog.md` (R-PIPE-1 **done**):

**Permanent documented split (Wave A freeze).** An optional later merge under M5-PIPE exit criteria is allowed only with shims + import-linter migration — it is **not** current product reality and must not be documented as completed.

## What each package is for

| Package | Path | Job |
| --- | --- | --- |
| `reveng.pipeline` | `src/reveng/pipeline/` | Stage engine + **step runners** used by the main analyzer CLI |
| `reveng.pipelines` | `src/reveng/pipelines/` | Opinionated multi-tool **workflow templates** (malware / .NET / triage-style automation) |

Package docstrings already state the split:

- `src/reveng/pipeline/__init__.py` — distinct from `reveng.pipelines`; points at M5-PIPE before any merge
- `src/reveng/pipelines/__init__.py` — intentional separation; forbids merge without an import-linter migration plan

### Typical contents

**`reveng.pipeline`**

- `pipeline_engine.py` — `AnalysisPipeline`, stage types / results
- `steps/` — step runners (e.g. vulnerability discovery, threat intelligence imported from `REVENGAnalyzer`)
- `e2e_integration.py` — `EndToEndPipelineRunner`

**`reveng.pipelines`**

- `automated_analysis.py` — `AutomatedAnalysisPipeline` and template types

Breadcrumbs: `src/reveng/pipeline/claude.md`, `src/reveng/pipelines/claude.md`.

## Regression gate

`tests/unit/test_pipeline_package_split.py` asserts the packages remain distinct (names, docstring cross-mentions, key exports). Do not weaken that test to “force” a merge.

## Import guidance for juniors

```text
Need a step the analyzer already calls?     → reveng.pipeline.steps / pipeline_engine
Need a high-level automated template?       → reveng.pipelines.AutomatedAnalysisPipeline
Unsure?                                     → read both __init__.py docstrings + R-PIPE-1 decision
```

`.importlinter` inventories `reveng.pipeline` among foundation-adjacent domains; a real merge would need a new contract plan, not a drive-by rename.

## Related

- Decision: `docs/architecture/decision-r-pipe-1-pipeline-packages.md`
- [Analysis pipeline](analysis-pipeline.md) (uses `reveng.pipeline.steps`)
- [Architecture overview](architecture-overview.md)
- Ops index: root `backlog.md`
