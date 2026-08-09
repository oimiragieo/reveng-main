# How to: add an app reverse-engineering adapter

> **Maturity:** app RE path is **supported** for languages listed in the [support matrix](../../support/support-matrix.md) · a new adapter is **unsupported** until registered, tested, and (if claimed) matrix-updated
>
> Follow [honesty rules](../../support/honesty-rules.md): code that only exists in unit tests does not ship.

## Goal

Add a language adapter that the default framework can dispatch, returning an enriched `AppReverseEngineeringResult`.

## 1. Implement the `AppAdapter` protocol

Protocol: `src/reveng/app_reverse_engineering/framework.py`

Required surface:

- `language: str` — registry key (e.g. `"javascript"`)
- `supported_extensions: Sequence[str]`
- `adapter_name: str`
- `supports_path(self, path: Path) -> bool`
- `async def reverse_engineer(self, input_path, output_dir, **kwargs) -> AppReverseEngineeringResult`

Return type: `src/reveng/app_reverse_engineering/models.py` — `AppReverseEngineeringResult`.

Put the class under `src/reveng/app_reverse_engineering/adapters/<lang>.py`. Study existing adapters (`javascript.py`, `jvm.py`, `python.py`, `dotnet.py`) for SPECS / analysis.json layout conventions.

`NativeAppAdapter` (`adapters/native.py`) is a cautionary example: the class can exist **without** being product-supported if it is never registered ([App RE dispatch](../../explanation/app-re-dispatch.md)).

## 2. Register in `create_default_framework`

Edit `src/reveng/app_reverse_engineering/__init__.py`:

1. Import the new adapter.
2. Call `framework.register(YourAdapter())` inside `create_default_framework()`.
3. Export the class in `__all__` if it is part of the public adapter set.

Until this step lands, CLI / API / MCP paths that use `create_default_framework()` will never see your adapter.

## 3. Rely on enrich contracts (do not bypass)

`AppReverseEngineeringFramework.reverse_engineer` always runs `enrich_app_analysis_payload` then `rewrite_analysis_file` (`contracts.py`). Your adapter should populate metadata / artifacts the enricher expects (sources, topic files, warnings). Do not invent a parallel validation scheme — Ladder A grades come from `build_validation_summary` ([Reading validation grades](../../support/reading-validation-grades.md), [Result contracts](../../explanation/result-contracts.md)).

## 4. Tests

Add unit / corpus coverage under `tests/unit/` (patterns: `test_app_reverse_engineering.py`, language-specific adapter tests). At minimum:

- `supports_path` positive / negative
- `reverse_engineer` writes analysis artifacts
- Default framework registers the language key
- Enrichment produces `schema_version`, `validation`, `evidence`, `provenance`

Prefer `/usr/bin/python3.9` for local gates when matching CI honesty.

## 5. Support matrix — only if claiming support

If you will tell customers the language is supported:

1. Edit **`docs/support_matrix.json`** first (`app_reverse_engineering.languages`).
2. Mirror the change in **`docs/support/support-matrix.md`**.
3. Remember: release gates read the **JSON** ([Update support matrix](update-support-matrix.md)).

If you are only prototyping, leave the matrix alone and document the adapter as experimental / unregistered research.

## Checklist

- [ ] Protocol implemented under `adapters/`
- [ ] Registered in `create_default_framework()`
- [ ] Enrichment path exercised (not unit-only helper)
- [ ] Tests added
- [ ] Matrix JSON + Markdown updated **iff** claiming support
- [ ] No Ghidra requirement implied for managed languages ([Ghidra boundary](../../explanation/ghidra-boundary.md))

## Related

- Explanation: [App RE dispatch](../../explanation/app-re-dispatch.md)
- [Support matrix](../../support/support-matrix.md)
- [Maturity badges](../../support/maturity-badges.md)
