# How to: App reverse-engineer (JavaScript)

> **Maturity:** supported (`app_reverse_engineering` · language `javascript`)
>
> Adapter: `javascript_bundle_workflow` (`JavaScriptAppAdapter`). Trust SPECS + `analysis.json` validation/evidence — not invented recovery %. Optional deobfuscators improve quality when present.

## Goal

Recover a SPECS library and JS project artifacts from a `.js` / `.cjs` / `.mjs` bundle (or similar entry) via `reverse-engineer-app`.

## Prerequisites

- Working CLI — [Install and triage](../../tutorials/analyst/01-install-and-triage.md)
- Input with a supported suffix (adapter: `.js`, `.cjs`, `.mjs`)
- Optional: deeper deobfuscation tooling if you pass `--run-deobfuscator` (quality varies)
- Sample for practice: `test_samples/sample_bundle.js` (also `js_tracked_bundle_artifact/`, `sample_tsx_cli.tsx` is TSX — prefer `.js` fixtures for this adapter)

## Steps

1. Run app RE (auto or explicit language):

```bash
reveng reverse-engineer-app test_samples/sample_bundle.js \
  --language javascript \
  --output-dir analysis_app_javascript
```

2. Optional inventory root / noise filters:

```bash
reveng reverse-engineer-app path/to/bundle.js \
  --language javascript \
  --input-root path/to/project \
  --skip-pattern sentry \
  --skip-pattern source-map \
  --max-snippets 12 \
  --output-dir analysis_app_javascript
```

3. Optional deobfuscation attempt:

```bash
reveng reverse-engineer-app path/to/obfuscated.js \
  --language javascript \
  --run-deobfuscator \
  --output-dir analysis_app_javascript_deob
```

4. Or via `reveng-app`:

```bash
reveng-app reverse-engineer test_samples/sample_bundle.js \
  -o analysis_app_javascript \
  --language javascript
```

5. Open grades with the App RE ladder: [Reading validation grades](../../support/reading-validation-grades.md).

## Expected outputs

| Path | Role |
| --- | --- |
| `SPECS/` | Topic markdown (structure, deps, IO, …) |
| `analysis.json` | `validation`, `evidence`, `provenance`, often `capability_report` |
| `project/` | Recovered JS tree when the workflow writes one (grade promotion may use syntax/behavior probes) |

Console prints language, adapter name, specs root, source count, and validation grade.

JS-specific note: some `partial_recovery` / `structure_only` results can **promote** toward `evidence_backed` when behavior probes pass (tier ≥ 2 + syntax ok). Still open evidence — promotion is not a blank check.

## Failure modes

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Wrong adapter / auto miss | Unsupported suffix (e.g. only `.tsx`) | Emit/use a `.js` artifact or convert; check `--language` |
| `packaging_only` / weak grade | Minified bundle, no map, heavy noise | Adjust `--skip-pattern`; try `--run-deobfuscator`; supply `--input-root` |
| Confusing App RE with Bun PE path | Input is a Bun `.exe` | [Bun executable](bun-executable.md) first, then app RE on recovered JS |
| Treating fixture grade as customer GA | Fixture ≠ capability | [Honesty rules](../../support/honesty-rules.md) |

## Related

- [First app reverse-engineer](../../tutorials/analyst/02-app-reverse-engineer.md)
- [App RE dispatch](../../explanation/app-re-dispatch.md)
- [Support matrix](../../support/support-matrix.md)
- [Bun executable](bun-executable.md)
