# How to: App reverse-engineer (Python)

> **Maturity:** supported (`app_reverse_engineering` · language `python`)

## Goal

Recover sources/specs from a Python input via the registered adapter and read the validation summary.

## Prerequisites

- Working `reveng` install — [Install and triage](../../tutorials/analyst/01-install-and-triage.md)
- Sample under `test_samples/` (or your own Python artifact)

## Steps

1. Choose an input (repo example: `test_samples/sample_app.pyc`).
2. Run:

```bash
reveng reverse-engineer-app test_samples/sample_app.pyc --output-dir analysis_app_python
```

3. Open `analysis_app_python/` and locate recovered sources plus JSON/summary with **validation**, **evidence**, and **provenance**.
4. Map the grade using [Reading validation grades](../../support/reading-validation-grades.md) (App RE ladder).

## Input shapes

- `.py` source, `.pyc` bytecode, `.pyz` archives (`sample_app.pyz`)
- Optional `pyi-archive_viewer` improves some packaged shapes when installed

## What “good” looks like

- Recovered modules / SPECS-like artifacts under `--output-dir`
- Grade + evidence fields present in the analysis payload
- Do not confuse bytecode recovery with native PE GA

## Failure modes

| Symptom | What to try |
| --- | --- |
| Language mis-detected | Pass explicit language if CLI exposes it (`reveng reverse-engineer-app --help`) |
| Empty recovery | Confirm input is actually Python; check optional tool install notes above |
| Confusing grades | Re-read honesty rules — fixture ≠ capability |

## Related

- [First app reverse-engineer tutorial](../../tutorials/analyst/02-app-reverse-engineer.md)
- [App RE dispatch](../../explanation/app-re-dispatch.md)
- [Support matrix](../../support/support-matrix.md)
