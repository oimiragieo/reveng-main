# How to: App reverse-engineer (JVM)

> **Maturity:** supported (`app_reverse_engineering` · language `jvm`)

## Goal

Recover sources/specs from a JVM input via the registered adapter and read the validation summary.

## Prerequisites

- Working `reveng` install — [Install and triage](../../tutorials/analyst/01-install-and-triage.md)
- Sample under `test_samples/` (or your own JVM artifact)

## Steps

1. Choose an input (repo example: `test_samples/HelloWorld.jar`).
2. Run:

```bash
reveng reverse-engineer-app test_samples/HelloWorld.jar --output-dir analysis_app_jvm
```

3. Open `analysis_app_jvm/` and locate recovered sources plus JSON/summary with **validation**, **evidence**, and **provenance**.
4. Map the grade using [Reading validation grades](../../support/reading-validation-grades.md) (App RE ladder).

## Input shapes

- `.jar` / `.class` / sometimes `.java` sources
- Obfuscated samples (e.g. `ObfuscatedExample.java`) exercise harder recovery

## What “good” looks like

- Class/method structure recovered into the output directory
- Validation grade on the App RE ladder with at least some evidence items
- Warnings about missing optional tools should be readable, not silent failures

## Failure modes

| Symptom | What to try |
| --- | --- |
| Language mis-detected | Pass explicit language if CLI exposes it (`reveng reverse-engineer-app --help`) |
| Empty recovery | Confirm input is actually JVM; check optional tool install notes above |
| Confusing grades | Re-read honesty rules — fixture ≠ capability |

## Related

- [First app reverse-engineer tutorial](../../tutorials/analyst/02-app-reverse-engineer.md)
- [App RE dispatch](../../explanation/app-re-dispatch.md)
- [Support matrix](../../support/support-matrix.md)
