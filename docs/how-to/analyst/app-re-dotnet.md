# How to: App reverse-engineer (.NET)

> **Maturity:** supported (`app_reverse_engineering` · language `dotnet`)

## Goal

Recover sources/specs from a .NET input via the registered adapter and read the validation summary.

## Prerequisites

- Working `reveng` install — [Install and triage](../../tutorials/analyst/01-install-and-triage.md)
- Sample under `test_samples/` (or your own .NET artifact)

## Steps

1. Choose an input (repo example: `test_samples/sample_dotnet.dll`).
2. Run:

```bash
reveng reverse-engineer-app test_samples/sample_dotnet.dll --output-dir analysis_app_dotnet
```

3. Open `analysis_app_dotnet/` and locate recovered sources plus JSON/summary with **validation**, **evidence**, and **provenance**.
4. Map the grade using [Reading validation grades](../../support/reading-validation-grades.md) (App RE ladder).

## Input shapes

- `.dll` / `.exe` managed assemblies
- Optional `ilspycmd` improves decompilation quality when on PATH

## What “good” looks like

- Decompiled C# / IL-backed sources in the output tree
- Validation summary with evidence; note tool-absent warnings honestly
- Still App RE ladder — not VRL `behavior_matched`

## Failure modes

| Symptom | What to try |
| --- | --- |
| Language mis-detected | Pass explicit language if CLI exposes it (`reveng reverse-engineer-app --help`) |
| Empty recovery | Confirm input is actually .NET; check optional tool install notes above |
| Confusing grades | Re-read honesty rules — fixture ≠ capability |

## Related

- [First app reverse-engineer tutorial](../../tutorials/analyst/02-app-reverse-engineer.md)
- [App RE dispatch](../../explanation/app-re-dispatch.md)
- [Support matrix](../../support/support-matrix.md)
