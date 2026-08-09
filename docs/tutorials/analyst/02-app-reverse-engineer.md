# Tutorial: First app reverse-engineer

> **Maturity:** supported (`app_reverse_engineering`) · preview (product overall)
>
> Trust: adapter outputs + `validation` / `evidence` / `provenance` in `analysis.json`. This is the preferred junior-friendly **GA path** for managed languages (JS / JVM / Python / .NET). Do **not** treat native PE recompile as GA.

## Goal

Run `reveng reverse-engineer-app` on a tracked `test_samples/` input, then open SPECS, `analysis.json`, and the validation grade with the right ladder in mind.

## Prerequisites

- Working install from [Install and triage](01-install-and-triage.md) (`reveng --help` works)
- Optional language tools improve quality but are not always required:
  - Python frozen apps: `pyi-archive_viewer` on `PATH`
  - .NET: `ildasm` / ILSpy (`ilspycmd`) when available
  - JVM: JDK tools help reconstruction; adapters still produce SPECS without a full IDE

## Pick a sample

From the repo root:

| Language | CLI `--language` | Example path |
| --- | --- | --- |
| JavaScript | `javascript` | `test_samples/sample_bundle.js` |
| Python | `python` | `test_samples/sample_app.py` (also `.pyc` / `.pyz`) |
| JVM | `jvm` | `test_samples/HelloWorld.jar` (also `.java` / `.class`) |
| .NET | `dotnet` | `test_samples/sample_dotnet.dll` |

Default language is `auto` (suffix / detector based). Native PE/ELF is **not** the default app-RE registry path — use triage/analyze (+ Ghidra when needed) for natives.

## Run (recommended CLI)

```bash
cd reveng-main

reveng reverse-engineer-app test_samples/sample_bundle.js \
  --language javascript \
  --output-dir analysis_app_js
```

Useful flags (see `reveng reverse-engineer-app --help`):

| Flag | Role |
| --- | --- |
| `--language` | `auto` \| `javascript` \| `jvm` \| `python` \| `dotnet` |
| `--input-root` | Directory to inventory (defaults near the input) |
| `--skip-pattern` | Repeatable; exclude noisy excerpt matches |
| `--max-snippets` / `--snippet-context` | SPECS excerpt budget |
| `--run-deobfuscator` | Deeper deobfuscation when the adapter supports it (JS) |
| `--output-dir` | Global option; default is `analysis_<stem>` |

### Alternate entry: `reveng-app`

The dedicated console script uses a **subcommand** and **requires** `-o`:

```bash
reveng-app reverse-engineer test_samples/sample_bundle.js \
  -o analysis_app_js \
  --language javascript
```

## What success looks like on the console

You should see something like:

- `Language:` / `Adapter:` (e.g. `javascript` / `javascript_bundle_workflow`)
- `Specs root:` … `/SPECS`
- `Analysis summary:` … `/analysis.json`
- `Recovered source files:` count
- `Validation:` an App RE grade (`evidence_backed`, `partial_recovery`, `structure_only`, or `packaging_only`)
- Optional `Warnings:` (missing optional tools, weak recovery, etc.)

Exit code `0` means the framework finished — still **open the evidence**.

## High-level output layout

Under `--output-dir` (adapter-dependent, but shared contract):

```text
analysis_app_js/
  SPECS/                 # topic markdown library + domains/
  analysis.json          # machine summary + validation + evidence + provenance
  artifacts/             # or project/ for JS recovered tree — adapter-specific
  ...
```

| Artifact | Plain meaning |
| --- | --- |
| **SPECS/** | Human-readable topic specs (structure, entrypoints, IO, …) built from keyword/excerpt evidence |
| **analysis.json** | Canonical machine payload: `result_type`, `schema_version`, `validation`, `evidence`, `provenance`, often `capability_report` |
| **validation** | Grade + summary — App RE ladder only |
| **evidence** | Concrete items (paths, counts, traces) backing that grade |
| **provenance** | Language, adapter name, input/output paths, topic/artifact maps |

Read grades carefully: [Reading validation grades](../../support/reading-validation-grades.md).

## Trust checklist

1. You are on the **App RE** grade ladder, not the VRL ladder.
2. At least one `evidence` item matches files you can open under the output dir.
3. Warnings about missing `pyi-archive_viewer` / ILSpy mean **optional tooling**, not “app RE unsupported”.
4. A green run on `test_samples/` is a **fixture exercise** for that language adapter — it is not a production % claim and not native recompile GA.

## Next

- [Reading outputs](03-reading-outputs.md)
- Language how-tos: [JS](../../how-to/analyst/app-re-javascript.md) · [JVM](../../how-to/analyst/app-re-jvm.md) · [Python](../../how-to/analyst/app-re-python.md) · [.NET](../../how-to/analyst/app-re-dotnet.md)
- [Support matrix](../../support/support-matrix.md) · [App RE dispatch](../../explanation/app-re-dispatch.md)
