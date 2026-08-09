# Tutorial: Install and triage

> **Maturity:** supported (`cli_triage`) · preview (product overall)
>
> Trust: core triage / analyze without advanced reconstruction. Native PE/ELF **recompile** is **not** GA — see [Support matrix](../../support/support-matrix.md).

## What you will learn

- Install REVENG from source on Python 3.9+
- Verify the CLI entry points
- Run a first `triage` / `analyze` and know what that does *not* prove

## Prerequisites

- Git
- Python `>=3.9` (prefer `/usr/bin/python3.9` on this repo’s dogfood hosts)
- Optional later: Ollama / cloud API keys for AI helpers (not required for basic triage)

## Install from source (analyst path)

From a clone of the repo:

```bash
cd reveng-main
python3.9 -m pip install -r requirements.txt
python3.9 -m pip install -e .
```

That gives you the `reveng` console script (entry: `reveng.cli:main`). There is **no** repo-root `reveng.py` launcher — it was removed so it would not shadow the package.

### Contributors / full toolchain

If you will run tests, lint, or Java-related deps, prefer the contributor install:

```bash
make install-dev
python3.9 -m pip install -e . --no-deps
```

Details: [Engineer: Dev setup](../engineer/01-dev-setup.md). Honesty CI must **not** blindly install full `requirements.txt` — see that tutorial and [Honesty rules](../../support/honesty-rules.md).

## Verify the CLI

```bash
reveng --help
python -m reveng --help
```

If `reveng` is missing from `PATH`, use `python -m reveng` (or set `PYTHONPATH=src` when running from a source tree without the editable install).

You should see commands such as `analyze`, `triage`, and `reverse-engineer-app`. Skim `reveng triage --help` and `reveng analyze --help` once.

## First triage

Use any local sample you are allowed to analyze. In-repo PE for smoke (when present):

```bash
reveng triage test_samples/sample.exe --format markdown
```

Formats: `text` (default), `json`, `markdown`. Bulk:

```bash
reveng triage dummy.exe --bulk sample1.exe sample2.exe --format json
```

## First analyze

```bash
reveng analyze test_samples/sample.exe
# optional explicit output folder (global flag):
reveng analyze test_samples/sample.exe --output-dir analysis_sample_triage
```

Results typically land under `analysis_<stem>/` in the working directory. Open the reports there; do not stop at “exit code 0”.

## Prefer app RE for managed languages

For JavaScript, JVM, Python, or .NET **applications**, the supported GA-oriented path is **`reverse-engineer-app`**, not a native Ghidra loop:

→ [Tutorial: First app reverse-engineer](02-app-reverse-engineer.md)

## What this does *not* prove

| Claim | Reality |
| --- | --- |
| Triage finished | Supported first-pass workflow — not reconstruction quality |
| Analyze wrote files | Artifacts exist; native deep decompile may still need Ghidra (**limited**) |
| Process `completed` / exit 0 | Not native analyze GA (**DF-5**) — [Honesty rules](../../support/honesty-rules.md) |
| `generate-exploit` exists | **EXPERIMENTAL / non-GA** — watermarked in the CLI; not a customer-safe workflow |

## Maturity badges refresher

See [Maturity badges](../../support/maturity-badges.md). Match language to [`docs/support_matrix.json`](../../support_matrix.json).

## Next

1. [First app reverse-engineer](02-app-reverse-engineer.md)
2. [Reading outputs](03-reading-outputs.md)
3. How-to: [Triage a PE](../../how-to/analyst/triage-pe.md)
