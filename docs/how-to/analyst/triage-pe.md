# How to: Triage a PE (or other binary) with the CLI

> **Maturity:** supported (`cli_triage`) · preview (product overall)
>
> Deep native decompile / native recompile remains **limited** and Ghidra-backed — not GA-equivalent. Prefer [app reverse-engineer](../../tutorials/analyst/02-app-reverse-engineer.md) for managed-language apps.

## Goal

Produce a first-pass triage (and optional analyze) for an unknown Windows PE or similar binary without claiming reconstruction or exploit GA.

## Prerequisites

- Install + `reveng --help` — [Install and triage](../../tutorials/analyst/01-install-and-triage.md)
- A sample you are authorized to analyze (in-repo smoke: `test_samples/sample.exe` when present)
- Optional: Ghidra Analysis Server only if you escalate beyond triage — [When Ghidra is required](when-ghidra-is-required.md)

## Steps

1. Confirm the CLI:

```bash
reveng triage --help
```

2. Run instant triage:

```bash
reveng triage path/to/suspicious.exe --format markdown
```

Formats: `text` (default), `json`, `markdown`.

3. Bulk triage when needed:

```bash
reveng triage path/to/one.exe --bulk a.exe b.exe --format json
```

4. Optional deeper analyze (still not native recompile GA):

```bash
reveng analyze path/to/suspicious.exe --output-dir analysis_suspicious
```

5. If the PE is Bun-packed, analyze may route to Bun extraction — see [Bun executable](bun-executable.md).

## Expected outputs

| Step | What you get |
| --- | --- |
| `triage` | Narrative / indicators / structured report for IR first pass |
| `analyze` | Files under `analysis_<name>/` or `--output-dir` |
| Bun route | `bun_analysis.json`, recovered bundle / bunfs when detected |

Read reports on disk; exit code alone is not a capability claim — [Reading outputs](../../tutorials/analyst/03-reading-outputs.md).

## Failure modes

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `reveng` not found | PATH / no editable install | `python -m reveng` or finish install |
| Binary not found | Wrong path | Resolve absolute path; check CWD |
| Thin native decompile | No Ghidra server | [When Ghidra is required](when-ghidra-is-required.md) |
| AI sections skipped | No Ollama/API | Fine for basic triage |
| Overclaim from exit 0 | Hollow success (**DF-5**) | Open evidence; check matrix |

## Related

- [Support matrix](../../support/support-matrix.md)
- [Honesty rules](../../support/honesty-rules.md)
- [YARA and VirusTotal](yara-and-vt.md)
- [CLI reference](../../reference/cli.md)
