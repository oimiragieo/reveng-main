# Tutorial: Reading outputs and trusting grades

> **Maturity:** preview (product) · reading skill is **required** for every workflow
>
> Trust: open JSON fields and SPECS/files on disk. Never invent success percentages. Fixture samples ≠ capability — [Honesty rules](../../support/honesty-rules.md).

## Goal

Learn how to navigate `analysis_*` directories, interpret App RE validation grades, and avoid common junior overclaims (especially around native fixtures and process exit codes).

## Prerequisites

- Completed [Install and triage](01-install-and-triage.md)
- Ideally completed [First app reverse-engineer](02-app-reverse-engineer.md) so you have a real `analysis_*` tree

## The folder you get

Most CLI flows write under `analysis_<stem>/` or a path you pass with `--output-dir`.

| Flow | Typical tree |
| --- | --- |
| `reverse-engineer-app` | `SPECS/`, `analysis.json`, recovered `project/` or `artifacts/` |
| `analyze` / Bun-aware PE | Reports, optional `bun_analysis.json`, recovered bundle / bunfs |
| `triage` | Console / file report depending on `--format` (may not create a full SPECS library) |

Generated trees under `analysis_*` and `reports/` are **outputs**, not source to edit or commit casually.

## Fields that matter (app RE)

Open `analysis.json` after app RE. Look for:

| Field | Why it matters |
| --- | --- |
| `schema_version` / `result_type` | Confirms you are reading a versioned app result contract |
| `validation` / grade | Summary strength — not a proof by itself |
| `evidence` | Paths and crumbs you can verify on disk |
| `provenance` | Adapter, language, input/output roots |
| `capability_report` | Extra capability probes (especially JS syntax/behavior) |
| `warnings` | Missing tools, weak recovery, reconstruction limits |

SPECS markdown (`SPECS/*.md`, `SPECS/domains/*.md`) is the human companion to those topic matches.

## Two grade ladders (do not mix)

| Ladder | Used by | Example grades |
| --- | --- | --- |
| **A — App reverse engineering** | `reverse-engineer-app` | `evidence_backed`, `partial_recovery`, `structure_only`, `packaging_only` |
| **B — VRL** | Verified Recompilation Loop / verification models | climb toward `behavior_matched`, `source_reconstruction_match`, … |

Full tables: [Reading validation grades](../../support/reading-validation-grades.md).

**Rule of thumb:** if you ran `reverse-engineer-app`, you are on ladder A. A strong App RE grade does **not** mean native PE recompile is GA.

## Fixture ≠ capability

| What you saw | What it means | What it does **not** mean |
| --- | --- | --- |
| `test_samples/sample_bundle.js` reverse-engineered cleanly | Adapter path works on that fixture | Your customer malware sample will get the same grade |
| Files under `test_samples/native/` | CLI micro-fixtures for measuring analyze | Native analyze GA — see `test_samples/native/README.md` |
| Probe / process `completed` or exit `0` | Process finished | Semantic native success (**DF-5**) |
| Hermetic bench “completed_without_behavior_checks” | Narrow tracked evidence | Full behavior equivalence |

Badge vocabulary: [Maturity badges](../../support/maturity-badges.md) (`fixture_only`, `limited`, `experimental`, …).

## Practice exercise

1. Run app RE on `test_samples/sample_app.py` → `--output-dir analysis_read_outputs`.
2. Open `analysis_read_outputs/analysis.json`.
3. Write down: language, adapter, validation grade, and one evidence path you opened.
4. Say whether that grade is ladder A or B.
5. Optional: open `SPECS/` and skim one topic file — does it match the evidence item?

## Failure modes while reading

| Mistake | Fix |
| --- | --- |
| Treating CLI “SUCCESS” as GA | Open validation + evidence |
| Quoting VRL grades for app RE (or vice versa) | Use [Reading validation grades](../../support/reading-validation-grades.md) |
| Claiming native recompile from managed SPECS | Managed recompile ≠ Ghidra-backed native — [Support matrix](../../support/support-matrix.md) |
| Ignoring warnings | Missing optional tools often explain weak grades |

## Related

- [Honesty rules](../../support/honesty-rules.md)
- [Support matrix](../../support/support-matrix.md)
- [Result contracts](../../explanation/result-contracts.md)
- [When Ghidra is required](../../how-to/analyst/when-ghidra-is-required.md)
