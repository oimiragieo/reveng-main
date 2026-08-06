# Lessons learned — Scope C wave (2026-08-06)

Durable agent/operator rules from the GA honesty + managed recompile + JS behavior campaign. **Do not re-derive these the hard way.**

## L1 — Green gate ≠ real evidence

A verifier that only checks weak predicates (`source_count >= 1`, counting failures as “breadth”) can **pass while tracked reports show 0 analyze artifacts**. Always open the tracked JSON and assert the field you care about (`analyze_report_exists`, status enum, rebuilt paths).

## L2 — Wire the product path, not just the unit

`build_capability_report` had tests and docs but was **never called from** `enrich_app_analysis_payload`. Orphan helpers look “done” in coverage and still change nothing customers see. Prefer a wiring test through enrich/framework.

## L3 — Managed languages must not require Ghidra

Spinning `GhidraEngine(fail_fast=True)` for `.pyc` / `.class` / `.jar` turns a working adapter path into a hard fail. Branch on input class first; native PE/ELF can keep Ghidra.

## L4 — REVENGLogger is not logging.Logger

`warning(msg, *args)` with `%s` **TypeError**s (`takes 2 positional arguments but N were given`). That shows up as “Behavioral monitoring failed” even when the real bug is the logger. Prefer stdlib-compatible `*args` on wrapper loggers, or only use f-strings.

## L5 — Python 3.9 is the dogfood interpreter here

Broken host `python3.13` (missing stdlib pieces) and 3.9 traps (`int | None` without `from __future__ import annotations`; f-string backslash in expressions) will block **all** app RE imports. Gate with `/usr/bin/python3.9`.

## L6 — Conftest must not import the universe

Eager imports of volatility3 / sklearn / malware stacks break focused unit collection. Lazy-import inside fixtures (or mark heavy suites). Do not teach agents `--noconftest` as the permanent fix.

## L7 — Git status on DrvFS + `reports/` will hang

Full-tree `git status` / `git diff --stat` over huge generated trees stalls WSL. Stage **named paths only**; never chain commit scripts behind a repo-wide status dump.

## L8 — Docs rot the day status changes

Execution backlog still claimed `analyze_ok_recompile_failed` after managed recompile shipped. When a gate flips, **update the tracked-evidence prose in the same change** (or the next PR is lying).

## L9 — Argparse flag order is load-bearing

Parent + subcommand both defining `--output-dir` can drop the value depending on global-before vs after-subcommand argv. Benchmark runners need **subcommand-specific** argv shapes; add a regression test.

## L10 — Scope C ≠ skip honesty

Thinktank recommended narrow Scope B; CEO chose full Scope C. Still execute **honesty / security first** (Phases 1–2), then the long roadmap. Do not market GA from preview gates alone.

## L11 — Bidirectional oracles on grades

Grade promotion (behavior tier → `evidence_backed`) must have tests that **refuse** promotion on tier 1 / missing syntax / packaging_only. A one-arm “happy path” green is a hollow gate (see L1).
