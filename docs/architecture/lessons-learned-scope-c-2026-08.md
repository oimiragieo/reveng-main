# Lessons learned — Scope C wave (2026-08-06)

Durable agent/operator rules from the GA honesty + managed recompile + JS behavior + native-fixtures campaign. **Do not re-derive these the hard way.**

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

## L12 — A fixture that builds is not a capability that works

Native micro-CLIs under `test_samples/native/` prove **byte-stable CLI surfaces**, not that REVENG analyzes them. Manifest entries stay `required: false` / `status: fixture_only` with a `status_note` naming the gap; a unit test forbids flipping status to `ga`/`verified`/`supported` without evidence. Measured analyze outcomes live only in `reports/native_analyze_probe/`.

## L13 — Nonzero exit is not `completed`

A three-valued probe (`completed` / `timeout` / `could_not_measure`) must map **returncode ≠ 0** to `could_not_measure` with `reason: nonzero_exit:<code>`, never to `completed`. Exit **2** on any `could_not_measure`; exit **0** on measured `timeout`. Process-level tests (real OS returncodes) beat catching `SystemExit` in-process alone. Bump `probe_version` when semantics change (v1.0 → v1.1).

## L14 — Regenerating `latest.json` does not scrub dishonest siblings

Every file retained under a tracked evidence directory must satisfy the same invariants as `latest.json`. Synthetic `true`-command runs and pre-fix stamps that contradict the status contract must be **deleted or quarantined**, not left beside a fixed pointer. Prefer a short README stating what is allowed in the folder.

## L15 — Cursor Pro quota is not Fable (and Auto is not Fable)

Fable is reached via **`claude -p --model claude-fable-5`** (or thinktank seat 1). Sol via **`codex exec --model gpt-5.6-sol`**. Cursor Task “premium” seats failing on Pro limits are a different product — do not report “Fable unavailable” because Cursor quota reset. Prefer CLI seats for plan/validate when the IDE router is exhausted.

## L16 — Alive ≠ working

A background implementer with a live PID, **~0 CPU**, and a **0-byte log** is stuck, not “buffering.” Measure CPU delta + log growth within ~1–2 minutes; run a tiny positive control. Kill and continue in-session rather than waiting on a silent seat.

## L17 — Inline evidence for Sol when the sandbox blocks greps

`codex exec --sandbox read-only` on this host may reject PowerShell `Select-String` / path probes (`blocked by policy`) and hang. For re-audits, **paste the file contents into the prompt** and instruct Sol not to shell. A hung validator is not a REJECT.

## L18 — Host C linker may be broken; Go still works; skips must be loud

This WSL host’s `cc`/`clang` can fail linking (`libc.so.6` / `.relr.dyn`). That is **environment**, not a missing fixture. Prefer `CGO_ENABLED=0 go build` for hermetic Go toys. Absent/broken toolchain → actionable skip marker (`NATIVE_FIXTURE_SKIPPED: …`); present toolchain → **no** marker (two-arm test). Plan paths saying `docs/BACKLOG.md` mean root **`backlog.md`**.

## L19 — “Close all backlog” is not one plan

A Superpowers plan that claims to finish Scope C phases 4–13, RALPH-2 engine, and native GA in one wave will (and should) be **REJECT**ed by Thinktank/Sol. Scope Wave A as honesty/ops/research-*decisions* + measurement; put engine work behind **Wave B exit criteria** with concrete close conditions.

## L20 — `tool_absent` is blocked, not done

Recording `tool_absent:hexyl` proves the instrument was missing. It does **not** answer “is hexyl still timeout-only?” Keep **R-HEX-1** as `blocked` until a real timed run on an obtained binary. Never mark research `done` from absence alone.

## L21 — Split baseline research from product rows

When a research question asks for both a measurement *and* a design wedge, close a **BASELINE** row (or `could_not_measure` with reason) separately. Keep the product/engine id (`R-RALPH-2`, `RALPH-2`) **open** until the wedge is chosen and implemented. Exact-id matching in tests — substring match will confuse `R-RALPH-2` with `R-RALPH-2-BASELINE`.

## L22 — Process `completed` ≠ native capability (DF-5)

`reveng analyze` / probe `status: completed` (exit 0) can still be CLI `partial_success` with empty native fallback / no useful rebuild. Always carry semantic fields (`analysis_report_present`, `native_fallback_empty`, `semantic_reason`) and say so in CEO/backlog language. Do not flip `required: true` from process green alone.

## L23 — Evidence hygiene must survive merge

Merging a clean worktree onto a dirty `main` can resurrect stale `20*.json` stamps beside `latest.json`. Post-merge: assert exactly one stamp, byte-identical to `latest.json`, before calling Wave A green. Prefer explicit paths over `git add reports/**/*.json` globs.

## L24 — Plan/validate seats need reachable paths and git identity

- Put thinktank question packs under the **worktree** (Windows-reachable), not only Linux `/tmp`, or Fable returns CANNOT_READ.
- Sol: prefer **fully inlined** evidence packets (“do not shell”) when sandbox greps hang.
- Merges/commits on this host need `git -c user.name=… -c user.email=…` from `git log -1` — empty ident aborts with exit 128.
- Do **not** `git stash` with live `.worktrees/`; discard or commit named paths instead.
