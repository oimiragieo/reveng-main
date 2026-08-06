---
name: reveng-release-honesty
description: >-
  REVENG GA/release honesty rules from Scope C 2026-08 (waves 1–2). Use when
  verifying GA readiness, editing verify_ga_readiness, support matrix claims,
  capability reports, managed recompile, JS behavior grades, native fixtures /
  analyze probes, Sol/Fable plan-validate loops, or writing CEO/release status.
---

# REVENG release honesty

## When this applies

Any change that touches release language, GA verifiers, tracked benchmark reports, validation grades, native fixture manifests, analyze timeout probes, or “ship ready” claims.

## Non-negotiables

1. **Open the tracked report** — do not trust verifier pass alone. Confirm `analyze_report_exists`, status enums, and recompile/rebuild paths in `reports/*.json` / `.reveng/*.json`.
2. **No hollow gates** — if a check can pass with empty evidence, it is broken. Prefer TDD that fails on a known-empty fixture before trusting green.
3. **Wire product paths** — helpers that only exist in unit tests (e.g. capability report builders) must be called from enrich/framework/CLI or they do not ship.
4. **Managed vs native** — `.pyc`/`.class`/`.jar`/app RE must not require Ghidra; native PE/ELF may.
5. **Fixture ≠ capability** — `test_samples/native/` micro-CLIs prove CLI byte-stability only. Manifest stays `required: false` / `fixture_only` until analyze is measured green.
6. **Probe status contract** — `completed` only for returncode 0; timeout is measured; nonzero / absent / OSError → `could_not_measure` (exit 2). Never label nonzero as `completed`.
7. **Evidence directory hygiene** — every retained stamp under `reports/native_analyze_probe/` must match the contract; delete synthetic/`true` and pre-fix lying stamps; bump `probe_version` on semantic changes.
8. **Exploits stay experimental** until SEC-1 sandbox research lands; keep watermarks.
9. **Match claims to `support_matrix`** — preview vs GA language.

## Agent seating (wave 2)

- **Fable** = `claude -p --model claude-fable-5` (not Cursor Pro quota, not `agent --model auto`).
- **Sol** = `codex exec --model gpt-5.6-sol`. If read-only sandbox blocks PowerShell greps, **inline file contents** in the audit prompt.
- Background seats: **alive ≠ working** — check CPU + log growth; kill silent 0-byte-log agents.

## Local dogfood

- Interpreter: prefer `/usr/bin/python3.9` on this WSL host (3.13 may be broken).
- GA: `python3.9 scripts/verify_ga_readiness.py --profile ga`
- Native probe: `python3.9 scripts/probe_native_analyze_timeout.py --binary <elf> --timeout-s 120 --analyze-cmd "/usr/bin/python3.9 -m reveng analyze"`
- C linker may be broken here; Go fixtures use `CGO_ENABLED=0`. Skips must emit `NATIVE_FIXTURE_SKIPPED:`.
- Avoid full-repo `git status` when `reports/` is dirty; stage named paths only.
- Ops index is root **`backlog.md`**, not `docs/BACKLOG.md`.

## Logger trap

`REVENGLogger` accepts printf `*args` (fixed 2026-08). If you see `warning() takes 2 positional arguments`, check for a custom logger missing `*args` before blaming the monitor.

## Canonical docs

- `docs/architecture/ceo-update-2026-08-06-wave2.md` (latest CEO)
- `docs/architecture/ceo-update-2026-08-06.md` (wave 1)
- `docs/architecture/lessons-learned-scope-c-2026-08.md` (L1–L18)
- Root `backlog.md`
- `docs/architecture/reveng-ga-master-plan.md`
