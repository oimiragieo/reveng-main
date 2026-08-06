---
name: reveng-release-honesty
description: >-
  REVENG GA/release honesty rules from Scope C 2026-08. Use when verifying GA
  readiness, editing verify_ga_readiness, support matrix claims, capability
  reports, managed recompile, JS behavior grades, or writing CEO/release status.
---

# REVENG release honesty

## When this applies

Any change that touches release language, GA verifiers, tracked benchmark reports, validation grades, or “ship ready” claims.

## Non-negotiables

1. **Open the tracked report** — do not trust verifier pass alone. Confirm `analyze_report_exists`, status enums, and recompile/rebuild paths in `reports/*.json` / `.reveng/*.json`.
2. **No hollow gates** — if a check can pass with empty evidence, it is broken. Prefer TDD that fails on a known-empty fixture before trusting green.
3. **Wire product paths** — helpers that only exist in unit tests (e.g. capability report builders) must be called from enrich/framework/CLI or they do not ship.
4. **Managed vs native** — `.pyc`/`.class`/`.jar`/app RE must not require Ghidra; native PE/ELF may.
5. **Exploits stay experimental** until SEC-1 sandbox research lands; keep watermarks.
6. **Match claims to `support_matrix`** — preview vs GA language.

## Local dogfood

- Interpreter: prefer `/usr/bin/python3.9` on this WSL host (3.13 may be broken).
- GA: `python3.9 scripts/verify_ga_readiness.py --profile ga`
- Avoid full-repo `git status` when `reports/` is dirty; stage named paths only.

## Logger trap

`REVENGLogger` accepts printf `*args` (fixed 2026-08). If you see `warning() takes 2 positional arguments`, check for a custom logger missing `*args` before blaming the monitor.

## Canonical docs

- `docs/architecture/ceo-update-2026-08-06.md`
- `docs/architecture/lessons-learned-scope-c-2026-08.md`
- Root `backlog.md`
- `docs/architecture/reveng-ga-master-plan.md`
