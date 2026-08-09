---
name: reveng-release-honesty
description: >-
  REVENG GA/release honesty rules from Scope C 2026-08 (waves 1–3 / Wave A).
  Use when verifying GA readiness, editing verify_ga_readiness, support matrix
  claims, capability reports, managed recompile, JS behavior grades, native
  fixtures / analyze probes, Sol/Fable plan-validate loops, backlog clearance
  waves, or writing CEO/release status.
---

# REVENG release honesty

## When this applies

Any change that touches release language, GA verifiers, tracked benchmark reports, validation grades, native fixture manifests, analyze timeout probes, backlog research rows, or “ship ready” claims.

## Non-negotiables

1. **Open the tracked report** — do not trust verifier pass alone. Confirm `analyze_report_exists`, status enums, and recompile/rebuild paths in `reports/*.json` / `.reveng/*.json`.
2. **No hollow gates** — if a check can pass with empty evidence, it is broken. Prefer TDD that fails on a known-empty fixture before trusting green.
3. **Wire product paths** — helpers that only exist in unit tests must be called from enrich/framework/CLI or they do not ship.
4. **Managed vs native** — `.pyc`/`.class`/`.jar`/app RE must not require Ghidra; native PE/ELF may.
5. **Fixture ≠ capability** — `test_samples/native/` proves CLI byte-stability only. Keep `required: false` / `fixture_only` until analyze is measured green.
6. **Probe status contract (v1.2)** — `completed` only for returncode 0; timeout measured; nonzero / `tool_absent` / `input_absent` / OSError → `could_not_measure` (exit 2). Process `completed` ≠ native GA (check semantic fields / DF-5).
7. **Evidence directory hygiene** — exactly one `20*.json` stamp byte-identical to `latest.json`; scrub orphans after merge; bump `probe_version` on semantic changes.
8. **Research honesty** — `tool_absent` / `input_absent` ≠ research done (do not close the question). Split BASELINE rows from engine rows (exact id match).
9. **Exploits stay experimental** — R-SEC-1 decision is Docker-only preview; no expansion without sandbox proofs; keep watermarks.
10. **Match claims to `support_matrix`** — preview vs GA language.
11. **Wave-scope plans** — do not plan “close all Scope C” in one PR; use Wave B exit criteria for engine work.

## Agent seating

- **Fable** = `claude -p --model claude-fable-5` (not Cursor Pro quota).
- **Sol** = `codex exec --model gpt-5.6-sol`. Prefer **inlined** audit packets when sandbox greps hang; put question files in the worktree (Windows-reachable), not only `/tmp`.
- Background seats: **alive ≠ working** — CPU + log growth.
- Git: `git -c user.name/email` from `git log -1`; named paths only; no stash across worktrees.

## Local dogfood

- Interpreter: `/usr/bin/python3.9`.
- GA: `python3.9 scripts/verify_ga_readiness.py --profile baseline` **and** `--profile ga` (open referenced JSON).
- Probe: `python3.9 scripts/probe_native_analyze_timeout.py --job reports/native_analyze_probe/wave_a_job.json` (or `--binary` legacy).
- Scoped status: `bash scripts/git_status_scoped.sh`.
- Ops index: root **`backlog.md`**.

## Canonical docs

- `docs/architecture/ceo-update-2026-08-08-tg-audit-merge.md` (latest CEO)
- `docs/architecture/ceo-update-2026-08-07-scope-c-charter.md` / `ceo-update-2026-08-06-wave3.md` (priors)
- `docs/architecture/lessons-learned-scope-c-2026-08.md` (**L1–L32**)
- `docs/architecture/wave-b-exit-criteria.md` / `wave-c-exit-criteria.md`
- Root `backlog.md`
- Junior docs home: `docs/README.md` (Analyst + Engineer tracks); support badges: `docs/support/`

## CI honesty install (L28)

Wave B / Phase 5 workflows must use `requirements-honesty.txt` + `pip install -e . --no-deps`.
Do **not** `pip install -r requirements.txt` in those jobs — py3.9 hits `resolution-too-deep`.

## Fake pins (L29)

Never restore `ghidramcp>=0.1.0` in requirements-java/security without a real PyPI package.
