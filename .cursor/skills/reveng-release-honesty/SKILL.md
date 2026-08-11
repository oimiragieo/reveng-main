---
name: reveng-release-honesty
description: >-
  REVENG GA/release honesty rules from Scope C 2026-08 (Waves 0–2 honesty
  closeout merged; Waves 3–10 JS recovery climb in progress; R-RALPH-2 open).
  Use when verifying GA readiness, editing verify_ga_readiness, support matrix
  claims, capability reports, managed recompile, JS behavior grades, native
  fixtures / analyze probes, Sol/Fable plan-validate loops, backlog clearance
  waves, JS recovery Option C metrics, or writing CEO/release status.
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
11. **Wave-scope plans** — do not plan “close all Scope C” in one PR (L33); use Wave B exit criteria for engine work. Disposition ≠ shipped (L34). Soft-fail ≠ done (L42). MCP hints = explicit denylist (L45).
12. **JS recovery Option C** — unlockable/survivor coverage is the ship bar (1.0); `oracle_coverage` is aspirational; report BOTH (+ recoverable when tombstones run). Hermetic fixtures ≠ Claude dogfood. Operator receipts under `/mnt/c/tmp/reveng_w*` never commit. See `reveng-js-recovery-climb`.

## Agent seating

- **Fable** = `claude -p --model claude-fable-5` (not Cursor Pro quota).
- **Sol** = `codex exec --model gpt-5.6-sol`. Prefer **inlined** audit packets when sandbox greps hang; put question files in the worktree (Windows-reachable), not only `/tmp`.
- Background seats: **alive ≠ working** — CPU + log growth.
- Git: `git -c user.name/email` from `git log -1`; named paths only; no stash across worktrees. On WSL vs Windows Git Bash hooks, prefer Windows `pwsh` git (`wsl-windows-git-hooks`).

## Local dogfood

- Interpreter: `/usr/bin/python3.9`.
- GA: `python3.9 scripts/verify_ga_readiness.py --profile baseline` **and** `--profile ga` (open referenced JSON).
- Probe: `python3.9 scripts/probe_native_analyze_timeout.py --job reports/native_analyze_probe/wave_a_job.json` (or `--binary` legacy).
- Scoped status: `bash scripts/git_status_scoped.sh`.
- Ops index: root **`backlog.md`** (not `docs/BACKLOG.md`).
- Research: Exa MCP is **often unavailable** — use WebSearch / pinned URLs + access dates (L44); never assume Exa is up.

## Canonical docs

- `docs/architecture/ceo-update-2026-08-10-wave10.md` (**latest CEO** — JS climb Option C / soft-assign + tombstones — **not** Phase 6 / GA)
- `docs/architecture/ceo-update-2026-08-09-wave3.md` (R-RALPH-2 re-baseline charter — stays open)
- `docs/architecture/ceo-update-2026-08-09-waves1-2.md` / `ceo-update-2026-08-09-wave0.md` (honesty closeout priors)
- `docs/architecture/lessons-learned-scope-c-2026-08.md` (**L1–L50**)
- `docs/architecture/wave-b-exit-criteria.md` / `wave-c-exit-criteria.md`
- Root `backlog.md` (ALL ids; §L = #101 dispositions — issue **#101** still OPEN)
- Junior docs home: `docs/README.md` (Analyst + Engineer tracks); support badges: `docs/support/`
- Related project skills: `reveng-js-recovery-climb`, `reveng-sol-frozen-tip`, `reveng-named-path-commit`, `reveng-mcp-annotation-honesty` (same `.cursor/skills/` tree); workflows `~/.claude/workflows/reveng-js-recovery-climb.md` · `reveng-wave-honesty-closeout.md`

## Wave status (do not regress)

| Wave | PR | Merge / tip |
|------|-----|-------------|
| 0 | #131 | merged |
| 1 | #132 → `41add7d1` | merged |
| 2 | #133 → `1eff22f8` | **MERGED** (not OPEN); Sol PASS_WITH_NITS on tip `34d5b99d`; post-merge note `00e9f65b` |
| 3 | Wave3=A R-RALPH-2 re-baseline | packaging re-baseline; R-RALPH-2 stays **open** |
| 4–6 | #135–#137 | recovered-root / fingerprint / wire — R-RALPH-2 still open |
| 7 | #138 | JS recovery toolkit ensemble |
| 8–9b | #149 → `838ef12e` | structural → defrag → LLM tag-boost |
| 10 | #150 | Hungarian soft_assign + unique-token tombstones |

Roadmap / RALPH-2 / phases 6–13 remain open — honesty Waves 0–2 and JS climb Waves 7–10 are **not** “all backlog closed” or enterprise GA.

## CI honesty install (L28 + L35 + L36)

Wave B / Phase 5 workflows must use `requirements-honesty.txt` + `pip install -e . --no-deps`.
Do **not** `pip install -r requirements.txt` in those jobs — py3.9 hits `resolution-too-deep`.
If the job passes `--no-cov`, **pytest-cov must be in** `requirements-honesty.txt` (L35).
Call `python` from setup-python — never hardcode `/usr/bin/python3.9` on GHA (L36).

## Fake pins (L29)

Never restore `ghidramcp>=0.1.0` in requirements-java/security without a real PyPI package.

## Wave closeout (L33–L50)

- Reject “close all backlog” PRs; implement only Thinktank-approved waves (L33).
- Issue disposition tables leave the issue **open** until acceptance (zero xfails) — #101 (L34).
- Fail-first TDD must assert a token that is red on main today (L41); soft-fail ≠ mitigated/done (L42).
- Section E: Phase 4 honesty-go stays `partial`; waiver in notes (L40/L43).
- Research cites need pinned URLs + access dates (L44). MCP hints = explicit denylist, not all `high` (L45).
- macOS slim: keep matrix legs; no angr/unicorn on slim; pin for oldest Python — `black>=24.8,<25` on macos-3.9 (L46).
- Sol verdict must cite **tip** HEAD SHA; bare FAIL / parent-SHA pin is process debt — don’t merge on self-PASS (L37/L47). Frozen tip2 flow: see `reveng-sol-frozen-tip`.
- Named-path git only on dirty DrvFS (L38); always verify `git diff --cached --name-status` before commit (L49).
- CI FAIL is a snapshot (L39); path-sep = assert hygiene; Cursor Task quota death ≠ research clean — parent finishes with tg/codex/web (L48).
- Merge bar = **honesty-unit + lint-python** (+ Sol PASS / PASS_WITH_NITS), not whole-matrix green (L50); soft-red docs-link/unit fixtures stay L42 unless wave-scoped.
