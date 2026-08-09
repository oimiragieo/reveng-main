# Backlog Closeout Program Plan (multi-wave)

> **For agentic workers:** REQUIRED: implement **only** the wave Thinktank marks APPROVE for coding. Do not claim phases 6–13 / RALPH-2 closed without Sol stop/go + measured evidence.

**Goal:** Drive REVENG backlog, open issues, and known bugs to honest terminal states (`done` / `partial` / `deferred` / `wontfix` / `parked`) without lying about GA — via sequenced waves, TDD, and security-minded reviews.

**Architecture:** Program plan (all IDs inventoried) + **Wave 0** (land in-flight honesty/docs + close what is Sol-safe now) + later waves gated by charter Sol stop/go. Branch `feat/backlog-closeout-wave0` for implementation; merge to `main` after Codex clean + lint + dogfood.

**Tech Stack:** Python 3.9, pytest TDD, black/isort 100, import-linter, gh issues, root `backlog.md`.

## Global Constraints

- Honesty SoT: `docs/support_matrix.json`, release-honesty skill, lessons L1–L32
- Phases **6–13** remain `open (await Sol stop/go)` until Sol authorizes — disposition rows ≠ capability `done`
- **R-RALPH-2**, native `required:true`, LibAFL, exploit expansion: **not** Wave 0
- TDD: red → green → refactor; bidirectional honesty tests where status strings change
- Security: no exploit expansion; keep EXPERIMENTAL watermarks; no secrets in commits
- Named-path commits; `git -c user.name/email` from `git log -1`; no stash across worktrees
- Prefer `/usr/bin/python3.9`

## PLAN SUMMARY (Thinktank)

- **Intent:** Close **everything that can be closed honestly now** (Wave 0), and publish a sequenced program for the rest — not a fake “all 85 rows done” PR.
- **Wave 0 in scope:** Land uncommitted 2026-08-09 wiring/docs honesty; backlog hygiene for that wave; GitHub **#101** (rich Capstone pseudocode / 36 xfails) if TDD-green this wave **or** document blocked with acceptance tests filed; dogfood + lint; update `backlog.md`.
- **Out of Wave 0:** RALPH-2 engine, M1-NATIVE-FAM required:true, M2 world-class, phases 6–13 product builds, EPIC-3..9 megarefactors, V6 blue ocean.
- **Success metric Wave 0:** Codex PASS vs this plan’s Wave 0 tasks; `test_world_class_wiring_honesty_2026_08_09.py` green; `#101` closed **or** explicit backlog `blocked` with reason; `main` merged; no new honesty regressions.

---

## Inventory (2026-08-09)

| Bucket | Count / note |
| --- | --- |
| Backlog open/partial/blocked-ish | ~85 row mentions (section C/F/J duplicates) |
| Research open | **R-RALPH-2** only |
| Phases awaiting Sol | **6–13** |
| GitHub open issues | **#101** only |
| In-flight uncommitted | World-class wiring honesty + junior docs ecosystem (prior session) |

Canonical ID lists remain in root `backlog.md` sections C–J. Do not delete rows — update `status` + notes.

---

## Program waves (full backlog path)

| Wave | Closes / advances | Gate |
| --- | --- | --- |
| **0 — Honesty land + issue triage** | Ship in-flight honesty/docs; #101; backlog dogfood rows | Thinktank APPROVE Wave 0 (this plan) |
| **1 — Disposition P0 REVs** | REV-P0-INSTALLERS deprecate-or-finish policy; REV-P0-EVIDENCE-AUDIT read-only matrix; REV-P0-ANALYSIS-CLEANUP written policy | Sol light review |
| **2 — M3/M4 residual honesty** | Unified grade discriminators; corpus CI residual without claiming full nightly | Phase 5 thin honesty already authorized — cite `docs/architecture/decision-phase-05-thin-honesty-auth.md` + `reports/equivalence_honesty/latest.json` before dispatch |
| **3 — Phase 6 JS** | RALPH-1 finish; R-RALPH-2 research→wedge; P4-BUNDLER | **Sol stop/go** |
| **4 — Phase 7 native** | M1-NATIVE-FAM required flip; P5-NATIVE-EQ | Sol + measured analyze |
| **5 — Phases 8–11** | MCP productization, workers, packaging | Sol stop/go each |
| **6 — Phases 12–13 / V6** | Platform + blue ocean | Post SEC-1 / Sol |

---

## Wave 0 tasks (IMPLEMENT NOW if Thinktank APPROVES)

### Task W0-1 — Branch + baseline

- [ ] Record dirty-tree ownership: named-path `git status --porcelain -- <paths>` + `git branch --show-current` + note concurrent untracked noise (do **not** full `git status` on DrvFS)
- [ ] `git checkout -b feat/backlog-closeout-wave0` from current `main` only after recording baseline
- [ ] Baseline command (pin count from output):  
  `python3.9 -m pytest tests/unit/test_world_class_wiring_honesty_2026_08_09.py -q --no-cov`  
  Store exact `N passed` in the branch commit message / Sol packet (do not hardcode “22” if count drifts)
- [ ] Do not stage unrelated dirty files

### Task W0-2 — Land wiring honesty (already coded)

- [ ] Stage named paths for MCP/CLI/health/java_ai/native docstring + `tests/unit/test_world_class_wiring_honesty_2026_08_09.py` + related docs
- [ ] Re-run honesty suite; must match or exceed W0-1 baseline `N passed`
- [ ] Commit: `fix(honesty): MCP/CLI wiring Top-8 + tests`

### Task W0-3 — Land junior docs ecosystem (if still uncommitted)

- [ ] Stage `docs/support|tutorials|how-to|explanation|reference|ops`, `mkdocs.yml`, README docs section, design/plan docs as needed
- [ ] Commit: `docs: Diátaxis dual-door junior ecosystem`

### Task W0-4 — GitHub #101 Capstone pseudocode

**Acceptance (close #101 only if all true):**
1. `tests/unit/test_local_disassembler.py` has **zero** `xfail`/`XFAIL` remaining for the rich-pseudocode renderer stories listed in #101, **or**
2. A published disposition table in `backlog.md` lists **each** remaining xfail id → `pass` / `blocked` / `wontfix` with one-line reason, and #101 stays open with that table linked.

- [ ] Reproduce: read #101; inventory xfails in `tests/unit/test_local_disassembler.py`
- [ ] TDD: remove xfail from one failing case → red → implement minimal rich local renderer in the module under test → green
- [ ] Continue until acceptance (1) or publish disposition table (2)
- [ ] Security: no new untrusted-code execution beyond existing disassembler norms
- [ ] Close #101 only under acceptance (1)

### Task W0-5 — Backlog.md updates

- [ ] Dogfood rows: WIRING-2026-08-09, DOCS-DUALDOOR-2026-08-09, ISSUE-101 disposition
- [ ] Link this program plan + Wave 0 Sol verdict under ops/CEO pointers
- [ ] Section H: any new dogfood findings

### Task W0-6 — Codex audit loop

- [ ] Packet includes: plan Wave 0 tasks, `git rev-parse HEAD`, named-path `git diff main...HEAD --name-only`
- [ ] `codex exec --model gpt-5.6-sol` until PASS; save `docs/architecture/sol-wave0-impl-verdict.md` with **reviewed commit SHA**
- [ ] If working tree changes after the verdict SHA, re-run Codex before merge

### Task W0-7 — Lint / format / dogfood / merge

- [ ] black+isort on touched Python; `lint-imports --no-cache` if imports changed
- [ ] Dogfood commands (record exit codes):  
  - honesty suite (baseline file)  
  - `python3.9 -m pytest tests/unit/test_local_disassembler.py -q --no-cov` (or subset named in #101 disposition)  
  - `reveng --help` / `python -m reveng --help`  
  - optional: `reveng reverse-engineer-app test_samples/sample_bundle.js --output-dir /tmp/re_app_df`
- [ ] Open PR with named-path diff verification (`git diff --cached` / PR files == Wave 0 set); **no fast-forward-only merge bypass** — merge via PR when remote available
- [ ] Update `backlog.md` with any new bugs from dogfood

---

## Explicitly deferred (not Wave 0)

All of: RALPH-2 engine, M1-NATIVE-FAM `required:true`, world-class M2, phases 6–13 product implementation, EPIC-3–9 architecture extraction, FEAT-3–10, REV-MCP installable product, V6-* rows, exploit sandbox expansion.

---

## Thinktank decision required

Reply with **APPROVE Wave 0** / **APPROVE_WITH_NITS** / **REJECT**.  
REJECT if plan claims all 85 backlog rows ship in one coding loop.

**Round 1 (2026-08-09):** Sol APPROVE_WITH_NITS · Fable APPROVE_WITH_NITS — nits applied in Wave 0 tasks above (PR-only merge, baseline pin, #101 acceptance table, Sol SHA gate, Phase 5 evidence cite).
