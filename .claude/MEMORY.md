# REVENG agent memory (durable)

Cross-session facts for agents working in **reveng-main**. Keep terse; details live in linked docs.

## North star

- Product is **beta 4.0.0**; public **preview** — not full Scope C GA.
- Ops index: `/backlog.md` (root — not `docs/BACKLOG.md`)
- Latest CEO: `docs/architecture/ceo-update-2026-08-09-wave0.md` (prior: `ceo-update-2026-08-08-tg-audit-merge.md`)
- Junior docs ecosystem: Diátaxis dual doors in `docs/README.md` — `docs/support|tutorials|how-to|explanation|reference|ops`
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md` (**L1–L40**)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
- Wave B / Phase 5 honesty: `requirements-honesty.txt` (+ **pytest-cov**) + `pip install -e . --no-deps`; CI workflows use `python` not `/usr/bin/python3.9`

## Hard-won facts (through 2026-08-09)

- Use **python3.9** locally; avoid full-`git status` on dirty `reports/` — `scripts/git_status_scoped.sh` (DF-4 / **L38**).
- Fixture ≠ capability; process `completed` ≠ native GA (**DF-5**).
- Evidence dir: exactly one stamp ≡ `latest.json`.
- **L25–L32:** unpushed main ≠ shipped; tool floor vs py3.9; Windows `\\` in JSON; honesty slim install; no fictional ghidramcp; merge-while-installing; Dependabot flood; Phase 5 `partial` authorized.
- **L33–L40:** Wave-scope not all-backlog; #101 disposition ≠ shipped; slim install needs pytest-cov; no hardcoded GHA python path; Sol process FAIL ≠ product FAIL; named-path git; CI FAIL is a snapshot; section E status column must parse cleanly.
- Research open: **R-RALPH-2** only. Wave 0 **CLOSEOUT-W0 done** (PR #131). Issue **#101** still **OPEN** (43 xfails dispositioned blocked).
- Fable/Sol via CLI; inline Sol packets; `git -c user.name/email` from `git log -1`; no stash across worktrees.
- Cursor Task quota can exhaust — prefer `codex exec` / `claude -p` over Task spawn for audits.

## Open long poles

- RALPH-2 engine (R-RALPH-2) — needs research then Sol stop/go
- M1-NATIVE-FAM / M1 — hermetic analyze + `required: true`
- M2 world-class hexyl (beyond timed probe)
- M4 full nightly/corpus residual; phases 6–13 await Sol stop/go
- #101 rich Capstone renderer; CI-DOCS-LINK-1; CI-UNICORN-BUILD-1
- D1–D6 deferred tg-audit items; Docker Hub secrets / docs DNS ops
- Exploit expansion still gated (SEC = Docker-only preview)
