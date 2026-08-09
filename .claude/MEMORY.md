# REVENG agent memory (durable)

Cross-session facts for agents working in **reveng-main**. Keep terse; details live in linked docs.

## North star

- Product is **beta 4.0.0**; public **preview** — not full Scope C GA.
- Ops index: `/backlog.md` (root — not `docs/BACKLOG.md`)
- Latest CEO: `docs/architecture/ceo-update-2026-08-08-tg-audit-merge.md`
- Junior docs ecosystem (2026-08-09): Diátaxis dual doors in `docs/README.md` — `docs/support|tutorials|how-to|explanation|reference|ops`; MkDocs nav rewritten; maturity badges + honesty; do not treat MCP/changelogs brochure language as GA.
- Priors: `ceo-update-2026-08-07-scope-c-charter.md`, `ceo-update-2026-08-06-wave3.md`, wave2/wave1
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md` (**L1–L32**)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
- Wave B / Phase 5 honesty: slim install via `requirements-honesty.txt` (never full `requirements.txt` in those workflows)

## Hard-won facts (through 2026-08-08)

- Use **python3.9**; avoid full-`git status` on dirty `reports/` — `scripts/git_status_scoped.sh` (DF-4).
- Fixture ≠ capability; probe: `tool_absent` / `input_absent`; process `completed` ≠ native GA (**DF-5**).
- Evidence dir: exactly one stamp ≡ `latest.json` (re-check after merge).
- **L25–L32:** unpushed local main ≠ shipped; black/pytest floor vs py3.9; Windows `\\` in corpus JSON; honesty slim install; no fictional `ghidramcp>=0.1.0`; merge-while-honesty-installing; Dependabot flood returns; Phase 5 `partial` is authorized.
- Research open: **R-RALPH-2** only (engine wedge). R-HEX-1 / baselines / PIPE / SEC / VRL decisions done.
- Fable/Sol via CLI; inline Sol packets; `git -c user.name/email` from `git log -1`; no stash across worktrees.
- PR #119 merged `5a71ad65` (tg-audit + Scope C history). Issue #101 still open (pseudocode renderer).

## Open long poles

- RALPH-2 engine (R-RALPH-2)
- M1-NATIVE-FAM / M1 — hermetic analyze + `required: true`
- M2 world-class hexyl (beyond timed probe)
- M4 full nightly/corpus residual; phases 6–13 await Sol stop/go
- D1–D6 deferred tg-audit items; Docker Hub secrets / docs DNS ops
- Exploit expansion still gated (SEC = Docker-only preview)
