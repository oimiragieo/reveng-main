# REVENG agent memory (durable)

Cross-session facts for agents working in **reveng-main**. Keep terse; details live in linked docs.

## North star

- Product is **beta 4.0.0**; public **preview** — not full Scope C GA.
- Ops index: `/backlog.md` (root — not `docs/BACKLOG.md`)
- Latest CEO: `docs/architecture/ceo-update-2026-08-06-wave3.md`
- Priors: `ceo-update-2026-08-06-wave2.md`, `ceo-update-2026-08-06.md`
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md` (L1–L24)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
- Wave B gates: `docs/architecture/wave-b-exit-criteria.md`

## Hard-won facts (waves 1–3 / Wave A on main)

- Use **python3.9**; avoid full-`git status` on dirty `reports/` — use `scripts/git_status_scoped.sh` (DF-4 done).
- Fixture ≠ capability; probe v1.2: `tool_absent` / `input_absent`; process `completed` ≠ native GA (**DF-5**).
- Evidence dir: exactly one stamp matching `latest.json` (re-check after merge).
- Research: R-HEX-1 **blocked** until timed hexyl; R-RALPH-2-BASELINE done / R-RALPH-2 **open**; PIPE/SEC/VRL decisions done.
- Fable/Sol via CLI; inline Sol packets; worktree-reachable thinktank paths; `git -c user.name/email` for merges.
- Wave A merged: no `src/reveng` product changes in that wave.

## Open long poles (Wave B+)

- RALPH-2 engine (R-RALPH-2 still open)
- M1-NATIVE-FAM / M1 — analyze hermetic + `required: true`
- M2 — hexyl timed run (R-HEX-1 blocked on tool)
- M4 CI corpus gates; phases 4–13; P4/P5/P6 leftovers
- Exploit expansion still gated (SEC decision = Docker-only preview)
