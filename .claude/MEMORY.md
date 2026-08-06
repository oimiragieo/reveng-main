# REVENG agent memory (durable)

Cross-session facts for agents working in **reveng-main**. Keep terse; details live in linked docs.

## North star

- Product is **beta 4.0.0**; public **preview** after Phase 1–2 honesty + managed recompile — not full Scope C GA.
- Ops index: `/backlog.md` (root — not `docs/BACKLOG.md`)
- Latest CEO briefing: `docs/architecture/ceo-update-2026-08-06-wave2.md`
- Prior CEO: `docs/architecture/ceo-update-2026-08-06.md`
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md` (L1–L18)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`

## Hard-won facts (2026-08-06 waves 1–2)

- Use **python3.9** for gates on this host; system 3.13 may lack stdlib.
- `capability_report` must go through `enrich_app_analysis_payload` or it is dead code.
- Managed recompile path: `recompile_command.is_managed_language_input` → app adapters (no Ghidra).
- GA report rows: four hermetic managed benches `completed_without_behavior_checks`.
- Do not full-`git status` with huge `reports/` trees on WSL/DrvFS.
- Native fixtures (`test_samples/native/`) ≠ analyze capability; keep `fixture_only` / `required: false`.
- Analyze probe v1.1: nonzero → `could_not_measure` + exit 2; scrub dishonest stamps when fixing `latest.json`.
- Fable/Sol via CLI (`claude-fable-5`, `gpt-5.6-sol`); Cursor Pro ≠ Fable; alive ≠ working.
- Host C linker may be broken; Go `CGO_ENABLED=0` works; skip markers must be loud.

## Open long poles

- RALPH-2 (cli.js 0.8+ recall) — needs **R-RALPH-2** research then engine work
- M1-NATIVE-FAM — fixtures landed; need analyze ≤120s success + flip `required`
- M2 / R-HEX-1 — probe shipped; **hexyl binary timed run still open** on this host
- R-PIPE-1, R-SEC-1, R-VRL-1 — research before large builds
- Phases 4–13, M4 CI corpus gates — see `backlog.md`

## Active branch (wave 2)

- `feat/scope-c-phase-next` in `.worktrees/scope-c-phase-next` (Sol APPROVE native-fixtures)
