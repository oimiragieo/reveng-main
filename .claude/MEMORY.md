# REVENG agent memory (durable)

Cross-session facts for agents working in **reveng-main**. Keep terse; details live in linked docs.

## North star

- Product is **beta 4.0.0**; public **preview** after Phase 1–2 honesty + managed recompile — not full Scope C GA.
- Ops index: `/backlog.md`
- Latest CEO briefing: `docs/architecture/ceo-update-2026-08-06.md`
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md`
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`

## Hard-won facts (2026-08-06)

- Use **python3.9** for gates on this host; system 3.13 may lack stdlib.
- `capability_report` must go through `enrich_app_analysis_payload` or it is dead code.
- Managed recompile path: `recompile_command.is_managed_language_input` → app adapters (no Ghidra).
- GA report rows: four hermetic managed benches `completed_without_behavior_checks`.
- Do not full-`git status` with huge `reports/` trees on WSL/DrvFS.

## Open long poles

- RALPH-2 (cli.js 0.8+ recall) — engine work
- M1-NATIVE-FAM — needs Linux-hermetic native fixtures (research)
- Hexyl / VRL / phases 4–13 — see backlog + Scope C plan
