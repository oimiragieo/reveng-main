# Honesty rules (for readers and authors)

> **Maturity:** preview (product) · these rules are **supported** as process

REVENG is a large reverse-engineering platform under active hardening. Docs must teach juniors **what works** without selling unfinished work.

## Non-negotiables

1. **Open the evidence** — a green script is not enough; read the JSON fields it cites.
2. **No hollow gates** — a check that passes with empty evidence is broken.
3. **Fixture ≠ capability** — `test_samples/native/` proves CLI byte-stability only until analyze is measured green with `required: true`.
4. **Process `completed` ≠ native GA** — exit 0 with empty/partial native fallback is not success (DF-5).
5. **Wire product paths** — helpers that only exist in unit tests do not ship.
6. **Match the support matrix** — `docs/support_matrix.json` is the customer boundary.
7. **Exploits stay experimental** — Docker-only preview; CLI watermarked; no GA claims.
8. **Two grade ladders** — App RE grades and VRL grades are different vocabularies; do not mix them (see [Reading validation grades](reading-validation-grades.md)).

## Language to avoid

- “Production ready”, “world-class complete”, invented “95%+” rates
- Calling experimental features “supported” because a command exists
- Implying Ghidra-free native PE/ELF recompile is GA

## Where ops detail lives

CEO updates, thinktank packets, and wave exit criteria are **ops**, not product tutorials. Start at [Ops index](../ops/README.md).

## Related

- [Maturity badges](maturity-badges.md)
- [Support matrix](support-matrix.md)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md`
