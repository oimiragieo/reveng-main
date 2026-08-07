# Scope C — Phase 4 HOLD policy (narrowed, 2026-08-07)

## Situation
Phase 4 stop/go = **HOLD** (partial). Charter: do not execute Phase 5–13 product exits until Phase 4 = **go**.

## Allowed while HOLD (docs / honesty guards only)

1. Keep/update phase **plans** and catalog status (`planned / unauthorized` or `blocked_on_phase_4`).
2. Backlog rows may be `open` / `blocked` / `parked` / `deferred` — never `done` for phase 5–13 product exits.
3. Add **refuse/overclaim regression tests** that fail if docs/matrix claim phase 5–13 complete, native GA from process green, or T3-* unparked without CEO reopen.
4. No new feature modules, CI corpus product gates, MCP productization, workers, exploit surface, or capability `done` flips.

## Forbidden
- Substantive implementation across phases 5–13 labeled as “prep”
- Retrospective stop/go
- Hollow greens; Scope C complete claims

## Unblock
When Ollama yields VRL `runtime_status: measured` (and Phase 4 both exits met), record Phase 4 **go**, then Sol-authorize Phase 5 plan before any Phase 5 product code.
