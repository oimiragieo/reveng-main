# Scope C — Phase 4 HOLD prep policy (2026-08-07)

## Situation
Phase 4 stop/go = **HOLD** (partial): VRL measured blocked on Ollama; world-class M2 still open.
Charter default: do not start Phase N+1 product exits until Phase N = go.

## Exception (authorized prep only)
While Phase 4 is HOLD, agents MAY land **fail-closed prep** for phases 5–13 that:

1. Does **not** mark the phase or capability row `done`
2. Does **not** flip native `required: true` or claim GA/Scope C complete
3. Does **not** expand exploit surface (R-SEC-1)
4. Adds tests/gates that **fail** on empty/hollow evidence (bidirectional)
5. Updates backlog with `partial` / `open` / `parked` / `deferred` honestly
6. Leaves phase catalog status as planned/unauthorized or prep-partial until formal stop/go after Phase 4 go

## Allowed examples
- M4 CI workflow that fails closed on missing corpus report (Phase 5 prep)
- Equivalence helper + empty-fixture fail test (Phase 5 prep)
- Ralph `oracle_dir` wiring + scorecard tests without claiming 0.8 recall (Phase 6 prep)
- Import-linter / pipeline split docs already decided (Phase 9)
- Tier-3 honesty refuse tests (Phase 13 parked)

## Forbidden
- Claiming phase 5–13 `done` or Scope C complete
- Exploit scaffolding / Track J
- Hollow greens / fake ValidationGrade / fake measured VRL

## Reversion
If Phase 4 later goes go, re-run Sol stop/go per phase plan before marking phase exits.
