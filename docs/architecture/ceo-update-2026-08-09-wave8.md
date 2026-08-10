# CEO update — 2026-08-09 (Wave 8: structural + Bun map decode + coverage)

## Verdict

Wave 8 lands **structural MinHash**, **Bun SerializedSourceMap (zstd) decoder**, **singleton literal** attribution, and a **coverage union** reporter. Hermetic fixture hits **oracle + survivor coverage 100%**. Operator-local Claude stale→Bun: **621/1902 (~33%)** attributed with **survivor_coverage 1.0**; Claude SEA has **zero** embedded sourcemaps so the Bun decode path cannot unlock the rest. **Not R-RALPH-2 / Phase 6 / enterprise GA.**

## What “100%” means here

| Claim | Status |
|-------|--------|
| Hermetic remix: all first-party map sources attributed | **yes** |
| Same-era map materialize vs oracle `src/` | **yes (1.0)** — prior dogfood |
| All *survivors* on Claude Bun attributed | **yes (1.0)** |
| All 1902 old `src/` files on current Claude Bun | **no (~33%)** — no embedded maps; structural 0 |

## Next levers (honest)

1. Prefer matching-era `.map` when available (already 100%).
2. Re-measure when Anthropic ships Bun with `sourcemap_size > 0`.
3. Optional: more signal kinds / mid-size corpus hill-climb (precision gated).

## Pointers

- Research: `docs/architecture/research-wave8-structural-bun-100-2026-08-09.md`
- Tests: `tests/unit/test_wave8_structural_coverage.py`
