# Research — Wave 8 structural + Bun SerializedSourceMap + coverage union (2026-08-09)

Exa + Bun upstream (`sourcemap::SerializedSourceMap`) + hermetic climb. **Not** exe decode / R-RALPH-2 / enterprise GA.

## Research findings

| Finding | Implication |
|---------|-------------|
| Bun can embed **SerializedSourceMap** with **zstd** per-file `sourcesContent` | Path to ~100% **when** `sourcemap_size > 0` |
| Current Claude npm SEA module graph: **8 modules, all `sourcemap_size: 0`** | Embedded-map path is **inert** on this build |
| astdiff-style MinHash (identifier-blind shingles) | Useful on remixed fixtures; **0 adds** on stale-TS → minified Bun cli.js at threshold 0.50 |
| Same-era `.map` `sourcesContent` materialize | Already **oracle recall 1.0** (1902/1902) — the real 100% path when you have the matching map |

## New code

| Module | Role |
|--------|------|
| `js_recovery_toolkit/bun_serialized_sourcemap.py` | Decode Header + StringPointer tables + zstd contents; fixture builder |
| `js_recovery_toolkit/structural_match.py` | Pure-Python MinHash chunk matcher |
| `js_recovery_toolkit/coverage_union.py` | Singleton unique-literal + union coverage metrics |
| Pipeline stages | `singleton_literal`, `structural_match`, `coverage_union`, `bun_serialized_sourcemap` |

## Measured results

### Hermetic fixture

- `oracle_coverage == 1.0`, `survivor_coverage == 1.0` (`test_pipeline_survivor_and_oracle_100pct`)
- SerializedSourceMap round-trip recovers 100% of fixture sources
- Mismatch arm stays at attributed 0

### Operator-local Claude (stale map → Bun `stable/cli.js`)

| Metric | Value |
|--------|------:|
| oracle `src/` | 1902 |
| ensemble | 553 |
| singleton extras | +68 |
| **union attributed** | **621** |
| **oracle_coverage** | **0.3265 (~33%)** |
| **survivor_coverage** | **1.0** |
| structural adds | **0** |
| Bun embedded maps | **0** |
| `decoded_exe_claim` | false |

**Honest ceiling:** 100% of the *old* tree on a *newer* Bun ship without embedded maps is not available — deleted/rewritten modules leave no survivors. 100% of **survivors** is achieved. 100% of oracle remains: same-era map, or a Bun build that embeds SerializedSourceMap.

## How to run

```bash
export PYTHONPATH=src
python3.9 -m pytest tests/unit/test_wave8_structural_coverage.py -q --no-cov
python3.9 scripts/js_recovery_toolkit.py \
  --bundle path/to/bundle.js --map path/to/stale.map \
  --output-dir /tmp/w8_out
```

## Honesty

- Fixture 100% ≠ Claude 100% of old oracle
- Survivor 100% ≠ oracle 100%
- R-RALPH-2 / Phase 6 stay **open**
