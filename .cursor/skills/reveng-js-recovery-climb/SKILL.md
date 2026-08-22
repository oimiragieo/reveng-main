---
name: reveng-js-recovery-climb
description: >-
  Use when climbing JS recovery / unlockable coverage on Claude SEA or similar
  minified bundles, editing js_recovery_toolkit (Waves 7–10: ensemble, structural
  / Bun map, defrag / word_map, normalize / semantic / LLM, webcrack + tag-boost,
  Hungarian soft_assign + unique-token tombstones), running scripts/js_recovery_toolkit.py,
  writing test_wave8_* / test_wave85_* / test_wave9* / test_wave10_*, or reporting
  oracle_coverage vs survivor/unlockable ship-bar metrics. Enforces Option C honesty
  (100% unlockable ship bar; oracle aspirational; report BOTH) and refuses GA /
  R-RALPH-2 / exe-decode overclaims.
---

# REVENG JS recovery climb (Option C)

## When this applies

Any work on `src/reveng/app_reverse_engineering/js_recovery_toolkit/`, the
`scripts/js_recovery_toolkit.py` CLI, wave-tagged unit tests, Claude SEA / Bun
`.map` recovery dogfood, or status language that mentions oracle vs unlockable
coverage.

## Option C ship bar (non-negotiable)

| Metric | Role |
|--------|------|
| **Survivor / unlockable coverage** | **Ship bar = 1.0 (100%)** |
| **`oracle_coverage`** | **Aspirational** — climb is real; never the sole merge claim |
| **`recoverable_oracle_coverage`** | Climb vs map minus unique-token tombstones (Wave 10) |
| **Reporting** | Always report **BOTH** unlockable and oracle (plus recoverable when tombstones run) |
| **Wave 10 status** | Soft-assign + tombstones **merged** PR #150 → `82bc0ec3` (Sol PASS tip2 `accf553a`). Closeout CEO: `ceo-update-2026-08-21-wave10-closeout.md`. |

Do not invent metrics beyond pinned dogfood (see [references/pins.md](references/pins.md)).

## 100% ceiling honesty (CEO Q&A — do not regress)

| Claim | Truth |
|-------|--------|
| Unlockable / survivor **100%** | **Already the ship bar** — achieved on Claude Bun dogfood by construction once modules unlock |
| Full-oracle **100%** on *this* stale-map → Claude SEA (`sourcemap_size=0`) | **Not honestly possible** for ~**874** unique-token tombstones (no residue in the Bun blob) |
| Full-oracle **100%** in general | **Yes** when a **same-era `.map`** exists (already measured **1.0**) **or** Bun embeds SerializedSourceMap (`sourcemap_size > 0`) |
| Unique-residue survivors | ~**82%** recoverable; ~**18%** still climbable with better algorithms — **not** guaranteed to 100% without false positives |
| “Pretty close” / ~57% oracle | **≠ 100%** — never redefine near-miss as done |

Refuse status language that collapses these into one “100% recovery” claim.

## Wave map (do not renumber casually)

| Wave | Focus |
|------|--------|
| 7 | Ensemble signals / index |
| 8 | Structural match, Bun serialized sourcemap, singleton coverage |
| 8.5 | Iterative defrag + `word_map` |
| 9 | Readable normalize + semantic digest + LLM digest |
| 9b | webcrack + LLM tag-boost (`provider_summarize` / `tag_boost`) |
| 10 | Hungarian `soft_assign` (`scipy.optimize.linear_sum_assignment`) + unique-token tombstones + margin gate |

Merged lineage: **PR #149** = Waves 8–9b; **PR #150** = Wave 10 (open/merge as of skill authoring).

## Algorithms in play

- TF-IDF cosine similarity (word_map / soft_assign word channel)
- Char n-gram TF-IDF (fixtures / small bundles; skipped on multi-MB Claude `cli.js`)
- Greedy unique assignment → replaced/supplemented by Hungarian for collision traps
- Unique-token tombstones (shared boilerplate ≠ survivor)
- Margin gate (reject ambiguous best≈second pairs)
- Graph unlock / co-occurrence / semantic_digest (defrag loop)

Inspiration (cite, do not overclaim identity): Sinkhorn/assignment [arXiv:1707.07285](https://arxiv.org/abs/1707.07285); unsupervised clone measures [arXiv:2401.09885](https://arxiv.org/abs/2401.09885). Pins + access dates in `references/pins.md`.

## Non-negotiables checklist

```
JS recovery climb:
- [ ] Ship claim uses unlockable/survivor coverage (bar = 1.0), not oracle alone
- [ ] oracle_coverage reported alongside unlockable (BOTH) — aspirational only
- [ ] Numbers match pins.md or a NEW dated dogfood receipt (no invented deltas)
- [ ] Hermetic tests: test_wave8_* / test_wave85_* / test_wave9* / test_wave10_* green for touched wave
- [ ] CLI exercised via scripts/js_recovery_toolkit.py when behavior changes
- [ ] Dogfood receipts stay under /mnt/c/tmp/reveng_w* — NEVER git-add Anthropic trees / Bun extracts
- [ ] Honesty: NOT R-RALPH-2 close, NOT exe decode, NOT enterprise GA
- [ ] Named-path commit only (reveng-named-path-commit); verify git diff --cached --name-status
- [ ] Same-era .map materialize ≠ Claude SEA path (sourcemap_size=0) — do not conflate
- [ ] Tombstone scan uses unique-owner tokens (any-token hits false-survivors on 24MB bundles)
```

## Local surfaces

- Package: `src/reveng/app_reverse_engineering/js_recovery_toolkit/`
- CLI: `python scripts/js_recovery_toolkit.py` (prefer `/usr/bin/python3.9`)
- Tests: `tests/unit/test_wave8_*.py`, `test_wave85_*.py`, `test_wave9*.py`, `test_wave10_*.py`
- Fixtures: `test_samples/js_recovery_toolkit/`
- CEO (closeout, plain English): `docs/architecture/ceo-update-2026-08-21-wave10-closeout.md`
- CEO (feature metrics): `docs/architecture/ceo-update-2026-08-10-wave10.md`
- Research: `docs/architecture/research-wave10-soft-assignment-2026-08-10.md` (+ wave8/85/9*)

## Climb loop (agent)

1. **Research** — Read pins; cite arXiv with access date; Exa if up else WebSearch + L44.
2. **Hermetic TDD** — Fail-first on the wave under edit; keep tests offline / fixture-bound.
3. **Dogfood** — Operator-local Claude SEA (or agreed target); receipts only under `/mnt/c/tmp/reveng_w*`.
4. **Honesty docs** — Update status with BOTH metrics; cross-check `reveng-release-honesty`.
5. **Named-path PR** — Stage exact toolkit / test / doc paths; never dogfood trees.

## Anti-patterns

| Excuse | Reality |
|--------|---------|
| "oracle ~57% — almost GA" | Oracle is aspirational; ship bar is unlockable 1.0. Not enterprise GA. |
| "Map path got oracle 1.0, SEA is done" | Same-era `.map` materialize ≠ Claude SEA (`sourcemap_size=0`). |
| "Recoverable ~82% of residue = unlocked all" | Residue recoverable ≠ unlockable ship bar; report BOTH + tombstone count. |
| "Commit /mnt/c/tmp/reveng_w* for reproducibility" | Dogfood is operator-local, **never** in git. |
| "Wave 10 closes R-RALPH-2 / exe decode" | Toolkit climb ≠ R-RALPH-2 close ≠ native exe decode. |
| "Skip unlockable; oracle moved +3pp" | Option C: unlockable 100% is the bar; oracle climb is bonus. |
| "`git add -A` after dogfood" | Named-path only; tmp receipts must stay unstaged. |
| "Any token in bundle ⇒ survivor" | Use unique-owner tokens or mega-bundles mark everything alive. |
| "57% oracle / 82% recoverable ≈ 100%" | Pretty close ≠ 100%. Tombstones block full-oracle on SEA. |
| "Smarter algo will unlock tombstones" | No unique residue ⇒ not an algorithm miss; need map/embed or accept ceiling. |

## Measured dogfood (Claude SEA, operator-local — not in git)

Pinned snapshot (see pins for dates):

- Oracle climb: ~29% → 33% → 52% → 55% → **57% (1087/1902)**
- Recoverable ≈ **82%** of unique-residue survivors
- Tombstones: **874**
- Unlockable: **1.0**
- Contrast: same-era `.map` materialize → **oracle 1.0 when map exists**; Claude SEA `sourcemap_size=0`

## Cross-refs

- Release / GA honesty: `reveng-release-honesty`
- Commits on dirty DrvFS: `reveng-named-path-commit`
- Pins + paper URLs: [references/pins.md](references/pins.md)
- Dynamic workflow: `~/.claude/workflows/reveng-js-recovery-climb.md`
- Honesty closeout (different loop): `~/.claude/workflows/reveng-wave-honesty-closeout.md`
