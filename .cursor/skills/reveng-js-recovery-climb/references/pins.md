# Research pins — JS recovery climb (Option C)

Accessed / measured **2026-08-10** / **2026-08-11** (Claude SEA dogfood + PR lineage).
Do not invent metrics beyond this file; append new dated rows instead of rewriting history.

## Option C contract

| Field | Pin |
|-------|-----|
| Ship bar | survivor / unlockable coverage **= 1.0 (100%)** |
| Aspirational | `oracle_coverage` (report always; never sole ship claim) |
| Recoverable | `recoverable_oracle_coverage` = \|attr\| / \|oracle − unique-token tombstones\| |
| Reporting | **BOTH** unlockable and oracle in every status note |

## Package / CLI / tests

| Surface | Path |
|---------|------|
| Toolkit | `src/reveng/app_reverse_engineering/js_recovery_toolkit/` |
| CLI | `scripts/js_recovery_toolkit.py` |
| Wave 8–10 tests | `tests/unit/test_wave8_*.py`, `test_wave85_*.py`, `test_wave9*.py`, `test_wave10_*.py` |
| Fixtures | `test_samples/js_recovery_toolkit/` |

## PR lineage

| PR | Scope | Note |
|----|-------|------|
| **#149** | Waves 8–9b | merged `838ef12e` (2026-08-10) |
| **#150** | Wave 10 soft_assign + tombstones | `feat/wave10-soft-assignment` |

## Wave → algorithm focus

| Wave | Focus |
|------|--------|
| 7 | Ensemble signals |
| 8 | Structural / Bun map / singleton |
| 8.5 | Defrag / `word_map` |
| 9 | Normalize / semantic / LLM |
| 9b | webcrack + LLM tag-boost |
| 10 | Hungarian soft_assign + unique-token tombstones + margin gate |

Algorithms named in-tree: TF-IDF cosine, greedy unique, `scipy.optimize.linear_sum_assignment`, unique-token tombstones, margin gate.

## Claude SEA dogfood (operator-local — NOT in git)

Receipts live under `/mnt/c/tmp/reveng_w*` only. Never commit.

| Checkpoint | oracle_coverage (approx) | Notes |
|------------|--------------------------|--------|
| ensemble | ~29% | Wave 7 |
| + singleton union | ~33% | Wave 8 |
| + iterative defrag | ~52% | Wave 8.5 |
| + LLM tag-boost | ~55% (1053/1902) | Wave 9b |
| + soft_assign | **~57% (1087/1902)** | Wave 10 |
| residue | recoverable **~82%** of unique-residue survivors | Wave 10 |
| tombstones | **874** | unique-token locks |
| unlockable | **1.0** | Option C ship bar |

### Map vs SEA contrast

| Path | Pin |
|------|-----|
| `.map` materialize when map exists | **oracle 1.0** |
| Claude SEA | `sourcemap_size=0` (Bun embed decode inert) |

## arXiv inspiration (cite; not identity claims)

| Paper | URL | Access |
|-------|-----|--------|
| Sinkhorn / assignment (1707.07285) | https://arxiv.org/abs/1707.07285 | 2026-08-10 |
| Unsupervised clone measures (2401.09885) | https://arxiv.org/abs/2401.09885 | 2026-08-10 |

## 100% ceiling honesty

Accessed **2026-08-11** (CEO Q&A + Exa evaluation-honesty pins).

| Question | Pin |
|----------|-----|
| Unlockable / survivor 100%? | **Yes — ship bar already met** on Claude Bun dogfood |
| Full-oracle 100% on stale-map → SEA (`sourcemap_size=0`)? | **No** for ~874 unique-token tombstones (no residue) |
| Full-oracle 100% when same-era `.map` / embedded SerializedSourceMap? | **Yes** (map path already **oracle 1.0**; Wave 8 decoder ready when `sourcemap_size > 0`) |
| Unique-residue leftover (~18% of survivors)? | Climbable with better algos; **not** FP-free guaranteed to 100% |
| Pretty close (~57% oracle / ~82% recoverable)? | **≠ 100%** — never redefine |

Evaluation discipline (cite; not product claims):

- Report **triple coverage** (unlockable + oracle + recoverable); unitless similarity ≠ semantic recovery — [LLM4Decompile](https://arxiv.org/abs/2403.05286), [DecompileBench](https://arxiv.org/html/2505.11340v1) (accessed 2026-08-11).
- Tombstones are accounting, not “misses” folded into failure rate — Option C + Wave 10 unique-token locks.
- Hungarian / Sinkhorn assign is a **candidate generator**; accept only under margin / validators — [arXiv:1707.07285](https://arxiv.org/abs/1707.07285); BinSlayer-style bipartite validation (accessed 2026-08-11).
- Map-absent SEA unlockable 1.0 ≠ enterprise / exe / native GA.

## Honesty boundaries (do not regress)

- **Not** R-RALPH-2 close
- **Not** exe / native decode capability
- **Not** enterprise GA
- Dogfood under `/mnt/c/tmp/reveng_w*` — never stage into the repo
- Cross-skill: `reveng-release-honesty`, `reveng-named-path-commit`
