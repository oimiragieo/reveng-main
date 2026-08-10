# CEO update — 2026-08-10 (Wave 10: Hungarian soft-assign + tombstones)

## Why
Claude Bun climb stalled ~55% oracle because remaining modules mostly share weak tokens (greedy TF-IDF collisions) and many map paths have **no unique residue**. Exa→arXiv pointed at **global linear assignment** + **multi-feature unsupervised similarity** + **present-vs-absent** classification.

## Shipped
- `soft_assignment.py` — scipy Hungarian on blended word/char TF-IDF cosines, margin gate
- `tombstone.py` — unique-token residue tombstones + `recoverable_oracle_coverage`
- Wired into iterative defrag (`soft_assign`) + pipeline `tombstone` stage
- Hermetic: `test_wave10_soft_assignment.py` **5 passed**

## Operator-local Claude (stale map → Bun `cli.js`, seed = Wave 9b 1053)
| Metric | Value |
|--------|------:|
| soft_assign new | **+34** (unique-residue candidates; word channel) |
| oracle_coverage | **0.5715 (1087/1902)** ≈ **57%** (was ~55%) |
| unique-residue survivors | 1028 |
| tombstones (no unique token in bundle) | 874 |
| recoverable_oracle_coverage | **0.8191 (~82%)** |
| unlockable/survivor ship bar | **1.0** (unchanged) |

Receipt (operator-local, not in git): `/mnt/c/tmp/reveng_w10/wave10_probe.json`

## Metrics framing (option C)
| Metric | Role |
|--------|------|
| survivor / unlockable | **ship bar** (must stay 1.0) |
| oracle_coverage | aspirational climb vs full old map |
| recoverable_oracle_coverage | climb vs map minus unique-token tombstones |

## Honesty
Still **not** enterprise GA / R-RALPH-2 close / exe decode. Neural clone models (CodeBERT etc.) stay optional research lanes. Soft-assign on shared-token-only paths is suppressed by the unique-residue filter.
