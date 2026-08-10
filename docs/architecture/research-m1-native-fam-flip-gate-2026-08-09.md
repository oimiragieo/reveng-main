# M1-NATIVE-FAM flip gate — measured block (2026-08-09)

**Question:** May we flip `.reveng/source_binary_benchmarks.ga.json` native fixtures to `required:true`?

**Answer: NO.**

## Evidence

`reports/native_analyze_probe/latest.json` (probe_version **1.3**, recorded 2026-08-07):

| id | process status | `semantic_reason` | elapsed |
|----|----------------|-------------------|--------:|
| hello_go_analyze | completed (rc 0) | **native_fallback_empty** | ~7.6s |
| hexyl_subject | completed (rc 0) | **native_fallback_empty** | ~5.1s |

DF-5 / release honesty: process `completed` ≠ native GA when native fallback returns empty `analysis_data`. Ghidra was absent on the probe host; fallback produced no analysis_data.

## Gate to reconsider flip

All must hold:

1. Analyze ≤120s on hermetic C + Go (+ ≥1 other family) **without** requiring Ghidra for the flip claim path *or* document Ghidra as allowed with measured green.
2. Semantic fields show **non-empty** native `analysis_data` (not `native_fallback_empty`).
3. Fixtures stay `fixture_only` / `required:false` until (1)+(2) are stamped in `reports/native_analyze_probe/latest.json`.

## Status

`M1-NATIVE-FAM` remains **open**. Wave 6 Thinktank (Codex Sol) **APPROVE_W6A** explicitly forbids the flip while `native_fallback_empty` stands.
