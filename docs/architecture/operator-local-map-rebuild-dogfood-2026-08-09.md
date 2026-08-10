# Operator-local dogfood — map rebuild + stale-map fingerprint (2026-08-09)

**Scope:** Operator-local only. **No Anthropic recovered trees, maps, or bundle bytes in git.**
Counts/metrics only. **Not** exe decode. **Not** R-RALPH-2 / Phase 6 / enterprise GA close.

Inputs (host paths, not committed):

| Role | Path |
|------|------|
| Map-era package (cli.js + cli.js.map + oracle `src/`) | `C:/dev/github-repos/claude-code-source-main` |
| Bun extract (newer) | `/tmp/claude_bun_extract/stable/cli.js` (+ `claude_bundle.js`) |
| Workdir | `/tmp/claude_map_rebuild_w5dogfood/` |

## Arms

### A — Map rebuild (Wave 4 materialize)

Sibling `cli.js.map` → `materialize_js_project_tree` (`mode=source_map`).

| Metric | Value |
|--------|------:|
| `project_file_count` | 3821 |
| `project_src_file_count` | 2298 |
| `oracle_src_file_count` | 1902 |
| `src_path_intersection` | 1902 |
| **src_recall_vs_oracle** | **1.0** |
| elapsed | ~3.9s |
| `decoded_exe_claim` | false |

Interpretation: same-era map `sourcesContent` rebuild recovers the full oracle `src/` path set. Extra project files are map sources outside oracle `src/` (e.g. vendored paths under `project/`).

### B — Fingerprint transfer (Wave 5 Tier A)

Hashed index from map `sourcesContent`; scan target bundle; ≥2-signal confirmations.

| Arm | confirmed (first-party) | under `src/` | node_modules | provenance mean | name_recovery mean | index entries |
|-----|------------------------:|-------------:|-------------:|----------------:|-------------------:|--------------:|
| same-era map → `cli.js` | 263 | 263 | 0 | 0.923 | 0.0 | 9062 |
| stale map → Bun `stable/cli.js` | **232** | 232 | 0 | 0.927 | 0.0 | 9062 |
| stale map → `claude_bundle.js` | 232 | 232 | 0 | 0.927 | 0.0 | 9062 |

All arms: `decoded_exe_claim=false`, `llm_used=false`.

Interpretation: fingerprint transfer attributes hundreds of first-party `src/` paths from a **stale** map onto a **newer Bun extract** without claiming decode. This is attribution evidence for Wave 6 engine work — not a 0.8 Ralph close on product packaging.

### C — Bidirectional control (already hermetic)

Synthetic fixtures under `test_samples/js_stale_map_transfer/`: mismatch confirms **0**; positive confirms α with ≥2 signals (unit tests).

## Honesty bounds

- Fixture/dogfood ≠ product capability on current npm `claude.exe` packaging.
- VLQ remap of stale map onto Bun bytecode remains invalid (line-ratio ~0.31 historically); fingerprint path is the approved wedge.
- R-RALPH-2 / Phase 6 remain **open**.
