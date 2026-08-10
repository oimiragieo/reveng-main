# CEO update — 2026-08-09 (Wave 4: JS recovered-root)

## Verdict

Wave 4 lands the **recovered-root wedge** on the tracked micro-bundle: sibling source-map `sourcesContent` → `output_dir/project/`, structural identifier **hints** JSON (no rewrite), discriminating mismatch control. Tracked Ralph recall moved **0.0 → 0.4**. **R-RALPH-2 / Phase 6 / enterprise GA remain open.**

## What shipped

- `js_project_materialize.py` — `source_map` → `bun_vfs` → `fallback_index` / `absent`
- Adapter + framework wire (`bun_vfs_dir`, expanded `.ts/.tsx/.jsx` collection)
- `js_structural_identifiers.py` — hints only
- Frozen Wave 3 report: `reports/js_oracle_ralph_tracked/wave3_ralph_report.json`
- Live Wave 4 report: `ralph_report.json` (recall 0.4, mode `source_map`)
- Honesty tests + operator-local Claude provenance doc

## What this is not

- Not `cli.js` 0.8+
- Not Anthropic IP in git
- Not “any `claude.exe` → full codebase”

## Next

Engine path toward 0.8 on an authorized large surface (or honest target redefinition + Sol GO). Stack on Wave 3 PR #134 as appropriate.
