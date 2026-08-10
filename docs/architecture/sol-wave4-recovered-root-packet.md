# Sol audit packet — Wave 4 JS recovered-root

**Branch:** `feat/wave4-js-recovered-root`  
**Plan:** `docs/superpowers/plans/2026-08-09-wave4-js-recovered-root-naming.md`  
**Base:** Wave 3 tip `90de9d1c` (PR #134)

## Must verify

1. Tracked Ralph `ralph_report.json`: `best_project_file_recall` **> 0**, notes include `materialization_mode:source_map`, **no** `no_recovered_root`.
2. `wave3_ralph_report.json` frozen at recall **0.0** with `no_recovered_root`.
3. Mismatch control documents treatment > mismatch.
4. Hints JSON path exists in code; **no** regex rewrite of sources.
5. Backlog `R-RALPH-2` status remains **open**; no enterprise GA / Phase 6 complete claims.
6. Honesty tests green: `test_wave4_recovered_root_honesty.py` + `test_wave3_r_ralph2_rebaseline_honesty.py` + materialize/hints units.
7. No Anthropic recovered trees committed.

## Verdict file

`docs/architecture/sol-wave4-recovered-root-verdict.md` — tip1 stub `Reviewed HEAD SHA: TBD`; tip2 pins tip1 SHA.
