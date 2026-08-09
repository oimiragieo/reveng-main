# Policy — REV-P0-ANALYSIS-CLEANUP (Wave 1)

**Status:** `partial` — written policy only. Automated enforcement / CI scavenger not claimed.

## Rules

1. **Never** `git clean` or mass-delete untracked `analysis_*` / `reports/` trees without explicit operator permission.
2. CI must not upload secrets or local analysis dumps from `analysis_*` as artifacts.
3. Local dogfood should prefer `/tmp` or gitignored paths over writing under the repo root.
4. Agents use **named-path** git (`git add <paths>`) and scoped status scripts — full `git status` on dirty DrvFS trees is a known hang (DF-4 / L38).
5. Generated breadcrumbs under `analysis_*/` are not source; do not lint or treat as product evidence.

## Enforcement (open)

Future work may add a CI guard that fails if tracked files appear under `analysis_*/`. Not Wave 1.
