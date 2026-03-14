---
name: codebase-cleaner
description: Cleanup worker for deleting AI slop, consolidating duplicates, and fixing imports. Never breaks tests.
---

# Codebase Cleaner

NOTE: Startup is handled by `worker-base`. This skill defines the WORK PROCEDURE for cleanup tasks.

## When to Use This Skill

Use for features that:
- Delete files or directories from the repository
- Consolidate duplicate modules into a single canonical location
- Remove shim/re-export directories
- Clean up documentation padding
- Update imports after moving or deleting files

NOT for: writing new features, TDD workflows, or fixing broken logic (use python-developer for those).

## Work Procedure

### 1. Baseline Verification
Before touching anything, run the test suite and record the baseline:
```
python -m pytest tests/unit/ tests/integration/ -n 4 --ignore=tests/performance --ignore=tests/poc -q
```
Record: X passed, Y failed. If Y > 0, stop and return to orchestrator — do not proceed with cleanup against a broken baseline.

### 2. Investigate Before Deleting
For each file or directory you plan to delete:
```
git ls-files <path>                                  # confirm it exists in git
rg 'from reveng\.<module>|import reveng\.<module>' src/ tests/ --type py  # find all importers
```
If importers exist, update them BEFORE deleting the source. Never delete a file that has live importers without first updating them.

### 3. The Cleanup Loop (repeat for each batch)
```
a) Update imports (if any) in dependent files
b) Run tests: python -m pytest tests/unit/ tests/integration/ -n 4 --ignore=tests/performance --ignore=tests/poc -q
   → Must pass with 0 failures before proceeding
c) git rm <files>  (use git rm, not plain rm, so deletions are staged)
d) Run tests again to confirm nothing broke
e) git commit -m "cleanup: <description of what was removed>"
```

Keep commits small and frequent. One commit per logical batch (e.g., "cleanup: delete all claude.md files").

### 4. Import Update Pattern
When moving a module from A to B, update all importers:
```python
# Before: from reveng.tools.ai import SomeClass
# After:  from reveng.agents.ai import SomeClass
```
Use `rg` to find every import site, then edit each file. After updating, run tests before deleting the original.

### 5. Directory Deletion
Only delete a directory when ALL its files have been removed:
```
git ls-files <dir/>  # must return empty before directory deletion
git rm -r <dir/>     # removes any remaining tracked files
```

### 6. Verification
After completing all work for the feature:
```
git ls-files | rg '<pattern>'  # confirm deletions took effect
python -m pytest tests/unit/ tests/integration/ -n 4 --ignore=tests/performance --ignore=tests/poc -q
git status  # must be clean after commit
```

### 7. Commit and Report
Single clean commit per feature (or small sequential commits). The handoff must include:
- Exact `git ls-files` commands used for verification
- Before/after file counts
- Test output confirming 0 failures

## Example Handoff

```json
{
  "salientSummary": "Deleted all 113 claude.md files with git rm. Test suite confirmed 0 regressions (307 passed, 0 failed). git ls-files | rg 'claude.md' | wc -l = 0.",
  "whatWasImplemented": "Ran `git ls-files | rg 'claude\\.md'` to enumerate all 113 AI context files, then `git rm` each in batches. Ran baseline tests before and after — no failures either time. Committed as a single cleanup commit.",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {
        "command": "git ls-files | rg 'claude\\.md' | wc -l",
        "exitCode": 0,
        "observation": "Confirmed 113 claude.md files in git index before deletion"
      },
      {
        "command": "python -m pytest tests/unit/ tests/integration/ -n 4 --ignore=tests/performance --ignore=tests/poc -q",
        "exitCode": 0,
        "observation": "307 passed, 0 failed, 93 skipped — baseline confirmed clean before deletion"
      },
      {
        "command": "git rm $(git ls-files | rg 'claude\\.md')",
        "exitCode": 0,
        "observation": "113 files staged for removal"
      },
      {
        "command": "python -m pytest tests/unit/ tests/integration/ -n 4 --ignore=tests/performance --ignore=tests/poc -q",
        "exitCode": 0,
        "observation": "307 passed, 0 failed — no regressions from deletion"
      },
      {
        "command": "git ls-files | rg 'claude\\.md' | wc -l",
        "exitCode": 0,
        "observation": "0 — all claude.md files removed from git index"
      }
    ]
  },
  "tests": {
    "added": [],
    "coverage": "No tests added — this is a deletion-only feature. Test suite verified before and after."
  },
  "discoveredIssues": []
}
```

## When to Return to Orchestrator

- Test baseline is already red before your cleanup starts
- An import you need to update is complex (circular imports, dynamic imports, `__all__` re-exports that span multiple levels)
- A directory you were asked to delete actually contains non-shim code that's still needed
- After a deletion, tests fail and you cannot determine which import is broken
