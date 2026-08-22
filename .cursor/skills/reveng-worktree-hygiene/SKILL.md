---
name: reveng-worktree-hygiene
description: >-
  Prunes REVENG merged/prunable git worktrees and local feature branches without
  blind-merging unfinished work to main (L51/L52 companion). Use when cleaning
  .worktrees/, after Wave closeout, when git worktree list shows prunable tips,
  when tempted to merge foreign worktrees/PRs wholesale, or when disposing
  session temp thinktank/Sol artifacts on Windows.
---

# REVENG worktree hygiene (no blind-merge)

## Overview

A clean tree is a happy tree — **after** confirming tips are ancestors of
`main` (or intentionally abandoned). Blind-merge of every worktree/PR is
forbidden (Thinktank Option 1 / **L51**). Prefer `git worktree remove` +
`git worktree prune` over `rm -rf` (git-scm docs; Exa 2026-08-22).

## Protocol

1. **Inventory**
   ```bash
   git worktree list
   gh pr list --state open --limit 30
   ```
2. **Ancestor check before remove** (per worktree branch):
   ```bash
   git merge-base --is-ancestor <branch> main && echo MERGED
   ```
   - **MERGED** → safe to `git worktree remove --force <path>` then
     `git branch -d <branch>` (or `-D` if already gone remotely).
   - **NOT_MERGED** → do **not** merge to main from hygiene alone. Park,
     open a scoped PR, or leave until Thinktank/Sol wave. Never
     “merge everything even if not yours.”
3. **Remove + prune**
   ```bash
   git worktree remove --force <path>
   git worktree prune -v
   ```
   If the directory was deleted by hand first, `prune` alone clears
   `$GIT_DIR/worktrees` metadata.
4. **Merged local feature branches** (after fetch prune):
   ```bash
   git fetch --prune
   git branch -vv | findstr ": gone]"
   # delete only gone / ancestor-of-main feature refs — never main
   ```
5. **Open PRs**
   - Product waves: leave or close with reason; do not mass-merge.
   - Dependabot: leave open unless a wave scoped them — not “agent litter.”
6. **Windows thinktank temp** (**L52**)
   - Prefer `"C:\Program Files\Git\bin\bash.exe"` for `tt_council.sh`.
   - Clear `%TEMP%\tt_*` / `sol_*` / commit-msg temps with PowerShell
     `Remove-Item`, never WSL `rm -rf "$O"/*` with a mangled path.
7. **No stash** across worktrees (see `reveng-named-path-commit`).

## Anti-patterns

| Excuse | Reality |
|--------|---------|
| "User said clean everything — merge all worktrees to main" | Hygiene ≠ merge. Ancestor check first (**L51**). |
| "`rm -rf .worktrees/foo` is fine" | Prefer `worktree remove`; then `prune` if you already deleted. |
| "Close all Dependabot PRs to tidy" | Dep bumps are not stale agent worktrees; leave unless wave-scoped. |
| "WSL bash for tt_council out-dir clear" | **L52** — Git Bash or PowerShell `Remove-Item`. |

## Cross-refs

- `reveng-named-path-commit` (L38/L49/L56 staging)
- `reveng-sol-frozen-tip` / `reveng-release-honesty` (wave closeout)
- CEO: `docs/architecture/ceo-update-2026-08-21-wave10-closeout.md`
- Lessons: L51, L52, L54
