---
name: reveng-named-path-commit
description: >-
  Enforces named-path git staging on REVENG WSL/DrvFS dirty trees (L38/L49).
  Use when committing on reveng-main with other agents’ dirty files present,
  when tempted to git add -A / git add . / git stash across worktrees, when
  git status hangs on DrvFS, or when Windows Git Bash hooks need /c/Users/...
  Python via pwsh.exe.
---

# REVENG named-path commit (L38 / L49)

## Overview

On a shared dirty worktree, **only stage exact paths you intend to ship**. Bare
`git add -A` / `git add .` and cross-worktree `git stash` have deleted real work.

## Rules

1. **Stage by path only**
   ```bash
   git add -- path/one.py path/two.md
   ```
   Never: `git add -A`, `git add .`, `git add -u` without an explicit path list.

2. **Verify staged set BEFORE commit**
   ```bash
   git diff --cached --name-status
   ```
   Must equal the intended set. **Abort** if you see unexpected `D` / `A` / `M`.

3. **Windows hooks** — When pre-commit needs `/c/Users/.../python`, prefer
   Windows `pwsh.exe` + Windows git from the worktree. Do **not** `sudo` bind
   `/mnt/c` → `/c` (hangs). **REQUIRED SUB-SKILL:** `wsl-windows-git-hooks`.

4. **No `git stash` across worktrees** — stash refs are global. Isolate with
   named-path stage only; leave others’ files unstaged.

5. **Hung `git status` on DrvFS** — use a temp index if needed:
   ```bash
   export GIT_INDEX_FILE=$(mktemp)
   git read-tree HEAD
   git add -- <exact paths>
   git diff --cached --name-status
   # commit, then unset GIT_INDEX_FILE / remove temp
   ```
   Or use `bash scripts/git_status_scoped.sh` for scoped status.

## Pre-commit gate

```
- [ ] Intended paths listed explicitly
- [ ] git diff --cached --name-status == intended (no surprise D/A/M)
- [ ] No stash used to “clear the tree”
- [ ] If hooks need Windows Python → pwsh.exe path (not /c bind-mount)
```

## Anti-patterns

| Excuse | Reality |
|--------|---------|
| "`git add -A` then unstage theirs" | Easy to miss a `D`. Named-path only. |
| "Stash theirs, commit mine, pop" | Stash is global across worktrees — you can take another agent’s stash. |
| "Status hung, so commit blind" | Temp `GIT_INDEX_FILE` or scoped status first. |
| "Hooks hung — skip with --no-verify" | Use Windows pwsh git; don’t skip hooks. |

## Receipt (why this skill exists)

tip1 dirty-index accident deleted **macos-slim** + **MCP tests** from the index;
restored from the prior SHA. Named-path + cached name-status would have aborted.

## Cross-refs

- Sol tip loop: `reveng-sol-frozen-tip`
- Release honesty: `reveng-release-honesty`
- Pins: [references/pins.md](references/pins.md)
