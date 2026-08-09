# Research pins — Sol frozen tip / agent git

Accessed / cited from REVENG Wave 2 closeout session **2026-08-09**.

## Agent Skills spec

- Name + description required; progressive disclosure (load SKILL.md first, then references).
- Spec: https://agentskills.io/specification

## Named-path / staged-diff agent git

- Prefer exact-path staging and inspect staged diff before commit when agents share a dirty tree.
- https://nat.io/blog/git-worktrees-commit-hooks-agentic-coding

## Worktree no-stash

- `git stash` is **global across worktrees** (shared `.git` stash refs). Parallel agents can pop each other’s work. Prefer named-path `git add` + leave others’ dirty files unstaged; revert with `git checkout -- <file>` or a patch file — never stash to “isolate” commits.

## Related REVENG lessons

- L47 — Sol tip SHA discipline (this skill)
- L37 — don’t merge on self-PASS
- L38 / L49 — named-path commits on WSL/DrvFS dirty trees (`reveng-named-path-commit`)
