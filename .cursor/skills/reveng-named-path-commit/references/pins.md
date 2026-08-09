# Research pins — named-path commit / worktrees

Accessed / cited from REVENG Wave 2 closeout session **2026-08-09**.

## Named-path / staged-diff agent git

- Exact-path staging + inspect staged set before commit when agents share dirty trees.
- https://nat.io/blog/git-worktrees-commit-hooks-agentic-coding

## Worktree no-stash

- `git stash` is **global across worktrees** (shared `.git` stash refs). One agent’s
  `stash pop` can apply another agent’s WIP and conflict files that agent never touched.
- Prefer: `git add -- <only-my-paths>` then commit; verify with
  `git diff --cached --name-status` (yours) beside `git diff --name-only` (theirs).

## Unicorn / macOS cmake (related Wave 2 pin)

- macOS slim / unicorn-engine cmake issues stay matrix-aware; do not “fix” by
  deleting CI legs.
- https://github.com/unicorn-engine/unicorn/issues/2263

## Agent Skills spec

- https://agentskills.io/specification
