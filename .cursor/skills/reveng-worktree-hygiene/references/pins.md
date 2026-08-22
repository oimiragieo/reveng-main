# REVENG worktree hygiene — pins

Accessed 2026-08-22 via Exa:

- git-scm `git worktree` docs — prefer `worktree remove` then `worktree prune`;
  `rm -rf` leaves `$GIT_DIR/worktrees` metadata until prune.
  https://git-scm.com/docs/git-worktree
- Bulk stale worktree cleanup pattern (ancestor / remote-gone checks; force remove
  when remote branch deleted): https://brtkwr.com/posts/2026-03-06-bulk-cleaning-stale-git-worktrees/

REVENG rule overlay: never blind-merge NOT_MERGED tips to main (L51).
Windows thinktank: Git Bash ≠ WSL bash (L52).
