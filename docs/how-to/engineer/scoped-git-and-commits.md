# How to: scoped git status and commits

> **Maturity:** process guidance (**supported** as contributor practice)
>
> Parallel worktrees make shared `git stash` unsafe. Prefer named-path commits. See [honesty rules](../../support/honesty-rules.md) / AGENTS.md DF-4 notes.

## Why scoped status

A bare `git status` in this repo can hang or flood on generated trees (`reports/`, `analysis_*`, vendored Ghidra) over slow filesystems (e.g. DrvFS/WSL). Use the scoped helper instead.

## Scoped status

Script: `scripts/git_status_scoped.sh`

```bash
bash scripts/git_status_scoped.sh
```

It runs porcelain status with pathspec exclusions roughly equivalent to:

```bash
git status --porcelain -- \
  ':(exclude)reports/' \
  ':(exclude)analysis_*' \
  ':(exclude)external/ghidra*' \
  .
```

Use this before committing so you only review source you intend to stage.

## Named-path commits (no stash)

Worktrees share `.git` stash refs. **Do not `git stash`** to hide another agent’s edits.

To commit only your files:

```bash
git add path/to/file1 path/to/file2
git diff --cached --name-status   # must be exactly your set
git diff --name-only              # others remain unstaged
git commit -m "$(cat <<'EOF'
docs: explain your why here

EOF
)"
```

Never `git add -A` / `git add .` when the tree has unrelated agent WIP.

## Author identity from history (no `git config`)

Do not rewrite global/local git config in automation. For commits that need explicit author/committer (e.g. merges across agents), pass values from the latest commit:

```bash
name=$(git log -1 --format='%an')
email=$(git log -1 --format='%ae')
git -c user.name="$name" -c user.email="$email" commit ...
```

Same pattern for `git -c user.name=... -c user.email=... merge` when required by AGENTS.md.

## Hooks note (WSL)

Windows-authored hooks that hardcode a Windows Python path may fail under WSL — see skill `wsl-windows-git-hooks` if hooks misbehave. Do not use `--no-verify` unless explicitly requested.

## Checklist

- [ ] `bash scripts/git_status_scoped.sh` reviewed
- [ ] Only named paths staged
- [ ] No stash across worktrees
- [ ] Commit message Conventional Commit style used in this repo
- [ ] No secrets / `reports/` / analysis dumps committed

## Related

- Root `AGENTS.md` (DF-4, release honesty)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
- Contributor commands: `make test-unit`, `make lint`
