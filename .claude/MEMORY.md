# REVENG agent memory (durable)

Cross-session facts for agents working in **reveng-main**. Keep terse; details live in linked docs.

## North star

- Product is **beta 4.0.0**; public **preview** — not full Scope C GA.
- Ops index: `/backlog.md` (root — not `docs/BACKLOG.md`)
- Latest CEO: `docs/architecture/ceo-update-2026-08-09-waves1-2.md` (prior: `ceo-update-2026-08-09-wave0.md`)
- Junior docs ecosystem: Diátaxis dual doors in `docs/README.md` — `docs/support|tutorials|how-to|explanation|reference|ops`
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md` (**L1–L50**)
- Project skills: `.cursor/skills/` — `reveng-release-honesty`, `reveng-sol-frozen-tip`, `reveng-named-path-commit`, `reveng-mcp-annotation-honesty`. Personal index: `~/.claude/skills/INDEX.md`. Workflow: `~/.claude/workflows/reveng-wave-honesty-closeout.md`
- Wave B / Phase 5 honesty: `requirements-honesty.txt` (+ **pytest-cov**) + `pip install -e . --no-deps`; CI workflows use `python` not `/usr/bin/python3.9`

## Hard-won facts (through 2026-08-09 Waves 0–2 closeout)

- Use **python3.9** locally; avoid full-`git status` on dirty `reports/` — `scripts/git_status_scoped.sh` (DF-4 / **L38**). Temp `GIT_INDEX_FILE` / `git update-ref` when DrvFS hangs.
- Fixture ≠ capability; process `completed` ≠ native GA (**DF-5**).
- Evidence dir: exactly one stamp ≡ `latest.json`.
- **L25–L32:** unpushed main ≠ shipped; tool floor vs py3.9; Windows `\\` in JSON; honesty slim install; no fictional ghidramcp; merge-while-installing; Dependabot flood; Phase 5 `partial` authorized.
- **L33–L40:** Wave-scope not all-backlog; #101 disposition ≠ shipped; slim install needs pytest-cov; no hardcoded GHA python path; Sol process FAIL ≠ product FAIL; named-path git; CI FAIL is a snapshot; section E status column must parse cleanly.
- **L41–L48:** fail-first needs a new red token; soft-fail ≠ mitigated/done; Phase 4 honesty-go stays `partial`; pin research URLs; MCP hints = explicit denylist; macos slim keep matrix + pin black for 3.9; Sol FAIL+SHA tip debt; path-sep = assert hygiene / dead Task ≠ research done.
- **L49–L50 (closeout):** always `git diff --cached --name-status` before commit on dirty DrvFS (tip1 nearly wiped Wave 2); merge bar = **honesty-unit + lint-python** (+ Sol PASS), not whole matrix — docs-link/unit fixture soft-reds stay L42 unless wave-scoped.
- **Frozen tip2 Sol (L47):** tip1 lands content → tip2 pins tip1 SHA in verdict → Sol audits tip2 → PR comment → **NO post-Sol commit** → merge → post-merge SHA note separate. Skill: `.cursor/skills/reveng-sol-frozen-tip/`.
- Research open: **R-RALPH-2**; **EDGE-RECOMPILE-DIFF-1**; **R-MCP-ANNOTATION-1** partial (denylist only). Wave 0 **merged** (PR #131). Wave 1 **merged** (PR #132 → `41add7d1`). Wave 2 **MERGED** (PR #133 → `1eff22f8`; post-merge docs `00e9f65b`). Sol PASS_WITH_NITS on tip `34d5b99d`; Thinktank APPROVE_WITH_NITS. Issue **#101** still **OPEN**. Dogfood 135 passed.
- Fable/Sol via CLI; inline Sol packets; `git -c user.name/email` from `git log -1`; no stash across worktrees. WSL→Windows pwsh git when hooks need `/c/Users` python (`wsl-windows-git-hooks`).
- Cursor Task quota can exhaust — prefer `codex exec` / `claude -p` / parent tg over waiting on dead Tasks. Exa MCP often down → WebSearch + L44 URL pins.

## Open long poles

- RALPH-2 engine (R-RALPH-2) — needs research then Sol stop/go
- M1-NATIVE-FAM / M1 — hermetic analyze + `required: true`
- M2 world-class hexyl (beyond timed probe)
- M4 full nightly/corpus residual; phases 6–13 await Sol stop/go
- #101 rich Capstone renderer; CI-DOCS-LINK-1 (partial); CI-UNICORN mitigated not angr-green
- D1–D6 deferred tg-audit items; Docker Hub secrets / docs DNS ops
- Exploit expansion still gated (SEC = Docker-only preview)
