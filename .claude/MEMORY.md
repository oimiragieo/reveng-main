# REVENG agent memory (durable)

Cross-session facts for agents working in **reveng-main**. Keep terse; details live in linked docs.

## North star

- Product is **beta 4.0.0**; public **preview** — not full Scope C GA.
- Ops index: `/backlog.md` (root — not `docs/BACKLOG.md`)
- Latest CEO: `docs/architecture/ceo-update-2026-08-21-wave10-closeout.md` (Wave 10 **closed/merged**; plain English). Feature metrics: `ceo-update-2026-08-10-wave10.md`. R-RALPH-2 charter: `ceo-update-2026-08-09-wave3.md`.
- Junior docs ecosystem: Diátaxis dual doors in `docs/README.md` — `docs/support|tutorials|how-to|explanation|reference|ops`
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md` (**L1–L56**)
- Project skills: `.cursor/skills/` — `reveng-release-honesty`, `reveng-js-recovery-climb`, `reveng-sol-frozen-tip`, `reveng-named-path-commit`, `reveng-mcp-annotation-honesty`. Personal index: `~/.claude/skills/INDEX.md`. Workflows: `reveng-js-recovery-climb.md` · `reveng-wave-honesty-closeout.md`
- Wave B / Phase 5 honesty: `requirements-honesty.txt` (+ **pytest-cov**) + `pip install -e . --no-deps`; CI workflows use `python` not `/usr/bin/python3.9`

## Hard-won facts (through 2026-08-21 — Waves 0–2 honesty + Waves 7–10 JS climb + Wave 10 closeout)

- Use **python3.9** locally; avoid full-`git status` on dirty `reports/` — `scripts/git_status_scoped.sh` (DF-4 / **L38**). Temp `GIT_INDEX_FILE` / `git update-ref` when DrvFS hangs.
- Fixture ≠ capability; process `completed` ≠ native GA (**DF-5**).
- Evidence dir: exactly one stamp ≡ `latest.json`.
- **L25–L32:** unpushed main ≠ shipped; tool floor vs py3.9; Windows `\\` in JSON; honesty slim install; no fictional ghidramcp; merge-while-installing; Dependabot flood; Phase 5 `partial` authorized.
- **L33–L40:** Wave-scope not all-backlog; #101 disposition ≠ shipped; slim install needs pytest-cov; no hardcoded GHA python path; Sol process FAIL ≠ product FAIL; named-path git; CI FAIL is a snapshot; section E status column must parse cleanly.
- **L41–L48:** fail-first needs a new red token; soft-fail ≠ mitigated/done; Phase 4 honesty-go stays `partial`; pin research URLs; MCP hints = explicit denylist; macos slim keep matrix + pin black for 3.9; Sol FAIL+SHA tip debt; path-sep = assert hygiene / dead Task ≠ research done.
- **L49–L50:** always `git diff --cached --name-status` before commit on dirty DrvFS; merge bar = **honesty-unit + lint-python** (+ Sol PASS), not whole matrix.
- **L51–L56 (Wave 10 closeout 2026-08-21):** Thinktank before “finish everything” → close open wave (**L51**); Git Bash ≠ WSL bash for tt_council / rm (**L52**); Sol sandbox may block `git show` — inline packet OK (**L53**); Cursor Task quota death → parent tg/codex (**L54**); frozen tip2 proven tip1`fbc86c6e`→tip2`accf553a`→merge`82bc0ec3`→stamp`d3ac53ba` (**L55**); `git commit -F` over PS→bash heredoc (**L56**).
- **Frozen tip2 Sol (L47/L55):** tip1 lands content → tip2 pins tip1 SHA in verdict → Sol audits tip2 → PR comment → **NO post-Sol commit** → merge → post-merge SHA note separate. Skill: `.cursor/skills/reveng-sol-frozen-tip/`.
- **JS recovery Option C (Waves 7–10):** ship bar = unlockable/survivor **1.0** (**already met**); `oracle_coverage` aspirational; report BOTH (+ `recoverable_oracle_coverage` when tombstones run). Claude dogfood: oracle ~**57% (1087/1902)**; recoverable ~**82%**; **874** tombstones. PR #150 **merged** `82bc0ec3` (Sol PASS tip2 `accf553a`). Skill: `reveng-js-recovery-climb`.
- **100% ceiling:** full-oracle 100% on stale-map→SEA unique-token tombstones is **not honest**; same-era `.map` / embedded map can be 1.0; ~18% unique-residue climbable ≠ FP-free. Pretty close ≠ 100%.
- Research open: **R-RALPH-2**; **EDGE-RECOMPILE-DIFF-1**; **R-MCP-ANNOTATION-1** partial. Issue **#101** still **OPEN**.
- Fable/Sol via CLI; inline Sol packets; named-path git; no stash across worktrees. Thinktank on Windows: Git Bash (`tt_council.sh`).

## Open long poles

- RALPH-2 engine (R-RALPH-2) — needs research then Sol stop/go
- JS recovery ~18% unique-residue climb — Thinktank before Wave 11; not FP-free 100%
- M1-NATIVE-FAM / M1 — hermetic analyze + `required: true`
- M2 world-class hexyl (beyond timed probe)
- M4 full nightly/corpus residual; phases 6–13 await Sol stop/go
- #101 rich Capstone renderer; CI-DOCS-LINK-1 (partial); CI-UNICORN mitigated not angr-green
- Exploit expansion still gated (SEC = Docker-only preview)
