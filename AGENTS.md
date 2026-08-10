# Repository Guidelines

## Release honesty (read first for GA / ship claims)

- Living ops index: root `backlog.md` (not `docs/BACKLOG.md`). Latest CEO: `docs/architecture/ceo-update-2026-08-09-wave6.md` (Wave 5 fingerprint attribution — **not** exe decode / Phase 6 / enterprise GA; Wave 4: `ceo-update-2026-08-09-wave4.md`).
- Lessons: `docs/architecture/lessons-learned-scope-c-2026-08.md` (**L1–L50**). Wave B: `docs/architecture/wave-b-exit-criteria.md`.
- **Project skills** (`.cursor/skills/`): `reveng-release-honesty`, `reveng-sol-frozen-tip`, `reveng-named-path-commit`, `reveng-mcp-annotation-honesty`. Personal skill index: `~/.claude/skills/INDEX.md`. Wave closeout workflow: `~/.claude/workflows/reveng-wave-honesty-closeout.md`. Agent memory: `.claude/MEMORY.md`.
- **Junior docs:** start at `docs/README.md` (Analyst + Engineer Diátaxis tracks). Customer boundary: `docs/support/support-matrix.md` + `docs/support_matrix.json`. Ops/CEO packets are not product tutorials (`docs/ops/README.md`).
- **Never trust a green GA verifier alone** — open tracked JSON and confirm evidence fields (baseline **and** ga profiles).
- **Fixture ≠ capability**; process `completed` ≠ native GA (DF-5). Probe: `tool_absent` ≠ research done. #101 disposition ≠ renderer shipped (L34).
- **Honesty CI / merge bar:** `requirements-honesty.txt` (**include pytest-cov** if using `--no-cov`, L35) + `pip install -e . --no-deps` (L28). Wave closeout merges on **honesty-unit + lint-python** (+ Sol PASS), not the whole matrix — docs-link/unit fixture soft-reds stay L42 unless wave-scoped (L50). Workflows use `python`, not hardcoded `/usr/bin/python3.9` (L36). Soft-fail ≠ mitigated/done (L42).
- **Do not pin `ghidramcp>=0.1.0`** — not on PyPI (L29). Prefer Ghidra fallback.
- Prefer `/usr/bin/python3.9` locally. Use `scripts/git_status_scoped.sh` / named-path commits (DF-4 / L38). **Always** print `git diff --cached --name-status` before commit on dirty DrvFS and refuse unexpected deletes/adds (L49). No `git stash` across worktrees; merges need `git -c user.name/email` from `git log -1`. Temp `GIT_INDEX_FILE` if DrvFS status hangs. WSL→Windows **pwsh** git when hooks need `/c/Users/...` python — see `~/.claude/skills/wsl-windows-git-hooks/SKILL.md` (do not sudo-mount `/c`).
- Plan/validate: Fable = `claude -p --model claude-fable-5`; Sol = `codex exec --model gpt-5.6-sol` (inline packets if sandbox greps hang). Wave-scope only — “close all backlog” is REJECT (L33). **Frozen tip2 Sol (L47):** tip1 content → tip2 pins tip1 SHA → Sol audits tip2 → PR comment → no post-Sol commit → merge. Early CI FAIL is a snapshot (L39); MCP hints = denylist not all-high (L45).

## Code navigation (tensor-grep / `tg`)

Prefer **tensor-grep (`tg`)** over ad hoc ripgrep loops when editing this repo — especially shared honesty/grade/CLI/MCP surfaces (`result_contracts`, VRL gates, `verify_ga_readiness`, adapters).

- Orient / edit readiness: `tg prepare src/ "task" --json` (or scoped `src/reveng/<pkg>`)
- Impact before change: `tg callers src/ SYMBOL --json`, `tg blast-radius src/ SYMBOL --json`
- Vocabulary search: `tg find "intent" src/ --deadline 20 --json`
- Multi-agent: `tg ledger claim|list|release` (one store per git repo / worktree-aware)
- LSP: `tg lsp --provider hybrid` (or `native` / `lsp`); `tg doctor --with-lsp` for provider health — availability ≠ navigation proof
- Path-first args: `tg <cmd> <PATH> <SYMBOL_OR_QUERY>`; always pass an explicit PATH (bare multi-project root search is refused)

`tg` is for navigating/evolving the REVENG **source tree**, not a substitute for binary analysis / VRL / Ghidra on subject binaries.

## Project Structure & Module Organization
Primary code lives in `src/reveng/`. Add new runtime code to the closest domain package instead of creating new root scripts (there is **no** repo-root `reveng.py` — it was removed because it shadowed the package; use the `reveng` / `python -m reveng` entry points or `src/reveng/cli/reveng.py`). Key packages:
- `reveng.core` — foundation layer (exceptions, error codes, validation, config, `result_contracts`, `ir`, `ai_models`); must not import higher-level domains.
- `reveng.analysis` — binary/source analysis (`analyzer`, `pe`, `native`, `lifting`, `devirtualization`, `deobfuscation`, `diffing`, `analyzers`).
- `reveng.cli` (a package), `reveng.agents.ai` (LLM providers), `reveng.security`, `reveng.verification` (VRL), `reveng.app_reverse_engineering`, `reveng.agent_sdk` (MCP), `reveng.tools`, `reveng.integrations`/`ghidra`.

These boundaries are enforced by **import-linter** (`.importlinter`): `reveng.core` must not import higher domains, and `reveng.security` must not import `reveng.ai`/`reveng.agents.ai`. New code that violates a contract fails `make lint`. Tests are split by intent under `tests/unit`, `tests/integration`, `tests/e2e`, `tests/performance`, `tests/poc`, `tests/security`, and `tests/manual`. Keep examples in `examples/`, documentation in `docs/`, sample inputs in `test_samples/`, and third-party integrations in `external/`. Generated outputs in `analysis_*` and `reports/` are not the place for new source code.

## Build, Test, and Development Commands
Use `make install-dev` for the full local toolchain, or install directly with `pip install -r requirements.txt -r requirements-dev.txt -r requirements-java.txt`. Also run `pip install -e . --no-deps` (editable install) — import-linter/grimp need the `reveng` package resolvable as a top-level package. Run `reveng --help` (or `python -m reveng --help`) as a quick CLI smoke test. Common commands:

- `make test-unit` or `pytest tests/unit -v`
- `make test-integration` or `pytest tests/integration -v`
- `pytest -m "not requires_external_tools and not slow"`
- `make lint` (black/isort/pylint/mypy + `lint-imports` architecture contracts + hadolint)
- `lint-imports --no-cache` (run the `.importlinter` architecture contracts on their own)
- `make format`
- `python -m build`
- `mkdocs build`

## Coding Style & Naming Conventions
Follow `.editorconfig`: spaces everywhere, 4-space indents for Python, 2 for YAML/JSON. Format Python with Black and isort using a 100-character line limit. Lint with `pylint`, type-check with `mypy`, and run `pre-commit run --all-files` before opening a PR. Use `snake_case` for modules, functions, and variables, `PascalCase` for classes, and `UPPER_SNAKE_CASE` for constants.

## Testing Guidelines
Pytest is the test runner; `pytest-cov` reports coverage for `src/`. There is no enforced `fail-under`, so keep coverage steady or better in touched areas and add regression tests for every bug fix. Name files `test_*.py`, classes `Test*`, and functions `test_*`. Gate environment-heavy coverage with markers from `pytest.ini`, especially `integration`, `e2e`, `performance`, `poc`, `requires_external_tools`, and `requires_network`.

## Commit & Pull Request Guidelines
Recent history follows Conventional Commit style with optional scopes, for example `docs: ...`, `cleanup: ...`, `chore(validation): ...`, and `test(quality): ...`. Keep subjects imperative and specific. PRs should explain the problem, summarize the approach, link related issues, and list exact validation commands run. Include sample CLI output or screenshots only when behavior or documentation changes need them.

## Security & Configuration Tips
Do not commit secrets, local MCP credentials, large binaries, or generated analysis artifacts. Start from `mcp-config.example.json` for local config. Pre-commit blocks oversized files, so keep fixtures small and place reusable samples in `test_samples/` or `examples/test-samples/`.
