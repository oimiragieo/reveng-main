# Repository Guidelines

## Release honesty (read first for GA / ship claims)

- Living ops index: root `backlog.md`. Latest CEO briefing: `docs/architecture/ceo-update-2026-08-06.md`.
- Lessons from Scope C 2026-08: `docs/architecture/lessons-learned-scope-c-2026-08.md`.
- Cursor skill: `.cursor/skills/reveng-release-honesty/SKILL.md`. Agent memory: `.claude/MEMORY.md`.
- **Never trust a green GA verifier alone** — open tracked `reports/*.json` / `.reveng/*.json` and confirm analyze/recompile evidence fields.
- Prefer `/usr/bin/python3.9` for local gates on this host. Stage **named paths** for git commits when `reports/` is dirty (full `git status` can hang on WSL/DrvFS).

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
