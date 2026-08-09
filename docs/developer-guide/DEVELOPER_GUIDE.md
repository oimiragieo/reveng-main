# REVENG Developer Guide

> Prefer Diátaxis tracks for day-to-day work: [Engineer tutorials](../tutorials/engineer/01-dev-setup.md), [how-to/engineer](../how-to/engineer/extend-cli.md), [explanation](../explanation/architecture-overview.md), [reference](../reference/cli.md).

This page is a short contributor map. Dead paths from older docs are corrected below.

## Development setup

```bash
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
make install-dev
python -m pip install -e . --no-deps
```

Alternates: `pip install -r requirements.txt -r requirements-dev.txt -r requirements-java.txt` then editable `--no-deps`. See [Dev setup tutorial](../tutorials/engineer/01-dev-setup.md).

Optional: Ghidra for native decompile/recompile; Ollama or API keys for AI paths.

## Repository layout (current)

| Path | Role |
| --- | --- |
| `src/reveng/analysis/analyzer.py` | `REVENGAnalyzer` — **not** `src/reveng/analyzer.py` |
| `src/reveng/cli/` | CLI package — **not** `src/reveng/cli.py` |
| `src/reveng/api.py` / `src/reveng/ai_api.py` | Programmatic APIs |
| `src/reveng/app_reverse_engineering/` | App RE framework + adapters |
| `src/reveng/integrations/ghidra/` | Ghidra connectors |
| `src/reveng/pipeline/` and `src/reveng/pipelines/` | Permanent split — see [explanation](../explanation/pipeline-vs-pipelines.md) |
| `src/reveng/verification/` | VRL |
| `src/reveng/agent_sdk/` | MCP / skills |
| `tests/` | unit / integration / e2e / … |

## Entry points

```bash
reveng --help
python -m reveng --help
python src/reveng/cli/reveng.py --help
```

Do not build workflows around removed legacy launchers (no repo-root `reveng.py`).

## Architecture and lint

- Living overview: [explanation/architecture-overview.md](../explanation/architecture-overview.md)
- Contracts: `.importlinter` — `reveng.core` must not import higher domains; `reveng.security` must not import AI packages
- Run: `lint-imports --no-cache` and `make lint` (black/isort/pylint/mypy + import-linter + hadolint)

## Extending the product

1. Implement in the closest domain package (see import-linter).
2. Keep outputs contract-shaped (`reveng.core.result_contracts`).
3. Wire CLI / API / MCP only when user-facing; document maturity honestly.
4. Add tests before documenting behavior.

How-tos: [Extend CLI](../how-to/engineer/extend-cli.md) · [Add adapter](../how-to/engineer/add-adapter.md) · [Wire MCP tool](../how-to/engineer/wire-mcp-tool.md).

## Testing and honesty gates

```bash
make test-unit
python -m pytest -m "not requires_external_tools and not slow and not requires_network"
make lint
python3.9 scripts/verify_ga_readiness.py --profile baseline
python3.9 scripts/verify_ga_readiness.py --profile ga
```

Never trust verifier green alone — open tracked JSON. Details: [Unit & honesty gates](../tutorials/engineer/02-run-unit-and-honesty-gates.md) · [Corpus & GA scripts](../reference/corpus-and-ga-scripts.md).

POC suite remains optional (`tests/poc/`, markers `poc` / `requires_external_tools` / `slow`).

## Code style

- Black + isort at 100 columns; snake_case / PascalCase / UPPER_SNAKE_CASE
- Keep docs aligned with real commands from `src/reveng/cli/` and `docs/support_matrix.json`
- No invented success percentages; watermark experimental surfaces

## Contributing

Repository-wide process: [CONTRIBUTING.md](../../CONTRIBUTING.md). Release honesty: `.cursor/skills/reveng-release-honesty/SKILL.md` and [support/honesty-rules.md](../support/honesty-rules.md).
