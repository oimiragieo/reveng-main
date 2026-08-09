# Architecture Overview (short)

> **Living overview:** [docs/explanation/architecture-overview.md](../explanation/architecture-overview.md)
>
> Maturity: preview overall · match [support matrix](../support/support-matrix.md)

REVENG is a Python package (`src/reveng/`) exposed through three surfaces: CLI (`reveng.cli`), Python API (`reveng.api`), and MCP (`reveng.agent_sdk.mcp.servers`).

## Real entry points

| Path | Role |
| --- | --- |
| `src/reveng/cli/` | CLI package (`create_parser`, handlers); console → `reveng.cli:main` |
| `src/reveng/cli/reveng.py` | Source-tree wrapper |
| `src/reveng/analysis/analyzer.py` | `REVENGAnalyzer` (**not** `src/reveng/analyzer.py`) |
| `src/reveng/api.py` | `REVENGAPI` |
| `src/reveng/ai_api.py` | AI-oriented helpers |
| `src/reveng/agent_sdk/mcp/` | MCP servers |
| `src/reveng/app_reverse_engineering/` | Supported multi-language app RE |

Domain boundaries are enforced by **import-linter** (`.importlinter`): `reveng.core` is foundation-only; `reveng.security` must not import `reveng.ai` / `reveng.agents.ai`.

For package map, VRL, Ghidra boundary, and mermaid diagrams, use the [living architecture overview](../explanation/architecture-overview.md). Contributor layout: [Developer guide](../developer-guide/DEVELOPER_GUIDE.md) and [Engineer tutorials](../tutorials/engineer/01-dev-setup.md).
