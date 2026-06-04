# `claude.md` — REVENG master index (AI navigation)

This file is the **entry point** for large language models mapping the repository. Each major folder also contains a `claude.md` that lists local files and (for Python) top-level symbols.

## How to use

1. Start at the area below that matches your task (CLI, tests, docs, etc.).
2. Open the linked `claude.md` in that folder, then drill into subfolders.
3. Regenerate machine-derived breadcrumbs after large refactors: `python scripts/generate_claude_md_index.py`.

## Repository map

| Area | Role | Breadcrumb |
|------|------|--------------|
| `src/reveng/` | Core Python package (analyzers, CLI, tools, MCP) | [`src/reveng/claude.md`](src/reveng/claude.md) |
| `src/` | Source tree wrapper | [`src/claude.md`](src/claude.md) |
| `tests/` | Pytest suites | [`tests/claude.md`](tests/claude.md) |
| `docs/` | MkDocs / architecture / API docs | [`docs/claude.md`](docs/claude.md) |
| `examples/` | Demos and use-case writeups | [`examples/claude.md`](examples/claude.md) |
| `scripts/` | Repo maintenance scripts | [`scripts/claude.md`](scripts/claude.md) |
| `.github/` | CI workflows and templates | [`.github/claude.md`](.github/claude.md) |
| `test_samples/` | Small fixtures for tests | [`test_samples/claude.md`](test_samples/claude.md) |
| `AGENTS.md` | Contributor conventions | [`AGENTS.md`](AGENTS.md) |

## `src/reveng` — grouped `claude.md` index

### `agent_sdk`

- [`agent_sdk/claude.md`](src/reveng/agent_sdk/claude.md)
- [`agent_sdk/mcp/claude.md`](src/reveng/agent_sdk/mcp/claude.md)
- [`agent_sdk/mcp/servers/claude.md`](src/reveng/agent_sdk/mcp/servers/claude.md)
- [`agent_sdk/skills/builtin/claude.md`](src/reveng/agent_sdk/skills/builtin/claude.md)
- [`agent_sdk/skills/claude.md`](src/reveng/agent_sdk/skills/claude.md)
- [`agent_sdk/tools/claude.md`](src/reveng/agent_sdk/tools/claude.md)
- [`agent_sdk/tools/reveng/claude.md`](src/reveng/agent_sdk/tools/reveng/claude.md)

### `agents`

- [`agents/ai/ai_enhanced/claude.md`](src/reveng/agents/ai/ai_enhanced/claude.md)
- [`agents/ai/claude.md`](src/reveng/agents/ai/claude.md)
- [`agents/claude.md`](src/reveng/agents/claude.md)

### `ai`

- [`ai/claude.md`](src/reveng/ai/claude.md)

### `analysis`

- [`analysis/analyzers/claude.md`](src/reveng/analysis/analyzers/claude.md)
- [`analysis/claude.md`](src/reveng/analysis/claude.md)
- [`analysis/deobfuscation/claude.md`](src/reveng/analysis/deobfuscation/claude.md)
- [`analysis/devirtualization/claude.md`](src/reveng/analysis/devirtualization/claude.md)
- [`analysis/diffing/claude.md`](src/reveng/analysis/diffing/claude.md)
- [`analysis/lifting/claude.md`](src/reveng/analysis/lifting/claude.md)
- [`analysis/native/claude.md`](src/reveng/analysis/native/claude.md)
- [`analysis/pe/claude.md`](src/reveng/analysis/pe/claude.md)

### `app_reverse_engineering`

- [`app_reverse_engineering/adapters/claude.md`](src/reveng/app_reverse_engineering/adapters/claude.md)
- [`app_reverse_engineering/claude.md`](src/reveng/app_reverse_engineering/claude.md)

### `cli`

- [`cli/claude.md`](src/reveng/cli/claude.md)

### `cloud`

- [`cloud/claude.md`](src/reveng/cloud/claude.md)

### `compilation`

- [`compilation/claude.md`](src/reveng/compilation/claude.md)

### `core`

- [`core/claude.md`](src/reveng/core/claude.md)

### `evasion`

- [`evasion/claude.md`](src/reveng/evasion/claude.md)

### `exploits`

- [`exploits/claude.md`](src/reveng/exploits/claude.md)

### `ghidra`

- [`ghidra/claude.md`](src/reveng/ghidra/claude.md)

### `hardware`

- [`hardware/claude.md`](src/reveng/hardware/claude.md)

### `installers`

- [`installers/claude.md`](src/reveng/installers/claude.md)

### `instrumentation`

- [`instrumentation/claude.md`](src/reveng/instrumentation/claude.md)

### `integrations`

- [`integrations/claude.md`](src/reveng/integrations/claude.md)
- [`integrations/ghidra/claude.md`](src/reveng/integrations/ghidra/claude.md)

### `javascript`

- [`javascript/claude.md`](src/reveng/javascript/claude.md)

### `malware`

- [`malware/claude.md`](src/reveng/malware/claude.md)

### `ml`

- [`ml/claude.md`](src/reveng/ml/claude.md)

### `performance`

- [`performance/claude.md`](src/reveng/performance/claude.md)

### `pipeline`

- [`pipeline/claude.md`](src/reveng/pipeline/claude.md)
- [`pipeline/steps/claude.md`](src/reveng/pipeline/steps/claude.md)

### `pipelines`

- [`pipelines/claude.md`](src/reveng/pipelines/claude.md)

### `plugins`

- [`plugins/ai/claude.md`](src/reveng/plugins/ai/claude.md)
- [`plugins/analysis/claude.md`](src/reveng/plugins/analysis/claude.md)
- [`plugins/claude.md`](src/reveng/plugins/claude.md)
- [`plugins/security/claude.md`](src/reveng/plugins/security/claude.md)
- [`plugins/visualization/claude.md`](src/reveng/plugins/visualization/claude.md)

### `protocol`

- [`protocol/claude.md`](src/reveng/protocol/claude.md)

### `reporting`

- [`reporting/claude.md`](src/reveng/reporting/claude.md)
- [`reporting/visualization/claude.md`](src/reveng/reporting/visualization/claude.md)

### `security`

- [`security/claude.md`](src/reveng/security/claude.md)

### `server`

- [`server/claude.md`](src/reveng/server/claude.md)

### `tools`

- [`tools/anti_analysis/claude.md`](src/reveng/tools/anti_analysis/claude.md)
- [`tools/binary/claude.md`](src/reveng/tools/binary/claude.md)
- [`tools/claude.md`](src/reveng/tools/claude.md)
- [`tools/config/claude.md`](src/reveng/tools/config/claude.md)
- [`tools/core/claude.md`](src/reveng/tools/core/claude.md)
- [`tools/decompilers/claude.md`](src/reveng/tools/decompilers/claude.md)
- [`tools/diffing/claude.md`](src/reveng/tools/diffing/claude.md)
- [`tools/enterprise/claude.md`](src/reveng/tools/enterprise/claude.md)
- [`tools/languages/claude.md`](src/reveng/tools/languages/claude.md)
- [`tools/quality/claude.md`](src/reveng/tools/quality/claude.md)
- [`tools/threat_intel/claude.md`](src/reveng/tools/threat_intel/claude.md)
- [`tools/translation/claude.md`](src/reveng/tools/translation/claude.md)
- [`tools/utils/claude.md`](src/reveng/tools/utils/claude.md)

### `utils`

- [`utils/claude.md`](src/reveng/utils/claude.md)

### `validation`

- [`validation/claude.md`](src/reveng/validation/claude.md)

### `verification`

- [`verification/claude.md`](src/reveng/verification/claude.md)
- [`verification/differential/claude.md`](src/reveng/verification/differential/claude.md)
- [`verification/refinement/claude.md`](src/reveng/verification/refinement/claude.md)
- [`verification/symbolic/claude.md`](src/reveng/verification/symbolic/claude.md)

### `(package root)`

- [`claude.md`](src/reveng/claude.md)

## `tests` — `claude.md` index

- [`tests/claude.md`](tests/claude.md)
- [`tests/e2e/claude.md`](tests/e2e/claude.md)
- [`tests/integration/claude.md`](tests/integration/claude.md)
- [`tests/integration/test_tools/claude.md`](tests/integration/test_tools/claude.md)
- [`tests/integration/test_web/claude.md`](tests/integration/test_web/claude.md)
- [`tests/manual/claude.md`](tests/manual/claude.md)
- [`tests/performance/claude.md`](tests/performance/claude.md)
- [`tests/poc/claude.md`](tests/poc/claude.md)
- [`tests/security/claude.md`](tests/security/claude.md)
- [`tests/unit/claude.md`](tests/unit/claude.md)

## `docs` — `claude.md` index

- [`docs/api/claude.md`](docs/api/claude.md)
- [`docs/architecture/claude.md`](docs/architecture/claude.md)
- [`docs/changelogs/claude.md`](docs/changelogs/claude.md)
- [`docs/claude.md`](docs/claude.md)
- [`docs/deployment/claude.md`](docs/deployment/claude.md)
- [`docs/developer-guide/claude.md`](docs/developer-guide/claude.md)
- [`docs/getting-started/claude.md`](docs/getting-started/claude.md)
- [`docs/legal/claude.md`](docs/legal/claude.md)
- [`docs/mcp/claude.md`](docs/mcp/claude.md)
- [`docs/user-guide/claude.md`](docs/user-guide/claude.md)

## `examples` — `claude.md` index

- [`examples/advanced/claude.md`](examples/advanced/claude.md)
- [`examples/basic/claude.md`](examples/basic/claude.md)
- [`examples/claude.md`](examples/claude.md)
- [`examples/test-samples/claude.md`](examples/test-samples/claude.md)
- [`examples/use-cases/claude.md`](examples/use-cases/claude.md)
- [`examples/use-cases/js-oracle-ralph/claude.md`](examples/use-cases/js-oracle-ralph/claude.md)

## `.github` — `claude.md` index

- [`.github/claude.md`](.github/claude.md)
- [`.github/ISSUE_TEMPLATE/claude.md`](.github/ISSUE_TEMPLATE/claude.md)
- [`.github/workflows/claude.md`](.github/workflows/claude.md)

## `test_samples`

- [`test_samples/claude.md`](test_samples/claude.md)

---
Human-oriented contributor guide: **`AGENTS.md`**. Generated breadcrumbs: run `python scripts/generate_claude_md_index.py`.
