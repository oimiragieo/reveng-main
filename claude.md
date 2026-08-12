# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. The hand-written guidance below is emitted by `scripts/generate_claude_md_index.py`; the machine-derived navigation index follows it.

REVENG is a large, beta Python reverse-engineering platform (`reveng`, version `4.0.0`). Real core: the CLI, MCP servers, Ghidra integration, the app reverse-engineering adapters, and the Verified Recompilation Loop (VRL). Treat advanced claims (exploit gen, full binary↔source equivalence, broad JS deobfuscation) as experimental until verified on a tracked corpus. Keep behavior changes tied to tests.

## Commands

`src/` layout (`src/reveng/`), Python 3.9+. Config in `pyproject.toml`; task shortcuts in the `Makefile`; contributor conventions in `AGENTS.md`.

```bash
make install-dev                 # runtime + dev + java deps
pip install -e . --no-deps       # editable install (required for import-linter / grimp)

# Entry points (there is NO repo-root reveng.py; that launcher was removed):
reveng --help                    # main CLI            (reveng.cli:main)
reveng-app --help                # app reverse-eng     (reveng.app_reverse_engineering.cli)
reveng-js --help                 # JS analysis         (reveng.javascript.cli)
python -m reveng --help          # module entry        (reveng.__main__)
python src/reveng/cli/reveng.py --help   # source-tree wrapper (self-bootstraps sys.path)

# Tests (coverage auto-added via pyproject addopts; use --no-cov to skip)
make test                        # full suite
pytest tests/unit/test_foo.py::TestX::test_y      # a single test
pytest -m "not requires_external_tools and not slow and not requires_network"
# Markers: poc, slow, integration, unit, requires_external_tools, requires_network

# Lint / format (black & isort at 100 cols)
make format                      # black + isort (writes)
make lint                        # black/isort/pylint/mypy + lint-imports (architecture) + hadolint
lint-imports --no-cache          # import-linter architecture contracts (.importlinter)
```

## Architecture (the big picture)

**Three surfaces over one package.** Analysis logic is exposed through (a) the CLI (`reveng.cli`, plus `reveng-app`/`reveng-js`), (b) a Python API (`reveng.api`), and (c) MCP servers (`reveng.agent_sdk.mcp.servers`). Outputs carry versioned validation/evidence/provenance contracts (`reveng.core.result_contracts`).

**Domain layout (enforced by import-linter; see `.importlinter`):**

- `reveng.core` — foundation layer: exceptions, error codes, validation, config, the shared `result_contracts`, the `ir` (VRL IR), and `ai_models` (shared AI data models). Must not import any higher-level domain (the `core-is-foundation` contract).
- `reveng.analysis` — binary/source analysis: `analyzer` (REVENGAnalyzer), `pe`, `native`, `lifting`, `devirtualization`, `deobfuscation`, `diffing`, `analyzers`.
- `reveng.cli` — a real package (was a 1900-line `cli.py`); `reveng.cli:main` is the console entry; `cli/reveng.py` is the source-tree wrapper.
- `reveng.security` must not import `reveng.ai`/`reveng.agents.ai` (the cycle was broken by moving shared models to `reveng.core.ai_models`; enforced contract).
- AI providers live in `reveng.agents.ai` (`ai_provider_registry` → `get_analyzer`, `anthropic`/`openai`/`ollama`/`claude_cli` analyzers, `ai_enhanced_orchestrator`).

**Verified Recompilation Loop (VRL) — the flagship.** `reveng.verification.refinement.refiner.IterativeRefiner` drives decompile → compile → differentially-verify → LLM-refine to convergence. It is dependency-injected (analyzer / compile_fn / oracle_factory). The differential oracle passes corpus seed tokens as **argv** (not stdin) and records a real `ValidationGrade` into `.reveng/benchmarks/corpus.yaml`. Runner: `scripts/run_vrl.py` (`REVENG_AI_PROVIDER`=ollama|anthropic|openai; ollama is local/free).

**App reverse-engineering** (`reveng.app_reverse_engineering`) dispatches JS/JVM/Python/.NET inputs to language adapters; it is the corpus-gated, most mature multi-language path.

**Generated/vendored, do not edit or lint:** `analysis_*/`, `reports/`, `external/ghidra*/`. Regenerate these breadcrumbs after refactors: `python scripts/generate_claude_md_index.py`.

## Agent skills & honesty

Contributor conventions and release honesty: **`AGENTS.md`**. Durable cross-session facts: **`.claude/MEMORY.md`**. Project Cursor skills live under **`.cursor/skills/`** (`reveng-release-honesty`, `reveng-js-recovery-climb`, `reveng-sol-frozen-tip`, `reveng-named-path-commit`, `reveng-mcp-annotation-honesty`); personal index: `~/.claude/skills/INDEX.md`. Workflows: `~/.claude/workflows/reveng-js-recovery-climb.md` (Option C JS climb) · `~/.claude/workflows/reveng-wave-honesty-closeout.md` (honesty waves). Lessons **L1–L50** in `docs/architecture/lessons-learned-scope-c-2026-08.md`. Latest CEO: `docs/architecture/ceo-update-2026-08-10-wave10.md` (JS climb Option C; unlockable 100% ship bar already met; full-oracle 100% on SEA tombstones not honest — see `reveng-js-recovery-climb`; honesty Waves 0–2 merged 2026-08-09).

## Navigation index

Each major folder also contains a `claude.md` listing its files and (for Python) top-level symbols. Start at the area below that matches your task, then drill into subfolders.

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
- [`app_reverse_engineering/js_recovery_toolkit/claude.md`](src/reveng/app_reverse_engineering/js_recovery_toolkit/claude.md)

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
- [`docs/explanation/claude.md`](docs/explanation/claude.md)
- [`docs/getting-started/claude.md`](docs/getting-started/claude.md)
- [`docs/how-to/analyst/claude.md`](docs/how-to/analyst/claude.md)
- [`docs/how-to/claude.md`](docs/how-to/claude.md)
- [`docs/how-to/engineer/claude.md`](docs/how-to/engineer/claude.md)
- [`docs/legal/claude.md`](docs/legal/claude.md)
- [`docs/mcp/claude.md`](docs/mcp/claude.md)
- [`docs/ops/claude.md`](docs/ops/claude.md)
- [`docs/reference/claude.md`](docs/reference/claude.md)
- [`docs/superpowers/claude.md`](docs/superpowers/claude.md)
- [`docs/superpowers/plans/claude.md`](docs/superpowers/plans/claude.md)
- [`docs/superpowers/specs/claude.md`](docs/superpowers/specs/claude.md)
- [`docs/support/claude.md`](docs/support/claude.md)
- [`docs/tutorials/analyst/claude.md`](docs/tutorials/analyst/claude.md)
- [`docs/tutorials/claude.md`](docs/tutorials/claude.md)
- [`docs/tutorials/engineer/claude.md`](docs/tutorials/engineer/claude.md)
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
