# REVENG

REVENG is a large Python reverse-engineering repository with real core infrastructure and a wide experimental surface.

## Current Status

- Package version in this checkout: `4.0.0`
- Development status: `beta` with a **customer-safe GA readiness gate** (`scripts/verify_ga_readiness.py --profile ga`)
- Supported GA surface (see `docs/support_matrix.json`):
  - CLI threat triage
  - App reverse engineering (JavaScript, JVM, Python, .NET)
  - Managed-language source↔binary reconstruction (Java/Python hermetic benches tracked)
- Still limited / experimental until corpus-proven:
  - Native PE/ELF/Mach-O recompile (requires Ghidra Analysis Server)
  - exploit generation (CLI watermarked EXPERIMENTAL/non-GA)
  - end-to-end symbolic execution workflows
  - broad JavaScript deobfuscation claims
  - full binary-to-source-to-binary equivalence claims

Ops backlog: [`backlog.md`](backlog.md). Release evidence: `reports/ga_readiness_target.json`, `reports/release_report.md`.

## What This Repository Is

The codebase is best understood as an ambitious reverse-engineering platform under active hardening, not a finished product brochure. It contains substantial implementation across binary analysis, source recovery, malware workflows, decompilation helpers, and agent-facing integration, but maturity is uneven across subsystems.

For how the product and codebase work (junior-friendly), start with the **docs dual doors**:

- [Docs home — Analyst & Engineer tracks](docs/README.md)
- [Support matrix](docs/support/support-matrix.md) · [Honesty rules](docs/support/honesty-rules.md) · [Maturity badges](docs/support/maturity-badges.md) · [GA path checklist](docs/support/ga-path-checklist.md)
- [Architecture explanation](docs/explanation/architecture-overview.md)
- [CLI reference](docs/reference/cli.md)

Ops / program depth (not product tutorials): [Ops index](docs/ops/README.md), [backlog.md](backlog.md), [System Paper](docs/architecture/reveng-system-paper.md).

## Quick Start

```bash
# Inspect the main CLI
python src/reveng/cli/reveng.py --help

# Reverse engineer an application entrypoint or bundle
python src/reveng/cli/reveng.py reverse-engineer-app path/to/input --output-dir analysis_out

# Installed entrypoints
reveng --help
reveng-app --help
reveng-js --help
```

Start with:

- [Analyst tutorial: install and triage](docs/tutorials/analyst/01-install-and-triage.md)
- [Analyst tutorial: app reverse-engineer](docs/tutorials/analyst/02-app-reverse-engineer.md)
- [Getting Started (legacy install page)](docs/getting-started/installation.md)
- [CLI reference](docs/reference/cli.md)

## Key Features

- Main CLI, Python API, and MCP server surfaces
- App reverse engineering for JavaScript, JVM, Python, and .NET inputs
- Native-analysis-adjacent tooling for YARA, malware triage, patching, and reporting
- Versioned contracts with validation, evidence, and provenance fields
- Corpus, benchmark, and GA-readiness workflows for tracked quality gates

## Documentation

The documentation ecosystem is Diátaxis-shaped (tutorials → how-to → explanation → reference) with **Analyst** and **Engineer** tracks:

| Door | Start here |
| --- | --- |
| Home | [docs/README.md](docs/README.md) |
| Support / trust | [Support matrix](docs/support/support-matrix.md) · [Honesty rules](docs/support/honesty-rules.md) · [Validation grades](docs/support/reading-validation-grades.md) · [GA checklist](docs/support/ga-path-checklist.md) |
| Analyst tutorials | [Install & triage](docs/tutorials/analyst/01-install-and-triage.md) · [App RE](docs/tutorials/analyst/02-app-reverse-engineer.md) · [Reading outputs](docs/tutorials/analyst/03-reading-outputs.md) |
| Engineer tutorials | [Dev setup](docs/tutorials/engineer/01-dev-setup.md) · [Honesty gates](docs/tutorials/engineer/02-run-unit-and-honesty-gates.md) |
| Explanation | [Architecture](docs/explanation/architecture-overview.md) · [VRL](docs/explanation/vrl-and-verification.md) · [Result contracts](docs/explanation/result-contracts.md) |
| Reference | [CLI](docs/reference/cli.md) · [Python API](docs/reference/python-api.md) · [MCP tools](docs/reference/mcp-tools.md) |
| Ops | [Ops index](docs/ops/README.md) · [backlog.md](backlog.md) |

MkDocs nav mirrors this tree (`mkdocs.yml`). Legacy pages under `docs/user-guide/`, `docs/mcp/`, and `docs/architecture/` remain linked where useful; prefer the new tracks for learning.

## Practical Entry Points

```bash
# Main CLI
python src/reveng/cli/reveng.py --help

# Generic app reverse-engineering workflow
python src/reveng/cli/reveng.py reverse-engineer-app path/to/input --output-dir analysis_out

# Package entrypoints
reveng --help
reveng-app --help
reveng-js --help
```

## Shipping Guidance

If you need something defensible in the next 24 hours, treat the repository this way:

- use the main CLI and the app reverse-engineering adapters as the stable path
- keep claims tied to test results and tracked artifacts
- avoid marketing language like "production-ready" unless the relevant workflow is benchmarked and passing
- assume heavy analysis paths still need environment validation before release

## Contributing

Use [CONTRIBUTING.md](CONTRIBUTING.md) for contribution process details and [AGENTS.md](AGENTS.md) for repo-specific contributor guidance. Keep behavior changes tied to tests and update docs when public contracts change.

## License

See [LICENSE](LICENSE) for current licensing terms.
