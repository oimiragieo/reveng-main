# REVENG

REVENG is a large Python reverse-engineering repository with real core infrastructure and a wide experimental surface.

## Current Status

- Package version in this checkout: `4.0.0`
- Development status: `beta`, not production-stable
- Core platform areas that are real:
  - main CLI and Python package
  - Ghidra integration points
  - MCP server surface
  - YARA, malware, and reporting modules
  - JVM, JavaScript, Python, and .NET app reverse-engineering adapters
- Advanced capability areas that should be treated as experimental until verified on tracked corpora:
  - exploit generation
  - end-to-end symbolic execution workflows
  - broad JavaScript deobfuscation claims
  - full binary-to-source-to-binary equivalence claims

## What This Repository Is

The codebase is best understood as an ambitious reverse-engineering platform under active hardening, not a finished product brochure. It contains substantial implementation across binary analysis, source recovery, malware workflows, decompilation helpers, and agent-facing integration, but maturity is uneven across subsystems.

For a grounded architecture view, start with:

- [System Paper](docs/architecture/reveng-system-paper.md)
- [World-Class Implementation Roadmap](docs/architecture/reveng-world-class-implementation-roadmap.md)
- [World-Class Execution Backlog](docs/architecture/reveng-world-class-execution-backlog.md)
- [App Reverse Engineering TDD Plan](docs/architecture/app-reverse-engineering-tdd-plan.md)
- [Current Platform Status](docs/architecture/current-platform-status.md)
- [Support Matrix](docs/user-guide/support-matrix.md)

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

- [Installation](INSTALLATION.md)
- [Getting Started Installation Guide](docs/getting-started/installation.md)
- [CLI Reference](CLI_REFERENCE.md)

## Key Features

- Main CLI, Python API, and MCP server surfaces
- App reverse engineering for JavaScript, JVM, Python, and .NET inputs
- Native-analysis-adjacent tooling for YARA, malware triage, patching, and reporting
- Versioned contracts with validation, evidence, and provenance fields
- Corpus, benchmark, and GA-readiness workflows for tracked quality gates

## Documentation

- [Docs Index](docs/README.md)
- [MCP Guide](docs/mcp/README.md)
- [System Paper](docs/architecture/reveng-system-paper.md)
- [World-Class Implementation Roadmap](docs/architecture/reveng-world-class-implementation-roadmap.md)
- [Current Platform Status](docs/architecture/current-platform-status.md)
- [Support Matrix](docs/user-guide/support-matrix.md)

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
