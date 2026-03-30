# REVENG Developer Guide

This guide merges the useful material from the old developer, development, pipeline, and plugin docs into one current reference.

## Development Setup

```bash
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
python -m pip install -r requirements.txt
python -m pip install -e .
```

Optional extras:

- install Ghidra if you need native decompilation or reconstruction
- start Ollama if you want local AI assistance
- install dev-only tooling from `requirements-dev.txt` when working on the package itself

## Repository Layout

Most day-to-day work happens in:

- `src/reveng/analyzer.py` — analysis orchestrator
- `src/reveng/cli.py` — CLI parser and command handlers
- `src/reveng/api.py` / `src/reveng/ai_api.py` — programmatic APIs
- `src/reveng/integrations/ghidra/` — Ghidra connectors
- `src/reveng/pipeline/` and `src/reveng/pipelines/` — orchestration logic
- `src/reveng/security/`, `src/reveng/malware/`, `src/reveng/ml/` — analysis engines
- `src/reveng/plugins/` — plugin-facing abstractions
- `tests/` — unit and integration coverage

## Current Entry Points

Use one of these supported entry points:

```bash
reveng --help
python -m reveng --help
python src/reveng/cli/reveng.py --help
```

Do not build new workflows around removed legacy entry points.

## Extending the Analyzer

When adding a new analysis capability:

1. implement it in the appropriate subsystem package
2. keep inputs/outputs structured and serializable
3. wire the feature into `REVENGAnalyzer` or `REVENGAPI`
4. add CLI exposure only if the feature is user-facing
5. add tests before documenting the behavior

Keep new functionality local to one subsystem instead of adding more cross-package shims.

## Pipeline Development

REVENG has dedicated pipeline modules, but the durable design rules are simple:

- make stage dependencies explicit
- keep stage outputs as plain dictionaries or dataclasses
- fail clearly when a dependency is required
- degrade gracefully when a capability is optional
- write intermediate artifacts into the analysis output directory

If you add a pipeline stage, verify both its success path and its failure path.

## Plugin Development

REVENG still exposes plugin-oriented code under `src/reveng/plugins/` and `src/reveng/tools/enterprise/plugin_system.py`.

Good plugin patterns:

- one clear responsibility per plugin
- configuration-driven behavior
- explicit lifecycle hooks
- isolated side effects
- tests that exercise both success and cleanup behavior

If a plugin depends on external tools, validate the dependency during initialization and return a structured failure rather than crashing in the middle of analysis.

## Testing and Validation

Use the repository validators defined in `.factory/services.yaml`:

```bash
python -m pytest tests/unit/ tests/integration/ tests/performance -n 4 --ignore=tests/poc
flake8 src/reveng/ --extend-ignore=E501,F811,E203
python -m mypy src/reveng/ --ignore-missing-imports
```

Windows contributors should prefer `python -m pytest` over invoking `pytest` directly.

The remaining `tests/poc/` coverage is intentionally optional. Those files are now explicitly marked with `poc`, `requires_external_tools`, and `slow` because they depend on local compiler/model/runtime availability such as angr, GCC, and LLM4Decompile weights.

```bash
# Run the optional environment-heavy POC suite
python -m pytest tests/poc/ -m "poc and requires_external_tools" -v

# Or use the repo helper target
make test-poc
```

## Release Checklist

Before shipping a change:

1. run tests, lint, and type checks
2. verify `reveng --version`
3. update the relevant changelog entry
4. confirm docs still point to real commands and files

## Code Style

- follow the existing package structure instead of adding duplicate wrappers
- prefer typed public interfaces
- log important state transitions and external-tool failures
- keep new docs and examples aligned with real commands from `src/reveng/cli.py`

## Contributing

The repository-wide contribution process lives in [CONTRIBUTING.md](../../CONTRIBUTING.md). Use that as the canonical policy; this page focuses only on the engineering workflow.
