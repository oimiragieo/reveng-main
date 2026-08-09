# Tutorial: Engineer dev setup

> **Maturity:** preview (contributor workflow) · required for honest local gates
>
> Trust: editable install + thin honesty deps for CI-shaped gates. Do **not** cargo-cult full `requirements.txt` into honesty jobs (L28).

## Goal

Get a Python 3.9 editable checkout that can import `reveng`, run the CLI, and match the architecture/honesty install story used in this repo.

## Prerequisites

- Git
- Prefer `/usr/bin/python3.9`
- `make` available for `make install-dev` (or install the requirement files manually)

## Full contributor install

```bash
cd reveng-main
make install-dev
# Equivalent idea:
#   python3.9 -m pip install -r requirements.txt \
#     -r requirements-dev.txt -r requirements-java.txt
python3.9 -m pip install -e . --no-deps
```

### Why `pip install -e . --no-deps`?

Import-linter / grimp need the `reveng` package resolvable as a **top-level** package. The editable install wires that without re-resolving the entire fat dependency graph a second time. Runtime deps should already be present from `make install-dev` / the requirements files.

## PYTHONPATH and module entry

With the editable install, `import reveng` and `reveng` on `PATH` should work.

Without it (source-tree smoke only):

```bash
export PYTHONPATH=src
python3.9 -m reveng --help
# source-tree wrapper (self-bootstraps sys.path):
python3.9 src/reveng/cli/reveng.py --help
```

Always prefer the package entry points after install:

```bash
reveng --help
python3.9 -m reveng --help
reveng-app --help
```

## Layout you must know

| Path | Role |
| --- | --- |
| `src/reveng/` | Package root |
| `src/reveng/cli/` | CLI **package** (`reveng.cli:main`) — **not** a lone `src/reveng/cli.py` |
| `src/reveng/app_reverse_engineering/` | App RE framework + adapters |
| `src/reveng/core/` | Foundation (must not import higher domains) |
| `tests/` | pytest suites by intent |
| `docs/support_matrix.json` | Customer-facing supported-surface SoT |

## Honesty CI install (thin gate)

Wave B / Phase 5 honesty workflows use:

```bash
python3.9 -m pip install -r requirements-honesty.txt
python3.9 -m pip install -e . --no-deps
```

`requirements-honesty.txt` is intentionally minimal (pytest, PyYAML, …). Full `requirements.txt` on Python 3.9 can hit pip **`resolution-too-deep`** in GHA — never treat “install everything” as the honesty gate recipe.

See [Honesty rules](../../support/honesty-rules.md) and the release-honesty skill under `.cursor/skills/reveng-release-honesty/`.

## Smoke checklist

1. `python3.9 -c "import reveng; print(reveng.__file__)"` points under `src/reveng`
2. `reveng --help` lists `reverse-engineer-app` and `analyze`
3. `lint-imports --no-cache` can run after deps are present (see next tutorial)

## Next

- [Unit tests and honesty gates](02-run-unit-and-honesty-gates.md)
- [Architecture overview](../../explanation/architecture-overview.md)
- [Support matrix](../../support/support-matrix.md)
