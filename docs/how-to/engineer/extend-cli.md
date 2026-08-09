# How to: extend the CLI

> **Maturity:** CLI packaging is stable; individual subcommands follow the [support matrix](../../support/support-matrix.md) (triage **supported**, exploits **experimental**, …)
>
> The CLI is a **package**, not a single `cli.py` module. See [Architecture overview](../../explanation/architecture-overview.md).

## Where the CLI lives

| What | Path |
| --- | --- |
| Package | `src/reveng/cli/` |
| Parser + handlers | `src/reveng/cli/__init__.py` — `create_parser()`, `handle_*_command`, `main` |
| Source-tree wrapper | `src/reveng/cli/reveng.py` (bootstraps `sys.path`, calls `reveng.cli.main`) |
| Console entry | `pyproject.toml` → `reveng = "reveng.cli:main"` |
| Breadcrumb | `src/reveng/cli/claude.md` |

There is **no** repo-root `reveng.py`. Do not recreate one — it historically shadowed the package.

Separate app CLI: `reveng-app` → `reveng.app_reverse_engineering.cli`.

## Add a subcommand (pattern)

1. In `create_parser()`, obtain `subparsers` and `add_parser(...)`.
2. Attach arguments; use translator keys from `reveng.translations` when touching user-facing help.
3. Implement `handle_<name>_command(args)` in the same package module (or a focused submodule imported by `__init__.py` if the file grows further).
4. Register the handler in the command dispatch map (see existing `"analyze"`, `"reverse-engineer-app"`, `"generate-exploit"`, … entries near the bottom of `__init__.py`).
5. Ensure `main()` routes `args.command` to your handler and returns a process exit code.

### Maturity watermark example

Experimental commands must say so in help **and** at runtime. Pattern from `generate-exploit`:

- `help="[EXPERIMENTAL/non-GA] ..."`
- Banner + pointer to `docs/support_matrix.json`

Do not add a customer-facing subcommand that contradicts the matrix ([honesty rules](../../support/honesty-rules.md)).

## Wiring into analysis / app RE

- Binary analyze → construct `REVENGAnalyzer` / `EnhancedAnalysisFeatures` (respect `enable_ai` / Ghidra timeouts).
- App RE → `create_default_framework()` then `reverse_engineer` (see [Add adapter](add-adapter.md)).
- Prefer calling real package APIs over duplicating adapter logic in the CLI layer.

## Verify locally

```bash
reveng --help
python -m reveng --help
python src/reveng/cli/reveng.py --help
```

Add unit tests that parse argv and assert handler selection / exit codes where practical (`tests/unit/`).

## Related

- [Analysis pipeline](../../explanation/analysis-pipeline.md)
- [App RE dispatch](../../explanation/app-re-dispatch.md)
- [Security and exploits](../../explanation/security-and-exploits.md) for watermarked commands
- [Support matrix](../../support/support-matrix.md)
