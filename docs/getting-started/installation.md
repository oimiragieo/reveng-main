# REVENG Getting Started

> **Maturity:** preview (product overall) · triage and app RE are **supported** workflows — see [support matrix](../support/support-matrix.md)

This page covers setup, first-run, and troubleshooting. Prefer tutorials for step-by-step learning paths.

## Prerequisites

- Python `>=3.9` (dogfood hosts: prefer `/usr/bin/python3.9`)
- Git
- Optional: Java/Ghidra for deeper **native** binary work
- Optional: Ollama or API keys for AI-assisted features

## Install from source

### End users / quick try

```bash
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
python -m pip install -r requirements.txt
python -m pip install -e .
```

If you prefer the repository helper script, use `./install-reveng.sh` on Unix-like systems.

### Contributors (align with AGENTS.md)

```bash
make install-dev
# or: pip install -r requirements.txt -r requirements-dev.txt -r requirements-java.txt
python -m pip install -e . --no-deps
```

The editable `--no-deps` install is required so import-linter / grimp can resolve `reveng` as a top-level package. See [Engineer: Dev setup](../tutorials/engineer/01-dev-setup.md).

Honesty CI jobs use `requirements-honesty.txt` + `pip install -e . --no-deps` — do not cargo-cult a full `requirements.txt` resolve on py3.9 for those lanes.

## Verify the install

```bash
reveng --version
python -m reveng --version
reveng --help
```

If `reveng` is not on your `PATH`, use `python -m reveng ...`. Source-tree wrapper: `python src/reveng/cli/reveng.py --help`.

## First workflows

### Threat triage (supported)

```bash
reveng triage suspicious.exe --format markdown
reveng ask "What does this binary do?" suspicious.exe
```

### App reverse engineering (supported, first-class)

```bash
reveng reverse-engineer-app ./my-app --language auto
# languages: auto | javascript | jvm | python | dotnet
```

Also: `reveng-app --help`. Tutorial: [App reverse-engineer](../tutorials/analyst/02-app-reverse-engineer.md).

### Native analyze (often limited)

```bash
reveng analyze suspicious.exe
```

Typical outputs go to `analysis_<name>/`. Native depth often needs Ghidra — not GA-equivalent today.

## Optional services

### Ghidra-backed analysis

```bash
python scripts/install_ghidra.py
python external/ghidra-server/ghidra_http_server.py
```

Default URL: `http://127.0.0.1:13370`. Managed-language app RE does **not** require Ghidra.

### Ollama / providers

```bash
ollama serve
ollama pull llama3
# or set REVENG_AI_PROVIDER=anthropic|openai and the matching API key
```

Without a provider, core triage/app RE still run; AI-assisted features may skip.

## Experimental watermark

`reveng generate-exploit` is **EXPERIMENTAL / non-GA**. Do not treat it as a supported customer workflow. See [`docs/support_matrix.json`](../support_matrix.json) (`exploit_generation`).

## Troubleshooting

### `reveng` command not found

- Re-open your shell after installation, or run `python -m reveng ...`.

### Ghidra connection errors

- Confirm the Ghidra server is running at `http://127.0.0.1:13370`.
- Use `triage` or `reverse-engineer-app` while finishing native setup.

### Missing optional AI features

- Start Ollama or set provider keys — expect reduced capability, not a full install failure.

### Windows console encoding

```powershell
$env:PYTHONIOENCODING = "utf-8"
```

## Next reading

- Tutorials: [Install and triage](../tutorials/analyst/01-install-and-triage.md) · [App reverse-engineer](../tutorials/analyst/02-app-reverse-engineer.md)
- [CLI reference](../reference/cli.md) · [CLI usage](../user-guide/cli-usage.md)
- [Architecture overview (living)](../explanation/architecture-overview.md)
- [MCP tools](../reference/mcp-tools.md)
- [Root README](../../README.md)
