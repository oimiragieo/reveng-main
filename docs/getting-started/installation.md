# REVENG Getting Started

This page combines setup, first-run, and troubleshooting guidance for the current repository.

## Prerequisites

- Python `>=3.9`
- Git
- Optional: Java/Ghidra for deeper native-binary work
- Optional: Ollama or API keys for AI-assisted features

## Install From Source

```bash
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
python -m pip install -r requirements.txt
python -m pip install -e .
```

If you prefer the repository helper script, use `./install-reveng.sh` on Unix-like systems.

## Verify the Install

```bash
reveng --version
python -m reveng --version
```

If `reveng` is not on your `PATH`, use `python -m reveng ...` until your environment is fixed.

## First Analysis

```bash
reveng triage suspicious.exe
reveng analyze suspicious.exe
reveng ask "What does this binary do?" suspicious.exe
```

Typical outputs are written to an `analysis_<binary-name>/` directory in the current working directory.

## Optional Services

### Ghidra-backed analysis

Install Ghidra with the repository helper and start the local HTTP server when you need full decompilation or reconstruction flows:

```bash
python scripts/install_ghidra.py
python external/ghidra-server/ghidra_http_server.py
```

The default Ghidra URL used by the CLI is `http://127.0.0.1:13370`.

### Ollama

```bash
ollama serve
ollama pull llama3
```

Without Ollama or external API keys, REVENG still runs, but AI-assisted features may degrade or skip optional steps.

## Common Workflows

### Quick threat triage

```bash
reveng triage suspicious.exe --format markdown
reveng generate-yara suspicious.exe --output suspicious.yar
```

### Source reconstruction

```bash
reveng decompile suspicious.exe --enhance
reveng recompile suspicious.exe --output-dir analysis_suspicious
```

### Web interface

```bash
reveng serve --host localhost --port 3000
```

## Troubleshooting

### `reveng` command not found

- Re-open your shell after installation.
- Or run commands as `python -m reveng ...`.

### Ghidra connection errors

- Confirm the Ghidra server is running.
- Verify the default URL `http://127.0.0.1:13370` is reachable.
- Use non-Ghidra commands such as `triage` while you finish setup.

### Missing optional AI features

- Start Ollama locally, or set the relevant provider keys.
- Expect reduced capability rather than a full install failure.

### Windows console encoding issues

If help text or rich output fails to print correctly, set UTF-8 before running commands:

```powershell
$env:PYTHONIOENCODING = "utf-8"
```

## Next Reading

- [CLI Usage](../user-guide/cli-usage.md)
- [Architecture Overview](../architecture/overview.md)
- [MCP Guide](../mcp/README.md)
- [Root README](../../README.md)
