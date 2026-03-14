# CLI Usage Guide

This page reflects the current commands exposed by `src/reveng/cli.py`.

## Basic Usage

```bash
reveng --help
reveng analyze sample.exe
reveng triage sample.exe --format markdown
```

If the console script is unavailable, use `python -m reveng ...`.

## Command Reference

| Command | Purpose |
| --- | --- |
| `analyze [binary]` | run the main analysis flow |
| `serve` | start the local web interface |
| `ask <question> [binary]` | ask natural-language questions about a target |
| `ai <binary>` | launch the interactive AI assistant workflow |
| `triage <binary>` | fast threat assessment |
| `vt-lookup <binary-or-hash>` | enrich with VirusTotal data |
| `vt-submit <binary>` | submit a file to VirusTotal |
| `generate-yara <binary>` | emit a YARA rule |
| `scan-yara <binary>` | scan with YARA rules |
| `diff <old> <new>` | compare two binaries |
| `patch-analysis <old> <new>` | inspect a security patch |
| `detect-packer <binary>` | identify packing / obfuscation |
| `unpack <binary>` | attempt unpacking |
| `enhance-code <file>` | improve raw decompiled code |
| `recompile <binary>` | run the binary → source → binary flow |
| `decompile <binary>` | extract source-like output |
| `generate-exploit <binary>` | generate a proof-of-concept exploit |

## Common Workflows

### 1. First-pass triage

```bash
reveng triage suspicious.exe --format markdown
reveng ask "What does this binary do?" suspicious.exe
```

### 2. Deep analysis

```bash
reveng analyze suspicious.exe
reveng decompile suspicious.exe --enhance
```

### 3. Reconstruction workflow

```bash
reveng recompile suspicious.exe --output-dir analysis_suspicious
reveng enhance-code analysis_suspicious/decompiled/main.c --function-name main
```

### 4. Detection content

```bash
reveng generate-yara suspicious.exe --output suspicious.yar
reveng scan-yara suspicious.exe --rule-file suspicious.yar
```

### 5. Diffing and patch review

```bash
reveng diff old.exe new.exe --format markdown
reveng patch-analysis old.exe new.exe --format markdown
```

## Windows-focused Notes

The old Windows-specific guide was condensed into this section:

- start with `triage`, `detect-packer`, and `analyze` for PE files
- use `decompile` for source-oriented review
- use `ask` to summarize imports, persistence, network behavior, or crypto behavior
- use `recompile` only after Ghidra is available locally

## Useful Options

Selected command-specific options from the current parser:

- `serve --host --port --reload`
- `ask --analysis-results --conversational`
- `ai --analysis-type --goals --interactive`
- `triage --bulk --format`
- `diff --deep --format`
- `patch-analysis --cve --format`
- `unpack --output --method`
- `enhance-code --function-name --output`
- `recompile --output-dir --ghidra-url --no-gemini --no-exploits`
- `decompile --output --language --enhance`
- `generate-exploit --vulnerability --output --language --analysis-results`

## Troubleshooting

- If `reveng` is not found, use `python -m reveng`.
- If Ghidra-dependent commands fail, start `external/ghidra-server/ghidra_http_server.py`.
- If AI features are unavailable, start Ollama or configure the provider you want.

## Related Docs

- [Getting Started](../getting-started/installation.md)
- [API Reference](../api/API_REFERENCE.md)
- [MCP Guide](../mcp/README.md)
```
