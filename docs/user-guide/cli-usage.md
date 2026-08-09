# CLI Usage Guide

> **Maturity:** mixed — see [CLI reference](../reference/cli.md) and [support matrix](../support/support-matrix.md)

This page is a short narrative guide. The command table and maturity notes live in the [CLI reference](../reference/cli.md). Implementation: **`src/reveng/cli/`** package (`create_parser` in `cli/__init__.py`) — not `src/reveng/cli.py`.

## Basic usage

```bash
reveng --help
reveng triage sample.exe --format markdown
reveng reverse-engineer-app app.jar --language jvm
reveng analyze sample.exe
```

If the console script is unavailable, use `python -m reveng ...` or `python src/reveng/cli/reveng.py ...`.

## Command overview

| Command | Purpose | Note |
| --- | --- | --- |
| `analyze [binary]` | Main analysis flow | preview; native may need Ghidra |
| `reverse-engineer-app <input>` | App RE (JS/JVM/Python/.NET) | **supported** |
| `serve` | Local web interface | preview |
| `ask` / `ai` | AI Q&A / assistant | preview |
| `triage <binary>` | Fast threat assessment | **supported** |
| `vt-lookup` / `vt-submit` | VirusTotal | preview; API key |
| `generate-yara` / `scan-yara` | YARA helpers | preview |
| `diff` / `patch-analysis` | Compare / patch study | preview |
| `detect-packer` / `unpack` | Packer flows | preview |
| `enhance-code` | Improve decompiled code | preview |
| `recompile` | Binary → source → binary | managed supported; native limited |
| `build-bun-sea` | Bun → Node SEA | preview |
| `decompile` | Decompile / Bun JS extract | limited when Ghidra-backed |
| `generate-exploit` | PoC exploit assist | **EXPERIMENTAL / non-GA** |

## Common workflows

### 1. First-pass triage (supported)

```bash
reveng triage suspicious.exe --format markdown
reveng ask "What does this binary do?" suspicious.exe
```

### 2. App reverse engineering (supported)

```bash
reveng reverse-engineer-app ./my-app --language auto
reveng reverse-engineer-app package.json --language javascript
```

See [App reverse-engineer tutorial](../tutorials/analyst/02-app-reverse-engineer.md).

### 3. Deep / native analysis (often limited)

```bash
reveng analyze suspicious.exe
reveng decompile suspicious.exe --enhance
```

Requires a healthy Ghidra Analysis Server for many native paths (`http://127.0.0.1:13370`).

### 4. Reconstruction

```bash
reveng recompile suspicious.exe --output-dir analysis_suspicious
```

Managed-language inputs use app adapters (no Ghidra). Native PE/ELF/Mach-O still need Ghidra.

### 5. Detection content

```bash
reveng generate-yara suspicious.exe --output suspicious.yar
reveng scan-yara suspicious.exe --rule-file suspicious.yar
```

### 6. Diffing and patch review

```bash
reveng diff old.exe new.exe --format markdown
reveng patch-analysis old.exe new.exe --format markdown
```

### 7. Exploit assist (experimental)

```bash
reveng generate-exploit suspicious.exe
```

Watermarked **EXPERIMENTAL / non-GA**. Not part of the supported customer surface. See `exploit_generation` in [`docs/support_matrix.json`](../support_matrix.json).

## Windows-focused notes

- Start with `triage`, `detect-packer`, and `analyze` for PE files
- Prefer `reverse-engineer-app` for managed-language packages
- Use `decompile` / `recompile` for native only after Ghidra is available locally

## Troubleshooting

- If `reveng` is not found, use `python -m reveng`.
- If Ghidra-dependent commands fail, start the local Ghidra HTTP server.
- If AI features are unavailable, start Ollama or configure `REVENG_AI_PROVIDER` / API keys.

## Related docs

- [CLI reference](../reference/cli.md)
- [Install and triage tutorial](../tutorials/analyst/01-install-and-triage.md)
- [Getting started](../getting-started/installation.md)
- [Bun reversing](bun-reversing.md)
- [Python API reference](../reference/python-api.md)
- [MCP tools](../reference/mcp-tools.md)
