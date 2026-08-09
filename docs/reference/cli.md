# Reference: CLI

> **Maturity:** mixed — see per-command notes · product overall **preview**
>
> Machine support boundary: [`../support_matrix.json`](../support_matrix.json) · human: [Support matrix](../support/support-matrix.md)

## Entry points

| Entry | Notes |
| --- | --- |
| `reveng` | Console script → `reveng.cli:main` |
| `python -m reveng` | Module entry (`src/reveng/__main__.py`) |
| `python src/reveng/cli/reveng.py` | Source-tree wrapper (bootstraps `sys.path`) |
| `reveng-app` | App reverse-engineering CLI (`reveng.app_reverse_engineering.cli`) |
| `reveng-js` | JavaScript analysis CLI (`reveng.javascript.cli`) |

Implementation lives in the **`src/reveng/cli/` package** (`create_parser` in `cli/__init__.py`). There is no `src/reveng/cli.py`.

Smoke:

```bash
reveng --help
python -m reveng --help
```

## Commands

Flags below are the common ones from `create_parser`. Always prefer `reveng <command> --help` for the live surface.

| Command | Purpose | Key args | Maturity |
| --- | --- | --- | --- |
| `analyze` | Main analysis / e2e pipeline (Bun PE routes to bundle extraction) | `[binary_path]`, `--ghidra-timeout`, `--ghidra-retries`, `--no-ai` (sets `enable_ai=False`), global `--output-dir` | **preview**; native depth often needs Ghidra (**limited** per matrix) |
| `reverse-engineer-app` | App RE via language adapters → SPECS / validation / evidence | `input_path`, `--language` (`auto`/`javascript`/`jvm`/`python`/`dotnet`), `--input-root`, `--skip-pattern`, `--max-snippets`, `--run-deobfuscator` | **supported** (`app_reverse_engineering`) |
| `serve` | Local web UI | `--host`, `--port`, `--reload` | preview; needs `pip install -e .[web]` |
| `ask` | Natural-language Q&A about a binary | `question`, `[binary_path]`, `--analysis-results`, `--conversational` | preview; AI provider / Ollama |
| `ai` | AI assistant workflow | `binary_path`, `--analysis-type`, `--goals`, `--interactive` | preview; AI provider / Ollama |
| `triage` | Instant threat triage | `binary_path`, `--bulk`, `--format` | **supported** (`cli_triage`) |
| `vt-lookup` | VirusTotal hash/file lookup | `binary_path` or hash, `--api-key` / `VT_API_KEY` | preview; network + API key |
| `vt-submit` | Submit sample to VirusTotal | `binary_path`, `--api-key`, `--wait` | preview; policy-sensitive |
| `generate-yara` | Emit a YARA rule | `binary_path`, `--rule-name`, `--output`, `--analysis-results` | preview |
| `scan-yara` | Scan with YARA rules | `binary_path`, `--rules-dir`, `--rule-file` | preview |
| `diff` | Binary diff | `binary_v1`, `binary_v2`, `--deep`, `--format` | preview |
| `patch-analysis` | Patch / CVE-oriented diff | `unpatched_binary`, `patched_binary`, `--cve`, `--format` | preview |
| `detect-packer` | Packer / packing heuristics | `binary_path`, `--format` | preview |
| `unpack` | Attempt unpack | `binary_path`, `--output`, `--method` | preview |
| `enhance-code` | AI enhance decompiled/source snippet | `code_file`, `--function-name`, `--output` | preview; AI provider |
| `recompile` | Binary → source → binary (managed vs native; Bun → SEA) | `binary_path`, `--output-dir`, `--ghidra-url`, `--ghidra-timeout`, `--no-gemini`, `--no-exploits` | **supported** for managed-language paths; native PE/ELF/Mach-O still **limited** (needs Ghidra) |
| `build-bun-sea` | Recover Bun → Node SEA executable | `binary_path`, `--output-dir`, `--output`, `--skip-install` | preview / Bun-specific |
| `decompile` | Decompile (Ghidra; Bun → JS extract) | `binary_path`, `--output`, `--language`, `--enhance`, `--timeout` | limited when Ghidra-backed |
| `generate-exploit` | Exploit assist | `binary_path`, `--vulnerability`, `--output`, `--language`, `--analysis-results` | **EXPERIMENTAL / non-GA** (`exploit_generation`) |

### Global option groups

- Enhanced analysis toggles: `--no-enhanced`, `--no-corporate`, `--no-vuln`, `--no-threat`, `--no-reconstruction`, `--no-demo`, `--config`
- Config / env: `--config`, `--no-ollama-check`, `--output-dir`
- Logging: `--verbose` / `-V`, `--quiet` / `-q`, `--log-file`
- Locale: `--lang` (`en`, `pt-br`)

## Examples

```bash
# Supported triage
reveng triage suspicious.exe --format markdown

# Supported app reverse engineering
reveng reverse-engineer-app app.jar --language jvm
reveng reverse-engineer-app package.json --language javascript

# Limited / Ghidra-backed native
reveng analyze sample.exe --ghidra-timeout 900
reveng decompile sample.exe --language c
reveng recompile sample.exe --ghidra-url http://127.0.0.1:13370

# EXPERIMENTAL — not GA
reveng generate-exploit sample.exe
```

## What not to claim from CLI presence

- Command exists ≠ GA. Match [`support_matrix.json`](../support_matrix.json).
- Do not invent success rates for decompile / recompile / exploit / JS deobfuscation.
- `generate-exploit` is watermarked **EXPERIMENTAL** in help text and runtime banners.
- Native fixture samples under `test_samples/native/` prove CLI wiring only (**fixture_only**), not native analyze GA.

## Related

- Tutorial: [Install and triage](../tutorials/analyst/01-install-and-triage.md)
- Tutorial: [App reverse-engineer](../tutorials/analyst/02-app-reverse-engineer.md)
- Narrative guide: [CLI usage](../user-guide/cli-usage.md)
- [Support matrix](../support/support-matrix.md)
