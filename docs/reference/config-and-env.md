# Reference: Config and environment

> **Maturity:** preview · incomplete list — grep `os.environ` / scripts when adding knobs

## AI / LLM

| Variable | Role |
| --- | --- |
| `REVENG_AI_PROVIDER` | Provider for VRL / analyzer registry: `ollama` (default), `anthropic`, `openai` |
| `REVENG_OLLAMA_HOST` / `OLLAMA_HOST` | Ollama base URL (WSL→Windows host often needs an explicit URL) |
| `REVENG_OLLAMA_MODEL` / `OLLAMA_MODEL` | Model id override |
| `REVENG_MCP_OLLAMA_HOST` / `REVENG_MCP_OLLAMA_MODEL` / `REVENG_MCP_OLLAMA_TIMEOUT` | Enterprise MCP chat overrides |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` | Cloud providers (MCP example config, optional AI extras) |

## Threat intel / external

| Variable | Role |
| --- | --- |
| `VT_API_KEY` | VirusTotal for `vt-lookup` / `vt-submit` (or `--api-key`) |

## Ghidra

| Setting | Default / notes |
| --- | --- |
| CLI `--ghidra-url` | `http://127.0.0.1:13370` (`recompile`) |
| Client defaults | `GhidraEngine` / HTTP client use `http://127.0.0.1:13370` |
| Start server | `python external/ghidra-server/ghidra_http_server.py` or `python -m reveng.server.ghidra_analysis_server --port 13370` |

Managed-language app RE / recompile paths do **not** require Ghidra. Native PE/ELF/Mach-O reconstruction still does.

## MCP client config

- Template: repo-root `mcp-config.example.json`
- Copy into Claude Desktop / client config; point `command` at `./reveng-mcp-server`
- Do not commit filled secrets

## Local / debug

| Variable / path | Role |
| --- | --- |
| `.reveng/` | Benchmarks, corpus configs, validation examples, local artifacts |
| `REVENG_TOOLS_DIR` | Optional tools install root (else `~/.reveng/tools`) |
| `REVENG_DEBUG_FUNCTION_STAGES` / `REVENG_DEBUG_WHOLE_SOURCE_STAGES` / `REVENG_DEBUG_FUNCTION_TERMS` | Recompilation engine debug dumps |

## Contributor install

```bash
make install-dev
python3.9 -m pip install -e . --no-deps   # import-linter / grimp need top-level reveng
```

Honesty CI jobs: `requirements-honesty.txt` + `pip install -e . --no-deps` (avoid full `requirements.txt` on py3.9 — L28).

## Related

- [Dev setup tutorial](../tutorials/engineer/01-dev-setup.md)
- [CLI reference](cli.md)
- [MCP tools](mcp-tools.md)
