# Reference: MCP tools

> **Maturity:** **preview** · product beta · **not** “production ready”
>
> Do not invent success percentages. Match [`../support_matrix.json`](../support_matrix.json).
> Setup walkthrough (honesty-rewritten): [mcp/README.md](../mcp/README.md)

REVENG exposes MCP servers under `src/reveng/agent_sdk/mcp/servers/`. The repo-root `./reveng-mcp-server` launcher starts the **enterprise** server by default. Start local client config from `mcp-config.example.json` (never commit secrets).

## Core server (`reveng_server.py`)

Class: `REVENGMCPServer`

| Tool | Status | Notes |
| --- | --- | --- |
| `analyze_binary` | preview / limited for native | Uses `REVENGAnalyzer`; Ghidra may be required for deep native work |
| `deobfuscate_js` | preview | JS helper; broad “full deobfuscation” claims remain unverified |
| `detect_malware` | **unsupported** for `type=binary` | Explicit honesty response (`binary_malware_mcp_unsupported`). JavaScript path may run the JS malware detector |
| `reverse_engineer_app` | **supported** (languages in matrix) | Same app-RE contract as CLI |
| `run_app_corpus` | process / honesty tooling | Manifest-driven corpus rollup |

## Enterprise server (`reveng_enterprise_server.py`)

Wider tool surface. Presence in the registry is not a GA badge.

| Tool | Honest status |
| --- | --- |
| `analyze_binary` | preview; knobs must not silently no-op |
| `decompile_binary` | limited (Ghidra); AI enhancement / type reconstruction unsupported in this MCP path when so described |
| `recompile_binary` | managed vs native — native needs Ghidra; not GA-equivalent for all PE/ELF |
| `diff_binaries` | preview |
| `scan_yara` | preview |
| `analyze_memory_dump` | preview / uneven |
| `find_vulnerabilities` | preview; symbolic paths **experimental** |
| `generate_exploit` | **experimental / non-GA** (same policy as CLI) |
| `classify_malware` | preview |
| `deobfuscate_javascript` / `detect_js_malware` | preview |
| `ask_ai_about_binary` / `ai_code_reconstruction` | preview; provider-dependent |
| `get_analysis_report` / `list_recent_analyses` | utility |
| `reverse_engineer_app` / `run_app_corpus` | same honesty as core |

Resources / prompts (e.g. `reveng://analyses/recent`, `analyze_malware`, `find_and_exploit`) are convenience wrappers — they do not raise maturity above the underlying tools.

## Config and launch

```bash
# Enterprise MCP (stdio for Claude Desktop / agents)
./reveng-mcp-server

# HTTP (local only by default)
./reveng-mcp-server --transport http --host 127.0.0.1 --port 8080
```

Copy `mcp-config.example.json` into your client config; replace paths and API keys. Optional env: `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, plus Ollama hosts (`OLLAMA_HOST` / `REVENG_MCP_OLLAMA_*`).

## What not to claim

- No “Production Ready,” “95%+ decompilation,” or brochure exploit success rates.
- Core MCP binary `detect_malware` is **unsupported** — document that, not “coming soon as if it works.”
- Exploit tools stay experimental (Docker-only preview policy for expansion — R-SEC-1).

## Related

- [Wire an MCP tool](../how-to/engineer/wire-mcp-tool.md)
- [Support matrix](../support/support-matrix.md)
- [Maturity badges](../support/maturity-badges.md)

## Honesty notes (2026-08-09 wiring wave)

- Enterprise tool schemas must not advertise invented accuracy percentages.
- `unbundle_webpack=true` on `deobfuscate_javascript` is **unsupported** (warning in payload; not applied).
- `find_vulnerabilities`: `vulnerability_types` / `use_ai_analysis` are **unsupported**; `use_symbolic_execution=false` returns `could_not_measure` — agents must not treat that as a clean “no vulns” scan.
- Core `analyze_binary` accepts `enable_ai` (default true).
