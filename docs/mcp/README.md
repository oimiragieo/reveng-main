# REVENG MCP integration

> **Maturity:** **preview** (beta product) · **not** production-ready
>
> Capability index: [MCP tools reference](../reference/mcp-tools.md) · boundary: [Support matrix](../support/support-matrix.md) · machine SoT: [`../support_matrix.json`](../support_matrix.json)

REVENG exposes reverse-engineering capabilities to AI agents through the [Model Context Protocol](https://spec.modelcontextprotocol.io). Servers live under `src/reveng/agent_sdk/mcp/servers/`. The repo-root `./reveng-mcp-server` launches the **enterprise** server (stdio or HTTP).

Do **not** treat tool registration as GA. Match claims to the support matrix. Invented success rates (e.g. “95%+ decompilation”) are documentation bugs.

## Quick start

### 1. Install REVENG

```bash
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
python3.9 -m pip install -r requirements.txt
python3.9 -m pip install -e .
# Contributors:
# make install-dev && python3.9 -m pip install -e . --no-deps
```

Optional AI extras: `pip install -e .[ai]` (or the provider packages you need).

### 2. API keys / local LLM (optional)

```bash
export GEMINI_API_KEY="..."
export ANTHROPIC_API_KEY="..."
export OPENAI_API_KEY="..."
# or run Ollama and set OLLAMA_HOST / REVENG_OLLAMA_HOST as needed
```

### 3. MCP client config

Start from `mcp-config.example.json` at the repo root. Example Claude Desktop shape:

```json
{
  "mcpServers": {
    "reveng": {
      "command": "/path/to/reveng-main/reveng-mcp-server",
      "args": [],
      "env": {
        "GEMINI_API_KEY": "your-gemini-api-key-here"
      }
    }
  }
}
```

### 4. Launch

```bash
./reveng-mcp-server
./reveng-mcp-server --transport http --host 127.0.0.1 --port 8080
```

Useful flags: `--no-rate-limit`, `--no-audit-log`, `--config`, `--debug`.

## Tool surface (honest summary)

| Area | Reality |
| --- | --- |
| App reverse engineering (`reverse_engineer_app`) | **supported** for JS / JVM / Python / .NET (quality varies) |
| Binary analyze / decompile / recompile | preview or **limited** when Ghidra-backed; native ≠ GA |
| Core `detect_malware` + `type=binary` | **unsupported** (explicit refusal) |
| `generate_exploit` / exploit-oriented prompts | **experimental / non-GA** |
| JS deobfuscation / malware helpers | preview; do not claim measured accuracy % |

Full tables: [reference/mcp-tools.md](../reference/mcp-tools.md).

## Enterprise extras

The enterprise server may apply rate limiting and write audit logs under `~/.reveng/`. These are operational features, not a maturity upgrade. Disable with `--no-rate-limit` / `--no-audit-log` for local testing when appropriate.

## Testing

```bash
pytest tests/integration/test_mcp_integration.py -v
```

(Skip or mark-filter if your environment lacks MCP / external deps.)

## Related

- [MCP tools reference](../reference/mcp-tools.md)
- [Config and env](../reference/config-and-env.md)
- [Wire an MCP tool](../how-to/engineer/wire-mcp-tool.md)
- [Honesty rules](../support/honesty-rules.md)
- Older sibling pages under `docs/mcp/` (integration / deployment) may still contain aspirational language — prefer this README + the reference index.
