# Validation Surface — REVENG RE Platform

## Validation Surface

Primary surfaces:
1. **CLI Engine** — `python src/reveng/cli/reveng.py <command>` (Windows, with `PYTHONIOENCODING=utf8`)
2. **MCP Server** — direct Python instantiation: `REVENGEnterpriseServer(); server.tool_name({...})`
3. **pytest test suite** — `pytest tests/unit/ tests/integration/ -n 4`
4. **Ghidra HTTP API** — `curl http://localhost:13370/decompile` (requires Ghidra server running)

## Setup for Validation

```powershell
# Always set these before running CLI or tests on Windows
$env:PYTHONIOENCODING = "utf8"
$env:SKIP_SANDBOX = "true"  # in CI where Docker isolation is not needed
$env:SKIP_VOLATILITY = "true"  # in CI where memory dumps are not available

# Start Ghidra server (for decompilation tests)
Start-Process python -ArgumentList "external/ghidra-server/ghidra_http_server.py" -NoNewWindow

# Ollama is already running on port 11434
```

## Runtime Findings

- Ghidra binary installed at `external/ghidra-dist/ghidra_12.0.4_PUBLIC/` after foundation milestone
- Ghidra HTTP server port: **13370** (not 5000)
- Ollama: running, model `qwen2.5-coder:32b-instruct` available
- yara-python: installed after fix-critical-bugs
- ollama package: installed after fix-critical-bugs
- volatility3: installed after volatility3-memory feature

## Validation Concurrency

Machine: 128 GB RAM, 8 cores / 16 logical (AMD Ryzen 7 5800XT)

| Surface | Max Concurrent | Rationale |
|---|---|---|
| pytest (unit) | 4 workers | Low memory per test; 128GB headroom |
| pytest (integration) | 4 workers | Some Ghidra calls but manageable |
| Ghidra headless | 3 | Each instance uses ~2GB RAM |
| Ollama LLM inference | 2 | 32B model uses ~20GB VRAM/RAM |
| Docker sandbox | 3 | Each container lightweight |

## Known Gotchas

- Ghidra headless takes 30-120 seconds to analyze a binary — tests must have generous timeouts
- Ollama qwen2.5-coder:32b-instruct takes 10-60 seconds for typical code queries
- `SKIP_SANDBOX=true` and `SKIP_VOLATILITY=true` should be set in CI to avoid Docker/dump requirements
- Windows path separators: use `pathlib.Path` everywhere, convert to string only at subprocess call boundaries
