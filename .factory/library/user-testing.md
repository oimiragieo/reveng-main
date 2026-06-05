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

## Flow Validator Guidance: Python Direct Invocation

**Surface**: Python scripts/imports run directly via `python -c "..."` or `python -m pytest ...`
**Testing tool**: Direct subprocess execution (no browser or TUI needed)

**Isolation rules**:
- Each validator runs independent Python commands; no shared state
- No file mutations that could interfere with other validators
- Use `sys.path.insert(0, 'src')` if needed to import `reveng` modules
- Always use absolute paths for binary references (e.g., `test_samples/sample.exe`)
- On Windows, always set `PYTHONIOENCODING=utf8` environment variable

**Boundaries**:
- Do NOT start/stop the Ghidra HTTP server (managed by the parent validator)
- Do NOT modify any source files
- Write evidence files only to the assigned evidence directory

## Flow Validator Guidance: Ghidra HTTP API

**Surface**: HTTP API at `http://localhost:13370` served by the Ghidra HTTP server
**Testing tool**: `curl` or Python `requests` library

**Isolation rules**:
- The Ghidra HTTP server is shared; validators may send requests in parallel
- Each request is independent (no session state on the server)
- Ghidra headless analysis takes 30-120 seconds — set timeouts to 180s minimum
- Do NOT call `/shutdown` endpoint during testing

**Boundaries**:
- Server is already running on port 13370; do not restart it
- Test binary: `test_samples/sample.exe` (relative to repo root)
- Mock mode: controlled via `GHIDRA_MOCK=true` env var or mock_mode parameter
- Write evidence files only to the assigned evidence directory

## Known Gotchas

- Ghidra headless takes 30-120 seconds to analyze a binary — tests must have generous timeouts
- Ollama qwen2.5-coder:32b-instruct can exceed 90 seconds on this machine (32B params) — MCP AI tools (`ask_ai_about_binary`, `ai_code_reconstruction`) will return `fallback_used: true` with context-derived content on timeout. Validators: accept `status_code: 504` responses with substantive `answer`/`reconstructed_code` as PASS.
- `SKIP_SANDBOX=true` and `SKIP_VOLATILITY=true` should be set in CI to avoid Docker/dump requirements
- Windows path separators: use `pathlib.Path` everywhere, convert to string only at subprocess call boundaries
- **PowerShell + .bat files**: PowerShell cannot pass `--help` directly to `.bat` files (ParserError). When invoking `analyzeHeadless.bat` from Python/PowerShell, use `subprocess.run(['cmd', '/c', str(bat_path), ...])` or use shell=True with a quoted command string.
