# RE Platform Architecture

Key facts for workers implementing the REVENG production-grade RE platform.

## Ghidra Integration

- **Binary location**: `external/ghidra-dist/ghidra_12.0.4_PUBLIC/support/analyzeHeadless.bat` (Windows)
- **HTTP server**: `external/ghidra-server/ghidra_http_server.py` runs on port **13370**
- **Jython export script**: `external/ghidra-server/scripts/ExportAnalysisJSON.py`
- **GhidraEngine client**: `src/reveng/integrations/ghidra/ghidra_engine.py` — has `analyze_binary()`, needs `decompile()` added
- **IMPORTANT**: When Ghidra unavailable, raise `GhidraUnavailableError` — NEVER return mock data silently

## Ollama Integration

- **Running**: `http://localhost:11434` — always running
- **Best model for code**: `qwen2.5-coder:32b-instruct`
- **Python package**: `pip install ollama` (NOT installed yet at mission start)
- **Fallback**: Use HTTP API directly: `POST http://localhost:11434/api/chat`
- **Timeout**: 90 seconds for code queries, 30 seconds for classification

## MCP Server

- **Location**: `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py`
- **5 stub tools** (return "coming soon"): `recompile_binary`, `generate_exploit`, `classify_malware`, `ask_ai_about_binary` / `query_ai`, `ai_code_reconstruction` / `reconstruct_code_with_ai`
- **1 broken tool**: `decompile_binary` — calls `ghidra.decompile()` which doesn't exist → `AttributeError`
- **Tool count**: 15 total (must stay >= 15)

## YARA Integration

- **Package**: `yara-python` (NOT installed at mission start) — install via `pip install yara-python`
- **Import name**: `import yara` (NOT `import yara_python`)
- **Built-in rules**: Store in `src/reveng/security/yara_rules/*.yar`
- **Scanner class**: Create `src/reveng/security/yara_scanner.py`

## Docker Sandbox

- **Docker**: Available on host (Docker 29.2.1)
- **Sandbox image**: `python:3.11-slim` (no malware execution; use for behavioral tracing only)
- **Env var bypass**: `SKIP_SANDBOX=true` → return `{"sandbox_available": false}` gracefully (for CI)
- **Current broken code**: `behavioral_monitor.py` calls `powershell Get-Process` on HOST — must be replaced

## Memory Forensics

- **Volatility3**: Install via `pip install volatility3`
- **Import**: `import volatility3.framework`
- **Current broken code**: `memory_forensics.py` calls `wmic process get` on HOST — must be replaced
- **Env var bypass**: `SKIP_VOLATILITY=true` → use minimal mock for CI

## Key Files to NOT Modify

- `external/ghidra/` — Ghidra source code (leave completely alone)
- `src/reveng/pipeline/pipeline_engine.py` — async DAG pipeline (already production-quality)
- `src/reveng/ai/angr_cfg_preprocessor.py` — CFG extraction (already working)
- `src/reveng/ml/forensics_anomaly_models.py` — IsolationForest models (already working with singleton cache)
