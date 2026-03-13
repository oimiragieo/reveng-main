# Environment Setup

Environment variables, external dependencies, and setup notes.

## Installed Packages
- Python 3.14.0, angr 9.2.194, capstone 5.0.3, pefile 2024.8.26, lief 0.17.5
- torch 2.9.1, transformers 4.57.1, huggingface-hub 0.36.0, scikit-learn
- yara-python: MUST INSTALL (`pip install yara-python`)
- ollama: MUST INSTALL (`pip install ollama`)
- volatility3: MUST INSTALL (`pip install volatility3`)

## External Services
- **Ghidra HTTP server**: port 13370 (was 5000, changed to avoid Razer SDK conflict)
- **Ghidra binary**: `external/ghidra-dist/ghidra_12.0.4_PUBLIC/` (installed by ghidra-binary-install feature)
- **Ghidra installer helper**: `python scripts/install_ghidra.py` downloads the pinned GitHub release, extracts into `external/ghidra-dist/`, verifies `support/analyzeHeadless.bat`, and is safe to rerun when the dist already exists
- **Ollama**: port 11434 — ALWAYS RUNNING; model `qwen2.5-coder:32b-instruct` available
- **Docker**: 29.2.1 available; used for sandbox execution

## Windows Gotchas
- Always set `PYTHONIOENCODING=utf8` for CLI output
- Ghidra headless: `analyzeHeadless.bat` (Windows) — NOT `analyzeHeadless` (Linux)
- Subprocess calls with Windows paths need proper quoting — use `pathlib.Path` and `str()`, shell=False
- `.factory/init.sh` does NOT work on Windows — run pip commands directly

## Environment Variables
- `SKIP_SANDBOX=true` — bypass Docker sandbox in tests (set in CI)
- `SKIP_VOLATILITY=true` — bypass Volatility3 in tests (set in CI)
- `GHIDRA_MOCK=true` — force Ghidra mock mode (should raise exception)
- `GEMINI_API_KEY` — optional, for Gemini API fallback
- `ANTHROPIC_API_KEY` — optional, for Claude API fallback
