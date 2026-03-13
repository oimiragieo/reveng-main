# Validation Surface

The primary validation surfaces for the REVENG toolkit are:
1. The **CLI Engine** (`src/reveng/cli/reveng.py` and `reveng` executable).
2. The **Python Test Suite** (`pytest` via the `tests/` directory).

## Setup & Gotchas
- **Windows CLI Output:** When running the CLI tests or automation in Windows, you MUST set `PYTHONIOENCODING=utf8` to prevent `charmap` codec errors (e.g. `cmd /c "set PYTHONIOENCODING=utf8 && python reveng.py --help"`).
- **Absolute vs Relative Paths:** Some existing unit tests fail if absolute paths are evaluated against expected relative paths in temp directories. Be mindful when writing new test assertions.

## Validation Concurrency
Based on the dry run and available headroom (where multiple large applications like VSCode, Chrome, Docker are active):
- **Test Suite (Pytest):** Max concurrent workers for `pytest-xdist` should be `4`.
- **CLI Validation (`tuistory` / subprocess execution):** Max concurrent validators is **3**. Running more concurrent instances of Ghidra, angr, and ML models simultaneously will cause severe memory bottlenecks.

## Flow Validator Guidance: Python Test Suite (Pytest)

### Surface Description
The Python test suite (`pytest`) is the primary user-facing surface for verifying pipeline and GPU batching behaviors. Developers invoke `pytest` to validate correctness.

### Isolation Rules
- Each test function creates its own temporary directory (`tmp_path` fixture) and monkeypatches internal methods. Tests are fully isolated from each other.
- No shared mutable state exists between tests — they can run concurrently within the same pytest session using `pytest-xdist`.
- Do NOT modify source files or production code during validation.

### Testing Approach
- Run the relevant test files using `pytest -v --tb=long` and capture full output.
- For VAL-PIPE-001 (async concurrency): The test `test_execute_pipeline_async_runs_stages_concurrently` validates concurrent DAG execution by measuring wall-clock time is less than sequential and verifying branch start times overlap.
- For VAL-PIPE-002 (GPU batching): The tests in `test_gpu_batching_integration.py` validate batch size limits, time-window flushing, and end-to-end memory forensics artifact extraction through batched GPU dispatch.
- For VAL-PIPE-003 (failure isolation): The test `test_execute_pipeline_isolates_failed_branch` validates that a failing branch is isolated, dependent stages are skipped, and independent branches continue successfully.

### Environment Variables
- Set `PYTHONIOENCODING=utf8` on Windows.
- No external services (Ghidra, Ollama) needed for these tests — they use monkeypatched executors.

### Constraints
- Do not exceed pytest-xdist concurrency of 4 workers.
- Do not run tests from `tests/performance` or `tests/poc` — those are out of scope.

## Flow Validator Guidance: Recompilation Engine (Pytest)

### Surface Description
The recompilation engine is validated through unit tests that exercise `AngrCFGPreprocessor` and `BinaryRecompilationEngine` (compiler-in-the-loop feedback). Tests live in:
- `tests/unit/test_angr_cfg_preprocessor.py` — CFG extraction and artifact persistence
- `tests/unit/test_recompilation_engine_feedback_loop.py` — compiler retry, stderr feedback, max retry limit

### Isolation Rules
- Each test uses its own `tmp_path` fixture and monkeypatched internals. Tests are fully isolated.
- `test_extract_cfg_payload_from_sample_pe` requires `test_samples/sample.exe` (pre-existing in the repo). It reads the file but does not modify it.
- Feedback loop tests use `DummyGemini` stubs and fake compiler functions — no real compiler or LLM calls.
- No external services (Ghidra, Ollama, etc.) are needed for these tests.

### Testing Approach
- **VAL-RECOMP-001** (angr CFG Extraction): Run all 3 tests in `test_angr_cfg_preprocessor.py`. The key test `test_extract_cfg_payload_from_sample_pe` verifies real angr CFG extraction against `sample.exe`, checking node/edge counts, function serialization, and LLM context generation. The other tests verify Gemini prompt injection and artifact persistence.
- **VAL-RECOMP-002** (Compiler Retry Behavior): Run `test_compile_with_feedback_loop_retries_and_includes_stderr`. Verifies that after initial compilation failure, stderr is captured, fed to LLM, and a second compilation succeeds.
- **VAL-RECOMP-003** (Max Retries Exceeded): Run `test_compile_with_feedback_loop_stops_at_retry_limit` and `test_full_pipeline_returns_graceful_failure_report_when_compilation_fails`. Verifies the engine stops at max retries, generates a structured failure report, and does not proceed to later pipeline phases.

### Environment Variables
- Set `PYTHONIOENCODING=utf8` on Windows.
- No API keys or external services needed.

### Constraints
- Run tests from the repo root (`C:\dev\projects\reveng-main`).
- Use `--tb=long` for detailed traceback output.
- Do not modify source or test files during validation.

## Flow Validator Guidance: AI Forensics ML Anomaly + MCP (Pytest)

### Surface Description
ML anomaly detection and MCP forensic tool discovery/invocation are validated through dedicated test suites:
- `tests/unit/test_malware_forensics_anomaly_detection.py` — ML anomaly scoring for behavioral profiles, memory artifacts, and end-to-end memory analysis
- `tests/poc/test_mcp_integration.py` — MCP tool discovery (tools/list), schema validation, and tool invocation for YARA scanning, memory dump analysis, and binary diffing

### Isolation Rules
- All tests use monkeypatched internals and temporary directories (`tmp_path` fixture). No shared mutable state.
- MCP tests instantiate `REVENGEnterpriseServer` in-process with rate limiting and audit logging disabled. No network ports are opened.
- ML anomaly tests create `BehavioralMonitor` and `MemoryForensics` instances with monkeypatched time and internal methods.
- Tests can run concurrently without interference.

### Testing Approach
- **VAL-FORENSICS-001** (ML Anomaly Detection): Run all 4 tests in `test_malware_forensics_anomaly_detection.py`. Key behaviors: high-anomaly behavioral profiles exceed threshold with flags, benign activity stays below threshold, memory artifacts get ML anomaly scores, end-to-end memory analysis aggregates ML scores.
- **VAL-FORENSICS-002** (MCP Tool Discovery): Run `test_tools_list_includes_forensic_tools` in `test_mcp_integration.py`. Verifies `scan_yara`, `analyze_memory_dump`, `diff_binaries` appear in tools/list response with correct schemas.
- **VAL-FORENSICS-003** (MCP Tool Invocation): Run `test_scan_yara_tool_returns_structured_matches`, `test_analyze_memory_dump_tool_returns_structured_analysis`, `test_diff_binaries_tool_returns_structured_diff` in `test_mcp_integration.py`. Verifies each tool executes backend logic and returns structured JSON.

### Environment Variables
- Set `PYTHONIOENCODING=utf8` on Windows.
- No API keys or external services needed.

### Constraints
- Run tests from the repo root (`C:\dev\projects\reveng-main`).
- Use `--tb=long` for detailed traceback output.
- Do not modify source or test files during validation.

## Flow Validator Guidance: E2E Pipeline Integration (Pytest + CLI)

### Surface Description
End-to-end pipeline integration is validated through:
- `tests/unit/test_e2e_pipeline_integration.py` — Pipeline generates unified report with dependency context propagation
- `tests/unit/test_unified_cli.py` — CLI handler reports pipeline results correctly
- CLI invocation: `python src/reveng/cli/reveng.py analyze test_samples/sample.exe` — Real CLI execution with graceful fallbacks

### Isolation Rules
- Unit tests use monkeypatched pipeline executors and `tmp_path`. Fully isolated.
- CLI invocation creates output in `analysis_sample/` directory. Does not require external services; falls back to local Capstone disassembly.
- No Ghidra server needed — pipeline gracefully degrades.

### Testing Approach
- **VAL-CROSS-001** (End-to-End Pipeline): 
  1. Run `test_e2e_pipeline_integration.py` — verifies unified report generation with stage dependency propagation and anomaly scores
  2. Run `test_unified_cli.py` — verifies CLI handler correctly routes through `run_end_to_end_analysis`
  3. Run actual CLI: `set PYTHONIOENCODING=utf8 && python src/reveng/cli/reveng.py analyze test_samples/sample.exe` — verifies real pipeline orchestration with graceful degradation

### Environment Variables
- Set `PYTHONIOENCODING=utf8` on Windows.
- No API keys or external services needed for unit tests.
- CLI invocation may try Ghidra (port 5000) then fallback to local analysis.

### Constraints
- Run tests from the repo root (`C:\dev\projects\reveng-main`).
- Use `--tb=long` for detailed traceback output.
- Do not modify source or test files during validation.
