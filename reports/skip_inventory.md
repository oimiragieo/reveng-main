# REVENG Skip-Lane Inventory

- Generated at: `2026-03-29T23:58:40.925121Z`
- Tests root: `C:\dev\projects\reveng-main\tests`
- Total skip sites: `65`

## Category Summary

- `asset_or_fixture`: `24`
- `external_tooling`: `31`
- `known_gap`: `3`
- `service_environment`: `1`
- `uncategorized`: `6`

## Kind Summary

- `runtime_skip`: `57`
- `skip`: `8`

## Skip Sites

- `tests\integration\test_app_reverse_engineering_external_tools.py:43` `runtime_skip` `asset_or_fixture`: sample_dotnet.dll fixture is missing
- `tests\integration\test_cli.py:358` `runtime_skip` `external_tooling`: Java sample not found
- `tests\integration\test_cli.py:375` `runtime_skip` `external_tooling`: Java sample not found
- `tests\integration\test_cli.py:483` `runtime_skip` `external_tooling`: Java sample not found
- `tests\integration\test_cli.py:602` `runtime_skip` `external_tooling`: Java sample not found
- `tests\integration\test_cli.py:616` `runtime_skip` `asset_or_fixture`: Windows bootstrap script not found
- `tests\integration\test_cli.py:623` `runtime_skip` `asset_or_fixture`: Linux bootstrap script not found
- `tests\integration\test_cli.py:643` `runtime_skip` `asset_or_fixture`: Cleanup script not found
- `tests\integration\test_documentation.py:125` `runtime_skip` `uncategorized`: Could not test external link {url}: {exc}
- `tests\integration\test_e2e_cli.py:35` `runtime_skip` `external_tooling`: Ghidra service unavailable: {exc}
- `tests\integration\test_e2e_cli.py:38` `runtime_skip` `external_tooling`: Ghidra health endpoint is up but reports ghidra_available=false
- `tests\integration\test_e2e_cli.py:45` `runtime_skip` `service_environment`: Ollama service unavailable: {exc}
- `tests\integration\test_e2e_cli.py:49` `runtime_skip` `uncategorized`: Required Ollama model not available: {OLLAMA_MODEL}
- `tests\integration\test_e2e_cli.py:65` `runtime_skip` `asset_or_fixture`: Native sample binary not found
- `tests\integration\test_examples.py:23` `runtime_skip` `asset_or_fixture`: Analysis template not found
- `tests\integration\test_examples.py:40` `runtime_skip` `asset_or_fixture`: Basic examples directory not found
- `tests\integration\test_examples.py:62` `runtime_skip` `asset_or_fixture`: Advanced examples directory not found
- `tests\integration\test_examples.py:84` `runtime_skip` `asset_or_fixture`: Examples README not found
- `tests\integration\test_examples.py:101` `runtime_skip` `asset_or_fixture`: Template or sample not found
- `tests\integration\test_examples.py:117` `runtime_skip` `asset_or_fixture`: Basic examples not found
- `tests\integration\test_examples.py:122` `runtime_skip` `asset_or_fixture`: No analysis examples found
- `tests\integration\test_examples.py:126` `runtime_skip` `asset_or_fixture`: Sample file not found
- `tests\integration\test_examples.py:148` `runtime_skip` `asset_or_fixture`: Example outputs directory not found
- `tests\integration\test_examples.py:158` `runtime_skip` `asset_or_fixture`: Example outputs directory not found
- `tests\integration\test_examples.py:176` `runtime_skip` `asset_or_fixture`: Examples README not found
- `tests\integration\test_examples.py:189` `runtime_skip` `asset_or_fixture`: Examples directory not found
- `tests\integration\test_ml_enhancements.py:76` `runtime_skip` `external_tooling`: ML vulnerability predictor dependencies not available: {e}
- `tests\integration\test_ml_enhancements.py:150` `runtime_skip` `external_tooling`: ML malware classifier dependencies not available: {e}
- `tests\integration\test_ml_enhancements.py:153` `runtime_skip` `known_gap`: Legacy malware classifier API mismatch: {e}
- `tests\integration\test_ml_enhancements.py:274` `runtime_skip` `external_tooling`: NLP analyzer dependencies not available: {e}
- `tests\integration\test_ml_enhancements.py:390` `runtime_skip` `external_tooling`: ML pipeline dependencies not available: {e}
- `tests\integration\test_symbolic_execution_integration.py:54` `runtime_skip` `external_tooling`: angr not available: {e}
- `tests\integration\test_symbolic_execution_integration.py:74` `runtime_skip` `external_tooling`: Dependencies not available: {e}
- `tests\integration\test_symbolic_execution_integration.py:110` `runtime_skip` `external_tooling`: Dependencies not available: {e}
- `tests\performance\test_incremental_compilation.py:88` `runtime_skip` `external_tooling`: Compiler cache not available. Install ccache or sccache.
- `tests\performance\test_incremental_compilation.py:150` `runtime_skip` `external_tooling`: Cache backend did not report a warm-cache hit in this environment
- `tests\performance\test_incremental_compilation.py:176` `runtime_skip` `external_tooling`: Compiler cache not available. Install ccache or sccache.
- `tests\performance\test_incremental_compilation.py:225` `runtime_skip` `external_tooling`: Compiler cache not available.
- `tests\performance\test_incremental_compilation.py:276` `runtime_skip` `external_tooling`: Compiler cache not available.
- `tests\poc\test_llm4decompile_poc.py:65` `runtime_skip` `uncategorized`: Failed to compile test binary: {result.stderr.decode()}
- `tests\poc\test_llm4decompile_poc.py:109` `runtime_skip` `external_tooling`: LLM4Decompile dependencies not available: {e}
- `tests\poc\test_llm4decompile_poc.py:144` `runtime_skip` `external_tooling`: LLM4Decompile dependencies not available: {e}
- `tests\poc\test_llm4decompile_poc.py:177` `runtime_skip` `external_tooling`: LLM4Decompile dependencies not available: {e}
- `tests\poc\test_llm4decompile_poc.py:225` `runtime_skip` `external_tooling`: LLM4Decompile dependencies not available: {e}
- `tests\poc\test_llm4decompile_poc.py:243` `runtime_skip` `external_tooling`: Ensemble dependencies not available: {e}
- `tests\poc\test_symbolic_execution_poc.py:77` `runtime_skip` `uncategorized`: Failed to compile vulnerable binary: {result.stderr.decode()}
- `tests\poc\test_symbolic_execution_poc.py:116` `runtime_skip` `uncategorized`: Failed to compile vulnerable binary
- `tests\poc\test_symbolic_execution_poc.py:172` `runtime_skip` `external_tooling`: Dependencies not available: {e}
- `tests\poc\test_symbolic_execution_poc.py:218` `runtime_skip` `external_tooling`: Dependencies not available: {e}
- `tests\poc\test_symbolic_execution_poc.py:240` `runtime_skip` `uncategorized`: No vulnerabilities found for exploit generation test
- `tests\poc\test_symbolic_execution_poc.py:267` `runtime_skip` `external_tooling`: Dependencies not available: {e}
- `tests\unit\test_analyzer.py:96` `skip` `known_gap`: Ollama checking functionality not implemented in current analyzer
- `tests\unit\test_analyzer.py:125` `skip` `known_gap`: Ollama checking functionality not implemented in current analyzer
- `tests\unit\test_analyzer.py:182` `skip` `asset_or_fixture`: Internal step methods testing - requires mock_analyzer fixture
- `tests\unit\test_analyzer.py:193` `skip` `asset_or_fixture`: Internal step methods testing - requires mock_analyzer fixture
- `tests\unit\test_analyzer.py:206` `skip` `asset_or_fixture`: Internal step methods testing - requires mock_analyzer fixture
- `tests\unit\test_analyzer.py:216` `skip` `asset_or_fixture`: Internal step methods testing - requires mock_analyzer fixture
- `tests\unit\test_analyzer.py:230` `skip` `asset_or_fixture`: Internal step methods testing - requires mock_analyzer fixture
- `tests\unit\test_analyzer.py:242` `skip` `asset_or_fixture`: Internal step methods testing - requires mock_analyzer fixture
- `tests\unit\test_angr_cfg_preprocessor.py:19` `runtime_skip` `asset_or_fixture`: PE sample missing from test_samples/sample.exe
- `tests\unit\test_installation.py:72` `runtime_skip` `external_tooling`: Java not available (optional)
- `tests\unit\test_installation.py:78` `runtime_skip` `external_tooling`: Ghidra not available (optional)
- `tests\unit\test_installation.py:99` `runtime_skip` `external_tooling`: No Unix compilers on Windows (optional)
- `tests\unit\test_installation.py:133` `runtime_skip` `external_tooling`: Toolchain check timed out
- `tests\unit\test_installation.py:135` `runtime_skip` `external_tooling`: Toolchain check script not found
