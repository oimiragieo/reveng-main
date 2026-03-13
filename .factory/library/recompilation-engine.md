## Recompilation engine notes

- `src/reveng/ai/angr_cfg_preprocessor.py` extracts full angr CFG payloads and builds a condensed `cfg_context_text` summary for prompts.
- `BinaryRecompilationEngine._phase1_decompilation(binary_path, output_dir)` now writes `cfg_payload.json` and `cfg_context.txt` into the reconstruction output directory and attaches `cfg_payload`, `cfg_context_text`, `cfg_artifacts`, and `cfg_summary` to `ghidra_data`.
- `GeminiEngine._create_reconstruction_prompt()` now includes `cfg_context_text` when present, so follow-on recompilation/feedback-loop work can reuse that field directly.
- Focused validation: `pytest tests/unit/test_angr_cfg_preprocessor.py -q` and `flake8 src/reveng/ai/angr_cfg_preprocessor.py src/reveng/ai/recompilation_engine.py src/reveng/ai/gemini_engine.py --extend-ignore=E501,F811,E203`.
- Sample manual check used `test_samples/sample.exe`, which currently yields a 214-function / 689-node / 1041-edge CFG on Windows with angr `CFGFast(normalize=True)`.

## Compiler Feedback Loop

- `BinaryRecompilationEngine._compile_with_feedback_loop(compiler, source_file, output_file, output_dir)` implements an iterative recompilation loop: if gcc/clang compilation fails, stderr is captured and fed back to the LLM for source repair.
- Constructor parameter `max_compilation_retries` (default 3) controls how many retry attempts are allowed per compiler before the loop gives up.
- Each attempt produces a structured report with `attempt_number`, `success`, `stderr`, `source_file`, and `return_code`. The full history is preserved in the final report.
- `_run_compiler_attempt(compiler, source_file, output_file)` is the extracted helper that runs `subprocess.run` with timeout and captures stderr.
- `_build_compile_command(compiler, source_file, output_file)` detects ccache/sccache availability and prepends the cache wrapper automatically.
- `_create_compilation_feedback_prompt(source_code, stderr, attempt, max_retries)` builds the LLM repair prompt including cfg_context when available.
- When all compilers exhaust retries, `_phase3_compilation` returns `compilation_success=False` and phases 4-6 of `full_reconstruction_pipeline` are skipped, producing a structured failure report.
- Edge case: `max_compilation_retries=0` means a single compilation attempt with no repair loop; if it fails, the report shows `max_retries_exceeded` immediately.
- Edge case: Non-retryable failures (e.g., subprocess crashes, non-compilation errors) terminate the loop immediately regardless of remaining retries, producing a `non_retryable_failure` report.
- Edge case: If the LLM returns an empty response during the repair loop, the engine treats it as a failed attempt and continues to the next retry.
- Focused validation: `pytest tests/unit/test_recompilation_engine_feedback_loop.py -q`.
