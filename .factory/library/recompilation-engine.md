## Recompilation engine notes

- `src/reveng/ai/angr_cfg_preprocessor.py` extracts full angr CFG payloads and builds a condensed `cfg_context_text` summary for prompts.
- `BinaryRecompilationEngine._phase1_decompilation(binary_path, output_dir)` now writes `cfg_payload.json` and `cfg_context.txt` into the reconstruction output directory and attaches `cfg_payload`, `cfg_context_text`, `cfg_artifacts`, and `cfg_summary` to `ghidra_data`.
- `GeminiEngine._create_reconstruction_prompt()` now includes `cfg_context_text` when present, so follow-on recompilation/feedback-loop work can reuse that field directly.
- Focused validation: `pytest tests/unit/test_angr_cfg_preprocessor.py -q` and `flake8 src/reveng/ai/angr_cfg_preprocessor.py src/reveng/ai/recompilation_engine.py src/reveng/ai/gemini_engine.py --extend-ignore=E501,F811,E203`.
- Sample manual check used `test_samples/sample.exe`, which currently yields a 214-function / 689-node / 1041-edge CFG on Windows with angr `CFGFast(normalize=True)`.
