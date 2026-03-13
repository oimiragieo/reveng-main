## AI forensics notes

- `src/reveng/ml/forensics_anomaly_models.py` now provides reusable Isolation Forest-based scorers for behavioral events, memory artifacts, and process metadata. Each scorer normalizes `decision_function()` output into a 0-1 anomaly score and emits human-readable reasons when the score crosses its threshold.
- `src/reveng/ml/forensics_anomaly_models.py` now caches one trained singleton instance per concrete forensics anomaly model class, so `BehavioralAnomalyModel`, `MemoryArtifactAnomalyModel`, and `MemoryProcessAnomalyModel` only fit their Isolation Forest pipelines once per process instead of retraining on every `BehavioralMonitor` / `MemoryForensics` instantiation.
- `src/reveng/malware/behavioral_monitor.py` now computes `anomaly_score`, `anomaly_threshold`, and `anomaly_flags` on `BehavioralProfile`; final risk scoring now promotes the ML anomaly score to the 0-100 risk scale, and suspicious operations can be promoted when the ML threshold is exceeded.
- `src/reveng/malware/memory_forensics.py` now computes ML anomaly scores for `ProcessInfo`, `MemoryArtifact`, and `MemoryAnalysis`; injected-code candidates are flagged from the ML artifact scores instead of static byte-signature hits. The file also now uses a `math.log2` entropy calculation and fixes the incorrect `create_error_context(...)` / `AnalysisFailureError(...)` argument usage encountered during testing.
- `tests/unit/test_malware_forensics_anomaly_detection.py` now also verifies that each cached forensics anomaly model class trains only once across repeated instantiations, in addition to the existing high-anomaly behavioral profiles, benign behavioral profiles, anomalous memory artifacts, and end-to-end memory-analysis aggregation coverage.
- Relevant validation commands that passed for this feature:
  - `pytest tests/unit/test_gpu_batching_integration.py tests/unit/test_malware_forensics_anomaly_detection.py -q`
  - `pytest tests/unit/test_malware_forensics_anomaly_detection.py -v`
  - `python -m mypy src/reveng/ml/forensics_anomaly_models.py --ignore-missing-imports --follow-imports=skip`
  - `python -m flake8 src/reveng/ml/forensics_anomaly_models.py tests/unit/test_malware_forensics_anomaly_detection.py --extend-ignore=E501,F811,E203`
  - `flake8 src/reveng/ml/forensics_anomaly_models.py src/reveng/malware/behavioral_monitor.py src/reveng/malware/memory_forensics.py --extend-ignore=E501,F811,E203`
  - `python -m mypy src/reveng/ml/forensics_anomaly_models.py src/reveng/malware/behavioral_monitor.py src/reveng/malware/memory_forensics.py --ignore-missing-imports --follow-imports=skip`
- The scoped baseline from `.factory/services.yaml` is still pre-existing red on unrelated CLI / documentation / ML workflow tests as documented in `AGENTS.md`; use focused validators for this feature until those suite-wide issues are fixed.

## E2E pipeline integration notes

- `src/reveng/pipeline/pipeline_engine.py` now supports stage-scoped dependency context via `_get_stage_context()`, adds `StageType.RECOMPILATION`, and provides concrete end-to-end handlers for:
  - `GHIDRA_ANALYSIS` with `mode="e2e_disassembly"` (tries `http://127.0.0.1:5000`, then `http://127.0.0.1:13370`, then falls back to `local_capstone`)
  - `RECOMPILATION`
  - `MALWARE_ANALYSIS` with `mode="behavioral_forensics"`
  - `ML_ANALYSIS` with `mode="memory_forensics"`
  - `REPORT_GENERATION` with `mode="unified_e2e_report"`
- `src/reveng/pipeline/e2e_integration.py` introduces `EndToEndPipelineRunner`, which builds the CLI end-to-end pipeline in this order: disassembly → recompilation → behavioral/memory forensics → unified report.
- `src/reveng/cli.py` now routes `reveng analyze ...` through `run_end_to_end_analysis(...)` after using `REVENGAnalyzer` only for path/output resolution. The CLI prints the unified report path and anomaly scores and returns success for `success` or `partial_success` pipeline outcomes.
- `src/reveng/cli/reveng.py` is a direct wrapper so the Windows/manual verification command `python src/reveng/cli/reveng.py analyze <binary>` now works.
- `tests/unit/test_e2e_pipeline_integration.py` verifies dependency output propagation into the unified report and checks that the CLI handler reports the end-to-end pipeline result.
- Focused validation that passed for this feature:
  - `pytest tests/unit/test_pipeline_engine_async.py tests/unit/test_e2e_pipeline_integration.py tests/unit/test_unified_cli.py -q`
  - `flake8 src/reveng/pipeline/pipeline_engine.py src/reveng/pipeline/e2e_integration.py src/reveng/cli.py src/reveng/cli/reveng.py tests/unit/test_e2e_pipeline_integration.py --extend-ignore=E501,F811,E203`
  - `python -m mypy src/reveng/pipeline/pipeline_engine.py src/reveng/pipeline/e2e_integration.py src/reveng/cli.py src/reveng/cli/reveng.py --ignore-missing-imports --follow-imports=skip`
  - `PYTHONIOENCODING=utf8 python src/reveng/cli/reveng.py analyze test_samples/sample.exe`
- Current manual behavior on Windows without a running Ghidra server is still useful: the pipeline falls back to local Capstone disassembly, generates `analysis_sample/reports/unified_analysis_report.json`, and reports `partial_success` if recompilation cannot recover from missing Gemini-assisted compiler fixes.
