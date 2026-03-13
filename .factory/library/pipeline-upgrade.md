## Pipeline upgrade notes

- `src/reveng/pipeline/pipeline_engine.py` now exposes `execute_pipeline_async()` and keeps `execute_pipeline()` as a synchronous wrapper.
- Independent DAG stages are scheduled in concurrent waves with `asyncio.gather(...)`; failed stages are isolated, and only downstream dependents are skipped.
- `src/reveng/ml/gpu_accelerator.py` now exposes `queue_memory_forensics_task()`, `dispatch_ready_memory_forensics_tasks()`, `flush_memory_forensics_tasks()`, and `process_memory_forensics_tasks()` for batching memory-region scans with batch-size and wait-window triggers.
- `src/reveng/malware/memory_forensics.py` now routes `_extract_memory_artifacts()` through the GPU batching helper and records dispatch telemetry in `memory_forensics_dispatch_history` / `get_batch_dispatch_history()`.
- `tests/security/test_advanced_malware_classifier.py` now skips all four tests when the optional bare-name imports (`ai_enhanced_data_models`, `ml_malware_classifier`) are unavailable, instead of aborting pytest collection with `SystemExit(1)`.
- `pytest tests/security/test_advanced_malware_classifier.py` now collects 4 tests and reports them as skipped on missing optional deps.
- Full baseline `pytest tests/ -n 4` now gets past collection; the remaining failures are unrelated pre-existing test failures across CLI, automated pipeline, ML workflow, input validation, and POC suites.
- Targeted validation for this feature passes with `pytest tests/unit/test_pipeline_engine_async.py -n 4`.
