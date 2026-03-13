## Pipeline upgrade notes

- `src/reveng/pipeline/pipeline_engine.py` now exposes `execute_pipeline_async()` and keeps `execute_pipeline()` as a synchronous wrapper.
- Independent DAG stages are scheduled in concurrent waves with `asyncio.gather(...)`; failed stages are isolated, and only downstream dependents are skipped.
- Full baseline `pytest tests/ -n 4` is currently blocked by pre-existing collection failures in `tests/security/test_advanced_malware_classifier.py` (`ModuleNotFoundError: ai_enhanced_data_models` followed by `SystemExit(1)`).
- Targeted validation for this feature passes with `pytest tests/unit/test_pipeline_engine_async.py -n 4`.
