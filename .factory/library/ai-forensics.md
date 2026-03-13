## AI forensics notes

- `src/reveng/ml/forensics_anomaly_models.py` now provides reusable Isolation Forest-based scorers for behavioral events, memory artifacts, and process metadata. Each scorer normalizes `decision_function()` output into a 0-1 anomaly score and emits human-readable reasons when the score crosses its threshold.
- `src/reveng/malware/behavioral_monitor.py` now computes `anomaly_score`, `anomaly_threshold`, and `anomaly_flags` on `BehavioralProfile`; final risk scoring now promotes the ML anomaly score to the 0-100 risk scale, and suspicious operations can be promoted when the ML threshold is exceeded.
- `src/reveng/malware/memory_forensics.py` now computes ML anomaly scores for `ProcessInfo`, `MemoryArtifact`, and `MemoryAnalysis`; injected-code candidates are flagged from the ML artifact scores instead of static byte-signature hits. The file also now uses a `math.log2` entropy calculation and fixes the incorrect `create_error_context(...)` / `AnalysisFailureError(...)` argument usage encountered during testing.
- Added focused validation in `tests/unit/test_malware_forensics_anomaly_detection.py` covering high-anomaly behavioral profiles, benign behavioral profiles, anomalous memory artifacts, and end-to-end memory-analysis aggregation.
- Relevant validation commands that passed for this feature:
  - `pytest tests/unit/test_gpu_batching_integration.py tests/unit/test_malware_forensics_anomaly_detection.py -q`
  - `flake8 src/reveng/ml/forensics_anomaly_models.py src/reveng/malware/behavioral_monitor.py src/reveng/malware/memory_forensics.py --extend-ignore=E501,F811,E203`
  - `python -m mypy src/reveng/ml/forensics_anomaly_models.py src/reveng/malware/behavioral_monitor.py src/reveng/malware/memory_forensics.py --ignore-missing-imports --follow-imports=skip`
- The scoped baseline from `.factory/services.yaml` is still pre-existing red on unrelated CLI / documentation / ML workflow tests as documented in `AGENTS.md`; use focused validators for this feature until those suite-wide issues are fixed.
