# `claude.md` — `ml`

**Repository path:** `src/reveng/ml/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** ML-Powered Features for REVENG
- **Functions / coroutines:**
  - `def __getattr__()` — Lazily import ML exports to avoid eager optional-dependency loading.

### `anomaly_detection.py`
- **Summary:** ML-Powered Anomaly Detection for REVENG
- **Classes:**
  - `AnomalyType` — Types of anomalies
  - `AnomalySeverity` — Anomaly severity levels
  - `AnomalyFeature` — Feature for anomaly detection
  - `AnomalyResult` — Anomaly detection result
  - `AnomalyModel` — Anomaly detection model
  - `MLAnomalyDetection` — ML-powered anomaly detection engine

### `code_reconstruction.py`
- **Summary:** ML-Powered Code Reconstruction for REVENG
- **Classes:**
  - `ModelType` — ML model types
  - `ReconstructionTask` — Reconstruction tasks
  - `CodeFragment` — Code fragment for reconstruction
  - `ReconstructionResult` — Code reconstruction result
  - `ThreatIntelligence` — Threat intelligence result
  - `MLCodeReconstruction` — ML-powered code reconstruction engine

### `forensics_anomaly_models.py`
- **Summary:** Lightweight ML anomaly models for malware forensics workflows.
- **Classes:**
  - `MLAnomalyAssessment` — Normalized anomaly assessment returned by the forensics models.
  - `_IsolationForestFeatureModel` — Shared feature-vector anomaly model backed by Isolation Forest.
  - `BehavioralAnomalyModel` — ML anomaly model for behavioral monitor event streams.
  - `MemoryArtifactAnomalyModel` — ML anomaly model for extracted memory region artifacts.
  - `MemoryProcessAnomalyModel` — ML anomaly model for suspicious process behavior inside memory analysis.
  - `ForensicsAnomalyModel` — ML anomaly model for static malware triage on binary file features.
- **Functions / coroutines:**
  - `def _calculate_entropy()` — Calculate Shannon entropy for a byte string.
  - `def _calculate_ascii_ratio()` — Estimate the printable ASCII ratio for a memory region.

### `gpu_accelerator.py`
- **Summary:** GPU Acceleration Framework - 10-100x Batch Processing Speedup
- **Classes:**
  - `DeviceType` — Supported GPU acceleration devices
  - `GPUInfo` — GPU device information
  - `BatchProcessingResult` — Result from batch processing
  - `QueuedMemoryForensicsTask` — Queued memory forensics task awaiting batched dispatch.
  - `MemoryForensicsBatchDispatch` — Telemetry for a single memory forensics batch dispatch.
  - `GPUAccelerator` — GPU acceleration manager for ML models
  - `BatchDecompiler` — Batch decompilation with GPU acceleration

### `integration.py`
- **Summary:** ML Integration Module for REVENG
- **Classes:**
  - `MLIntegrationConfig` — Configuration for ML integration
  - `MLIntegration` — ML integration engine for REVENG

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
