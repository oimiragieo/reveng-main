"""
ML-Powered Features for REVENG

Advanced machine learning capabilities for code reconstruction,
anomaly detection, and threat intelligence.
"""

import importlib
from typing import Any

__all__ = [
    # Code Reconstruction
    "MLCodeReconstruction",
    "CodeFragment",
    "ReconstructionResult",
    "ReconstructionTask",
    "ModelType",
    "ThreatIntelligence",
    # Anomaly Detection
    "MLAnomalyDetection",
    "AnomalyResult",
    "AnomalyFeature",
    "AnomalyType",
    "AnomalySeverity",
    "AnomalyModel",
    "ForensicsAnomalyModel",
    # Integration
    "MLIntegration",
    "MLIntegrationConfig",
]

_LAZY_IMPORTS = {
    # Code Reconstruction
    "MLCodeReconstruction": ("reveng.ml.code_reconstruction", "MLCodeReconstruction"),
    "CodeFragment": ("reveng.ml.code_reconstruction", "CodeFragment"),
    "ReconstructionResult": ("reveng.ml.code_reconstruction", "ReconstructionResult"),
    "ReconstructionTask": ("reveng.ml.code_reconstruction", "ReconstructionTask"),
    "ModelType": ("reveng.ml.code_reconstruction", "ModelType"),
    "ThreatIntelligence": ("reveng.ml.code_reconstruction", "ThreatIntelligence"),
    # Anomaly Detection
    "MLAnomalyDetection": ("reveng.ml.anomaly_detection", "MLAnomalyDetection"),
    "AnomalyResult": ("reveng.ml.anomaly_detection", "AnomalyResult"),
    "AnomalyFeature": ("reveng.ml.anomaly_detection", "AnomalyFeature"),
    "AnomalyType": ("reveng.ml.anomaly_detection", "AnomalyType"),
    "AnomalySeverity": ("reveng.ml.anomaly_detection", "AnomalySeverity"),
    "AnomalyModel": ("reveng.ml.anomaly_detection", "AnomalyModel"),
    "ForensicsAnomalyModel": (
        "reveng.ml.forensics_anomaly_models",
        "ForensicsAnomalyModel",
    ),
    # Integration
    "MLIntegration": ("reveng.ml.integration", "MLIntegration"),
    "MLIntegrationConfig": ("reveng.ml.integration", "MLIntegrationConfig"),
}


def __getattr__(name: str) -> Any:
    """Lazily import ML exports to avoid eager optional-dependency loading."""
    try:
        module_name, attribute_name = _LAZY_IMPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'") from exc

    module = importlib.import_module(module_name)
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value
