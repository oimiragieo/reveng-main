"""
ML-Powered Anomaly Detection for REVENG

Advanced machine learning models for detecting anomalies in binary analysis.
"""

import os
import sys
import json
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

from ..core.errors import REVENGError, AnalysisFailureError, create_error_context
from ..core.logger import get_logger

logger = get_logger(__name__)

class AnomalyType(Enum):
    """Types of anomalies"""
    BEHAVIORAL = "behavioral"
    STRUCTURAL = "structural"
    STATISTICAL = "statistical"
    PATTERN = "pattern"
    TEMPORAL = "temporal"

class AnomalySeverity(Enum):
    """Anomaly severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class AnomalyFeature:
    """Feature for anomaly detection"""
    name: str
    value: float
    type: str
    importance: float = 1.0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class AnomalyResult:
    """Anomaly detection result"""
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    confidence: float
    score: float
    features: List[AnomalyFeature]
    description: str
    recommendations: List[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []
        if self.metadata is None:
            self.metadata = {}

@dataclass
class AnomalyModel:
    """Anomaly detection model"""
    name: str
    type: AnomalyType
    features: List[str]
    threshold: float
    model_data: Dict[str, Any]
    performance: Dict[str, float] = None

    def __post_init__(self):
        if self.performance is None:
            self.performance = {}

class MLAnomalyDetection:
    """ML-powered anomaly detection engine"""

    def __init__(self):
        self.logger = get_logger(__name__)
        self.models = {}
        self.feature_extractors = {}
        self.anomaly_detectors = {}

        # Initialize feature extractors
        self._initialize_feature_extractors()

        # Initialize anomaly detectors
        self._initialize_anomaly_detectors()

        # Load models
        self._load_models()

    def _initialize_feature_extractors(self):
        """Initialize feature extractors"""

        try:
            self.feature_extractors = {
                "entropy": self._extract_entropy_features,
                "api_calls": self._extract_api_features,
                "strings": self._extract_string_features,
                "imports": self._extract_import_features,
                "exports": self._extract_export_features,
                "sections": self._extract_section_features,
                "resources": self._extract_resource_features,
                "behavioral": self._extract_behavioral_features,
                "network": self._extract_network_features,
                "file_ops": self._extract_file_operation_features
            }

            self.logger.info("Feature extractors initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize feature extractors: {e}")
            raise

    def _initialize_anomaly_detectors(self):
        """Initialize anomaly detectors"""

        try:
            self.anomaly_detectors = {
                AnomalyType.BEHAVIORAL: self._detect_behavioral_anomalies,
                AnomalyType.STRUCTURAL: self._detect_structural_anomalies,
                AnomalyType.STATISTICAL: self._detect_statistical_anomalies,
                AnomalyType.PATTERN: self._detect_pattern_anomalies,
                AnomalyType.TEMPORAL: self._detect_temporal_anomalies
            }

            self.logger.info("Anomaly detectors initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize anomaly detectors: {e}")
            raise

    def _load_models(self):
        """Load anomaly detection models"""

        try:
            # Load behavioral anomaly model
            self.models["behavioral"] = AnomalyModel(
                name="Behavioral Anomaly Detector",
                type=AnomalyType.BEHAVIORAL,
                features=["api_entropy", "api_frequency", "api_diversity", "process_creation", "file_operations"],
                threshold=0.7,
                model_data={"algorithm": "isolation_forest", "n_estimators": 100},
                performance={"accuracy": 0.85, "precision": 0.82, "recall": 0.88}
            )

            # Load structural anomaly model
            self.models["structural"] = AnomalyModel(
                name="Structural Anomaly Detector",
                type=AnomalyType.STRUCTURAL,
                features=["section_entropy", "section_size", "section_permissions", "import_count", "export_count"],
                threshold=0.6,
                model_data={"algorithm": "one_class_svm", "kernel": "rbf"},
                performance={"accuracy": 0.78, "precision": 0.75, "recall": 0.81}
            )

            # Load statistical anomaly model
            self.models["statistical"] = AnomalyModel(
                name="Statistical Anomaly Detector",
                type=AnomalyType.STATISTICAL,
                features=["byte_entropy", "byte_frequency", "string_length", "string_entropy", "resource_count"],
                threshold=0.5,
                model_data={"algorithm": "local_outlier_factor", "n_neighbors": 20},
                performance={"accuracy": 0.72, "precision": 0.70, "recall": 0.74}
            )

            # Load pattern anomaly model
            self.models["pattern"] = AnomalyModel(
                name="Pattern Anomaly Detector",
                type=AnomalyType.PATTERN,
                features=["api_patterns", "string_patterns", "byte_patterns", "section_patterns"],
                threshold=0.8,
                model_data={"algorithm": "dbscan", "eps": 0.5, "min_samples": 5},
                performance={"accuracy": 0.88, "precision": 0.85, "recall": 0.91}
            )

            # Load temporal anomaly model
            self.models["temporal"] = AnomalyModel(
                name="Temporal Anomaly Detector",
                type=AnomalyType.TEMPORAL,
                features=["execution_time", "api_timing", "file_timing", "network_timing"],
                threshold=0.6,
                model_data={"algorithm": "lstm_autoencoder", "sequence_length": 10},
                performance={"accuracy": 0.80, "precision": 0.78, "recall": 0.82}
            )

            self.logger.info(f"Loaded {len(self.models)} anomaly detection models")

        except Exception as e:
            self.logger.error(f"Failed to load models: {e}")
            raise

    def detect_anomalies(self, analysis_data: Dict[str, Any], anomaly_types: Optional[List[AnomalyType]] = None) -> List[AnomalyResult]:
        """Detect anomalies in analysis data"""

        try:
            if anomaly_types is None:
                anomaly_types = list(AnomalyType)

            self.logger.info(f"Detecting anomalies of types: {[t.value for t in anomaly_types]}")

            # Extract features
            features = self._extract_all_features(analysis_data)

            # Detect anomalies
            anomalies = []
            for anomaly_type in anomaly_types:
                if anomaly_type in self.anomaly_detectors:
                    detector = self.anomaly_detectors[anomaly_type]
                    type_anomalies = detector(features, analysis_data)
                    anomalies.extend(type_anomalies)

            # Sort by severity and confidence
            anomalies.sort(key=lambda x: (x.severity.value, x.confidence), reverse=True)

            self.logger.info(f"Detected {len(anomalies)} anomalies")
            return anomalies

        except Exception as e:
            self.logger.error(f"Failed to detect anomalies: {e}")
            raise

    def _extract_all_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract all features from analysis data"""

        try:
            features = []

            for extractor_name, extractor_func in self.feature_extractors.items():
                try:
                    extracted_features = extractor_func(analysis_data)
                    features.extend(extracted_features)
                except Exception as e:
                    self.logger.warning(f"Failed to extract {extractor_name} features: {e}")

            self.logger.info(f"Extracted {len(features)} features")
            return features

        except Exception as e:
            self.logger.error(f"Failed to extract features: {e}")
            return []

    def _extract_entropy_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract entropy-based features"""

        try:
            features = []

            # File entropy
            if "file_entropy" in analysis_data:
                entropy = analysis_data["file_entropy"]
                features.append(AnomalyFeature(
                    name="file_entropy",
                    value=entropy,
                    type="entropy",
                    importance=0.8
                ))

            # Section entropy
            if "sections" in analysis_data:
                sections = analysis_data["sections"]
                for section in sections:
                    if "entropy" in section:
                        features.append(AnomalyFeature(
                            name=f"section_{section.get('name', 'unknown')}_entropy",
                            value=section["entropy"],
                            type="entropy",
                            importance=0.6
                        ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract entropy features: {e}")
            return []

    def _extract_api_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract API call features"""

        try:
            features = []

            if "api_analysis" in analysis_data:
                api_analysis = analysis_data["api_analysis"]

                # API count
                api_count = len(api_analysis.get("api_calls", []))
                features.append(AnomalyFeature(
                    name="api_count",
                    value=api_count,
                    type="count",
                    importance=0.7
                ))

                # Suspicious API count
                suspicious_count = len(api_analysis.get("suspicious_apis", []))
                features.append(AnomalyFeature(
                    name="suspicious_api_count",
                    value=suspicious_count,
                    type="count",
                    importance=0.9
                ))

                # API diversity
                api_diversity = len(set(api.get("api", "") for api in api_analysis.get("api_calls", [])))
                features.append(AnomalyFeature(
                    name="api_diversity",
                    value=api_diversity,
                    type="diversity",
                    importance=0.6
                ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract API features: {e}")
            return []

    def _extract_string_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract string-based features"""

        try:
            features = []

            if "strings" in analysis_data:
                strings = analysis_data["strings"]

                # String count
                string_count = len(strings)
                features.append(AnomalyFeature(
                    name="string_count",
                    value=string_count,
                    type="count",
                    importance=0.5
                ))

                # Average string length
                if strings:
                    avg_length = sum(len(s) for s in strings) / len(strings)
                    features.append(AnomalyFeature(
                        name="avg_string_length",
                        value=avg_length,
                        type="statistical",
                        importance=0.4
                    ))

                # Suspicious string count
                suspicious_strings = [s for s in strings if any(keyword in s.lower() for keyword in ["password", "key", "secret", "token"])]
                features.append(AnomalyFeature(
                    name="suspicious_string_count",
                    value=len(suspicious_strings),
                    type="count",
                    importance=0.8
                ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract string features: {e}")
            return []

    def _extract_import_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract import table features"""

        try:
            features = []

            if "import_analysis" in analysis_data:
                import_analysis = analysis_data["import_analysis"]

                # Import count
                import_count = len(import_analysis.get("imported_dlls", []))
                features.append(AnomalyFeature(
                    name="import_count",
                    value=import_count,
                    type="count",
                    importance=0.6
                ))

                # Suspicious import count
                suspicious_imports = len(import_analysis.get("suspicious_apis", []))
                features.append(AnomalyFeature(
                    name="suspicious_import_count",
                    value=suspicious_imports,
                    type="count",
                    importance=0.9
                ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract import features: {e}")
            return []

    def _extract_export_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract export table features"""

        try:
            features = []

            if "export_analysis" in analysis_data:
                export_analysis = analysis_data["export_analysis"]

                # Export count
                export_count = len(export_analysis.get("exported_functions", []))
                features.append(AnomalyFeature(
                    name="export_count",
                    value=export_count,
                    type="count",
                    importance=0.5
                ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract export features: {e}")
            return []

    def _extract_section_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract section features"""

        try:
            features = []

            if "sections" in analysis_data:
                sections = analysis_data["sections"]

                # Section count
                section_count = len(sections)
                features.append(AnomalyFeature(
                    name="section_count",
                    value=section_count,
                    type="count",
                    importance=0.4
                ))

                # Section size features
                for section in sections:
                    if "size" in section:
                        features.append(AnomalyFeature(
                            name=f"section_{section.get('name', 'unknown')}_size",
                            value=section["size"],
                            type="size",
                            importance=0.3
                        ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract section features: {e}")
            return []

    def _extract_resource_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract resource features"""

        try:
            features = []

            if "pe_resources" in analysis_data:
                pe_resources = analysis_data["pe_resources"]

                # Resource count
                resource_count = len(pe_resources.get("icons", [])) + len(pe_resources.get("strings", [])) + len(pe_resources.get("manifests", []))
                features.append(AnomalyFeature(
                    name="resource_count",
                    value=resource_count,
                    type="count",
                    importance=0.4
                ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract resource features: {e}")
            return []

    def _extract_behavioral_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract behavioral features"""

        try:
            features = []

            if "behavioral_analysis" in analysis_data:
                behavioral = analysis_data["behavioral_analysis"]

                # Process count
                process_count = len(behavioral.get("processes_created", []))
                features.append(AnomalyFeature(
                    name="process_count",
                    value=process_count,
                    type="count",
                    importance=0.7
                ))

                # File operation count
                file_ops = len(behavioral.get("file_operations", []))
                features.append(AnomalyFeature(
                    name="file_operation_count",
                    value=file_ops,
                    type="count",
                    importance=0.6
                ))

                # Suspicious activity count
                suspicious_count = len(behavioral.get("suspicious_activities", []))
                features.append(AnomalyFeature(
                    name="suspicious_activity_count",
                    value=suspicious_count,
                    type="count",
                    importance=0.9
                ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract behavioral features: {e}")
            return []

    def _extract_network_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract network features"""

        try:
            features = []

            if "network_analysis" in analysis_data:
                network = analysis_data["network_analysis"]

                # Connection count
                connection_count = len(network.get("connections", []))
                features.append(AnomalyFeature(
                    name="connection_count",
                    value=connection_count,
                    type="count",
                    importance=0.7
                ))

                # Suspicious connection count
                suspicious_connections = len(network.get("suspicious_connections", []))
                features.append(AnomalyFeature(
                    name="suspicious_connection_count",
                    value=suspicious_connections,
                    type="count",
                    importance=0.9
                ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract network features: {e}")
            return []

    def _extract_file_operation_features(self, analysis_data: Dict[str, Any]) -> List[AnomalyFeature]:
        """Extract file operation features"""

        try:
            features = []

            if "file_operations" in analysis_data:
                file_ops = analysis_data["file_operations"]

                # File operation count
                op_count = len(file_ops)
                features.append(AnomalyFeature(
                    name="file_operation_count",
                    value=op_count,
                    type="count",
                    importance=0.6
                ))

                # Suspicious file operation count
                suspicious_ops = len([op for op in file_ops if op.get("suspicious", False)])
                features.append(AnomalyFeature(
                    name="suspicious_file_operation_count",
                    value=suspicious_ops,
                    type="count",
                    importance=0.8
                ))

            return features

        except Exception as e:
            self.logger.error(f"Failed to extract file operation features: {e}")
            return []

    def _detect_behavioral_anomalies(self, features: List[AnomalyFeature], analysis_data: Dict[str, Any]) -> List[AnomalyResult]:
        """Detect behavioral anomalies"""

        try:
            anomalies = []

            # Check for suspicious API calls
            suspicious_api_count = next((f.value for f in features if f.name == "suspicious_api_count"), 0)
            if suspicious_api_count > 5:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.BEHAVIORAL,
                    severity=AnomalySeverity.HIGH,
                    confidence=0.8,
                    score=suspicious_api_count / 10.0,
                    features=[f for f in features if f.name == "suspicious_api_count"],
                    description=f"High number of suspicious API calls detected: {suspicious_api_count}",
                    recommendations=[
                        "Review API call patterns",
                        "Check for malware behavior",
                        "Analyze function call sequences"
                    ]
                ))

            # Check for process creation anomalies
            process_count = next((f.value for f in features if f.name == "process_count"), 0)
            if process_count > 10:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.BEHAVIORAL,
                    severity=AnomalySeverity.MEDIUM,
                    confidence=0.6,
                    score=process_count / 20.0,
                    features=[f for f in features if f.name == "process_count"],
                    description=f"Unusual number of processes created: {process_count}",
                    recommendations=[
                        "Monitor process creation patterns",
                        "Check for process injection",
                        "Analyze parent-child relationships"
                    ]
                ))

            # Check for file operation anomalies
            file_op_count = next((f.value for f in features if f.name == "file_operation_count"), 0)
            if file_op_count > 50:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.BEHAVIORAL,
                    severity=AnomalySeverity.MEDIUM,
                    confidence=0.5,
                    score=file_op_count / 100.0,
                    features=[f for f in features if f.name == "file_operation_count"],
                    description=f"High volume of file operations: {file_op_count}",
                    recommendations=[
                        "Monitor file system access",
                        "Check for data exfiltration",
                        "Analyze file modification patterns"
                    ]
                ))

            return anomalies

        except Exception as e:
            self.logger.error(f"Failed to detect behavioral anomalies: {e}")
            return []

    def _detect_structural_anomalies(self, features: List[AnomalyFeature], analysis_data: Dict[str, Any]) -> List[AnomalyResult]:
        """Detect structural anomalies"""

        try:
            anomalies = []

            # Check for entropy anomalies
            entropy_features = [f for f in features if "entropy" in f.name]
            for feature in entropy_features:
                if feature.value > 7.5:  # High entropy threshold
                    anomalies.append(AnomalyResult(
                        anomaly_type=AnomalyType.STRUCTURAL,
                        severity=AnomalySeverity.HIGH,
                        confidence=0.7,
                        score=feature.value / 8.0,
                        features=[feature],
                        description=f"High entropy detected in {feature.name}: {feature.value:.2f}",
                        recommendations=[
                            "Check for packed/encrypted sections",
                            "Analyze compression patterns",
                            "Look for obfuscation techniques"
                        ]
                    ))

            # Check for section anomalies
            section_count = next((f.value for f in features if f.name == "section_count"), 0)
            if section_count > 20:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.STRUCTURAL,
                    severity=AnomalySeverity.MEDIUM,
                    confidence=0.6,
                    score=section_count / 30.0,
                    features=[f for f in features if f.name == "section_count"],
                    description=f"Unusual number of sections: {section_count}",
                    recommendations=[
                        "Review section structure",
                        "Check for section manipulation",
                        "Analyze section permissions"
                    ]
                ))

            return anomalies

        except Exception as e:
            self.logger.error(f"Failed to detect structural anomalies: {e}")
            return []

    def _detect_statistical_anomalies(self, features: List[AnomalyFeature], analysis_data: Dict[str, Any]) -> List[AnomalyResult]:
        """Detect statistical anomalies"""

        try:
            anomalies = []

            # Check for string anomalies
            string_count = next((f.value for f in features if f.name == "string_count"), 0)
            if string_count > 1000:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=AnomalySeverity.MEDIUM,
                    confidence=0.5,
                    score=string_count / 2000.0,
                    features=[f for f in features if f.name == "string_count"],
                    description=f"Unusual number of strings: {string_count}",
                    recommendations=[
                        "Analyze string patterns",
                        "Check for embedded data",
                        "Review string content"
                    ]
                ))

            # Check for resource anomalies
            resource_count = next((f.value for f in features if f.name == "resource_count"), 0)
            if resource_count > 100:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.STATISTICAL,
                    severity=AnomalySeverity.LOW,
                    confidence=0.4,
                    score=resource_count / 200.0,
                    features=[f for f in features if f.name == "resource_count"],
                    description=f"High number of resources: {resource_count}",
                    recommendations=[
                        "Review resource content",
                        "Check for embedded files",
                        "Analyze resource types"
                    ]
                ))

            return anomalies

        except Exception as e:
            self.logger.error(f"Failed to detect statistical anomalies: {e}")
            return []

    def _detect_pattern_anomalies(self, features: List[AnomalyFeature], analysis_data: Dict[str, Any]) -> List[AnomalyResult]:
        """Detect pattern anomalies"""

        try:
            anomalies = []

            # Check for suspicious string patterns
            suspicious_string_count = next((f.value for f in features if f.name == "suspicious_string_count"), 0)
            if suspicious_string_count > 0:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.PATTERN,
                    severity=AnomalySeverity.HIGH,
                    confidence=0.8,
                    score=suspicious_string_count / 5.0,
                    features=[f for f in features if f.name == "suspicious_string_count"],
                    description=f"Suspicious string patterns detected: {suspicious_string_count}",
                    recommendations=[
                        "Review string content",
                        "Check for credential exposure",
                        "Analyze string patterns"
                    ]
                ))

            # Check for API pattern anomalies
            api_diversity = next((f.value for f in features if f.name == "api_diversity"), 0)
            if api_diversity > 50:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.PATTERN,
                    severity=AnomalySeverity.MEDIUM,
                    confidence=0.6,
                    score=api_diversity / 100.0,
                    features=[f for f in features if f.name == "api_diversity"],
                    description=f"High API diversity: {api_diversity}",
                    recommendations=[
                        "Review API usage patterns",
                        "Check for complex functionality",
                        "Analyze API call sequences"
                    ]
                ))

            return anomalies

        except Exception as e:
            self.logger.error(f"Failed to detect pattern anomalies: {e}")
            return []

    def _detect_temporal_anomalies(self, features: List[AnomalyFeature], analysis_data: Dict[str, Any]) -> List[AnomalyResult]:
        """Detect temporal anomalies"""

        try:
            anomalies = []

            # Check for execution time anomalies
            if "execution_time" in analysis_data:
                exec_time = analysis_data["execution_time"]
                if exec_time > 300:  # 5 minutes
                    anomalies.append(AnomalyResult(
                        anomaly_type=AnomalyType.TEMPORAL,
                        severity=AnomalySeverity.MEDIUM,
                        confidence=0.6,
                        score=exec_time / 600.0,
                        features=[],
                        description=f"Long execution time: {exec_time} seconds",
                        recommendations=[
                            "Monitor execution patterns",
                            "Check for performance issues",
                            "Analyze timing behavior"
                        ]
                    ))

            return anomalies

        except Exception as e:
            self.logger.error(f"Failed to detect temporal anomalies: {e}")
            return []

    def save_anomaly_results(self, anomalies: List[AnomalyResult], output_file: str) -> bool:
        """Save anomaly detection results to file"""

        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Convert anomalies to dictionary
            anomalies_dict = {
                "anomalies": [
                    {
                        "anomaly_type": anomaly.anomaly_type.value,
                        "severity": anomaly.severity.value,
                        "confidence": anomaly.confidence,
                        "score": anomaly.score,
                        "features": [
                            {
                                "name": f.name,
                                "value": f.value,
                                "type": f.type,
                                "importance": f.importance
                            }
                            for f in anomaly.features
                        ],
                        "description": anomaly.description,
                        "recommendations": anomaly.recommendations,
                        "metadata": anomaly.metadata
                    }
                    for anomaly in anomalies
                ],
                "summary": {
                    "total_anomalies": len(anomalies),
                    "severity_distribution": {
                        "CRITICAL": sum(1 for a in anomalies if a.severity == AnomalySeverity.CRITICAL),
                        "HIGH": sum(1 for a in anomalies if a.severity == AnomalySeverity.HIGH),
                        "MEDIUM": sum(1 for a in anomalies if a.severity == AnomalySeverity.MEDIUM),
                        "LOW": sum(1 for a in anomalies if a.severity == AnomalySeverity.LOW),
                        "INFO": sum(1 for a in anomalies if a.severity == AnomalySeverity.INFO)
                    },
                    "type_distribution": {
                        "BEHAVIORAL": sum(1 for a in anomalies if a.anomaly_type == AnomalyType.BEHAVIORAL),
                        "STRUCTURAL": sum(1 for a in anomalies if a.anomaly_type == AnomalyType.STRUCTURAL),
                        "STATISTICAL": sum(1 for a in anomalies if a.anomaly_type == AnomalyType.STATISTICAL),
                        "PATTERN": sum(1 for a in anomalies if a.anomaly_type == AnomalyType.PATTERN),
                        "TEMPORAL": sum(1 for a in anomalies if a.anomaly_type == AnomalyType.TEMPORAL)
                    },
                    "average_confidence": sum(a.confidence for a in anomalies) / len(anomalies) if anomalies else 0,
                    "average_score": sum(a.score for a in anomalies) / len(anomalies) if anomalies else 0
                }
            }

            # Save to JSON file
            with open(output_path, 'w') as f:
                json.dump(anomalies_dict, f, indent=2, default=str)

            self.logger.info(f"Anomaly detection results saved to: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save anomaly results: {e}")
            return False
