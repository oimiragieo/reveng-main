"""
ML Integration Module for REVENG

Integrates ML-powered features with the core REVENG analysis pipeline.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass

from ..core.errors import REVENGError, AnalysisFailureError, create_error_context
from ..core.logger import get_logger
from .code_reconstruction import MLCodeReconstruction, CodeFragment, ReconstructionTask, ModelType
from .anomaly_detection import MLAnomalyDetection, AnomalyType, AnomalySeverity

logger = get_logger(__name__)

@dataclass
class MLIntegrationConfig:
    """Configuration for ML integration"""
    enable_code_reconstruction: bool = True
    enable_anomaly_detection: bool = True
    enable_threat_intelligence: bool = True
    model_preferences: Dict[str, str] = None
    output_directory: str = "ml_analysis"
    save_intermediate_results: bool = True

    def __post_init__(self):
        if self.model_preferences is None:
            self.model_preferences = {
                "decompilation": "codebert",
                "anomaly_detection": "isolation_forest",
                "threat_intelligence": "gpt"
            }

class MLIntegration:
    """ML integration engine for REVENG"""

    def __init__(self, config: Optional[MLIntegrationConfig] = None):
        self.logger = get_logger(__name__)
        self.config = config or MLIntegrationConfig()

        # Initialize ML components
        self.code_reconstruction = None
        self.anomaly_detection = None

        # Initialize components
        self._initialize_components()

    def _initialize_components(self):
        """Initialize ML components"""

        try:
            if self.config.enable_code_reconstruction:
                self.code_reconstruction = MLCodeReconstruction()
                self.logger.info("Code reconstruction engine initialized")

            if self.config.enable_anomaly_detection:
                self.anomaly_detection = MLAnomalyDetection()
                self.logger.info("Anomaly detection engine initialized")

            # Create output directory
            os.makedirs(self.config.output_directory, exist_ok=True)

        except Exception as e:
            self.logger.error(f"Failed to initialize ML components: {e}")
            raise

    def analyze_binary(self, binary_path: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive ML analysis on binary"""

        try:
            self.logger.info(f"Starting ML analysis for: {binary_path}")

            results = {
                "binary_path": binary_path,
                "analysis_timestamp": time.time(),
                "ml_analysis": {}
            }

            # Code reconstruction
            if self.code_reconstruction and self.config.enable_code_reconstruction:
                self.logger.info("Performing code reconstruction...")
                reconstruction_results = self._perform_code_reconstruction(binary_path, analysis_data)
                results["ml_analysis"]["code_reconstruction"] = reconstruction_results

            # Anomaly detection
            if self.anomaly_detection and self.config.enable_anomaly_detection:
                self.logger.info("Performing anomaly detection...")
                anomaly_results = self._perform_anomaly_detection(analysis_data)
                results["ml_analysis"]["anomaly_detection"] = anomaly_results

            # Threat intelligence
            if self.config.enable_threat_intelligence:
                self.logger.info("Generating threat intelligence...")
                threat_results = self._generate_threat_intelligence(analysis_data)
                results["ml_analysis"]["threat_intelligence"] = threat_results

            # Save results
            if self.config.save_intermediate_results:
                self._save_ml_results(results, binary_path)

            self.logger.info("ML analysis completed")
            return results

        except Exception as e:
            self.logger.error(f"ML analysis failed: {e}")
            raise

    def _perform_code_reconstruction(self, binary_path: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform code reconstruction analysis"""

        try:
            reconstruction_results = {
                "reconstructions": [],
                "summary": {}
            }

            # Extract code fragments from analysis data
            code_fragments = self._extract_code_fragments(analysis_data)

            # Perform reconstruction for each fragment
            for fragment in code_fragments:
                try:
                    # Select reconstruction task
                    task = self._select_reconstruction_task(fragment, analysis_data)

                    # Perform reconstruction
                    result = self.code_reconstruction.reconstruct_code(fragment, task)
                    reconstruction_results["reconstructions"].append(result)

                except Exception as e:
                    self.logger.warning(f"Failed to reconstruct code fragment at {hex(fragment.address)}: {e}")

            # Generate summary
            reconstruction_results["summary"] = self._generate_reconstruction_summary(reconstruction_results["reconstructions"])

            return reconstruction_results

        except Exception as e:
            self.logger.error(f"Code reconstruction failed: {e}")
            return {"error": str(e)}

    def _perform_anomaly_detection(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform anomaly detection analysis"""

        try:
            # Detect anomalies
            anomalies = self.anomaly_detection.detect_anomalies(analysis_data)

            # Generate summary
            summary = self._generate_anomaly_summary(anomalies)

            return {
                "anomalies": anomalies,
                "summary": summary
            }

        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return {"error": str(e)}

    def _generate_threat_intelligence(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat intelligence"""

        try:
            if not self.code_reconstruction:
                return {"error": "Code reconstruction not available"}

            # Generate threat intelligence
            threat_intelligence = self.code_reconstruction.generate_threat_intelligence(analysis_data)

            # Generate summary
            summary = self._generate_threat_summary(threat_intelligence)

            return {
                "threat_intelligence": threat_intelligence,
                "summary": summary
            }

        except Exception as e:
            self.logger.error(f"Threat intelligence generation failed: {e}")
            return {"error": str(e)}

    def _extract_code_fragments(self, analysis_data: Dict[str, Any]) -> List[CodeFragment]:
        """Extract code fragments from analysis data"""

        try:
            fragments = []

            # Extract from disassembly data
            if "disassembly" in analysis_data:
                disassembly = analysis_data["disassembly"]
                for instruction in disassembly.get("instructions", []):
                    fragment = CodeFragment(
                        address=instruction.get("address", 0),
                        size=instruction.get("size", 0),
                        assembly_code=instruction.get("mnemonic", ""),
                        hex_data=bytes.fromhex(instruction.get("bytes", "")),
                        context={"function": instruction.get("function", "")}
                    )
                    fragments.append(fragment)

            # Extract from function data
            if "functions" in analysis_data:
                functions = analysis_data["functions"]
                for func in functions:
                    fragment = CodeFragment(
                        address=func.get("address", 0),
                        size=func.get("size", 0),
                        assembly_code=func.get("disassembly", ""),
                        hex_data=b"",  # Would need to extract from binary
                        context={"function_name": func.get("name", "")}
                    )
                    fragments.append(fragment)

            return fragments

        except Exception as e:
            self.logger.error(f"Failed to extract code fragments: {e}")
            return []

    def _select_reconstruction_task(self, fragment: CodeFragment, analysis_data: Dict[str, Any]) -> ReconstructionTask:
        """Select appropriate reconstruction task for fragment"""

        try:
            # Simple heuristics for task selection
            if "function" in fragment.context:
                return ReconstructionTask.FUNCTION_RECONSTRUCTION
            elif "main" in fragment.assembly_code.lower():
                return ReconstructionTask.DECOMPILATION
            elif "call" in fragment.assembly_code.lower():
                return ReconstructionTask.CONTROL_FLOW_RECONSTRUCTION
            else:
                return ReconstructionTask.DECOMPILATION

        except Exception as e:
            self.logger.error(f"Failed to select reconstruction task: {e}")
            return ReconstructionTask.DECOMPILATION

    def _generate_reconstruction_summary(self, reconstructions: List[Any]) -> Dict[str, Any]:
        """Generate reconstruction summary"""

        try:
            if not reconstructions:
                return {"total_reconstructions": 0}

            # Calculate statistics
            total_reconstructions = len(reconstructions)
            average_confidence = sum(r.confidence for r in reconstructions) / total_reconstructions
            total_processing_time = sum(r.processing_time for r in reconstructions)

            # Task distribution
            task_distribution = {}
            for reconstruction in reconstructions:
                task = reconstruction.task.value
                task_distribution[task] = task_distribution.get(task, 0) + 1

            # Model distribution
            model_distribution = {}
            for reconstruction in reconstructions:
                model = reconstruction.model_used.value
                model_distribution[model] = model_distribution.get(model, 0) + 1

            return {
                "total_reconstructions": total_reconstructions,
                "average_confidence": average_confidence,
                "total_processing_time": total_processing_time,
                "task_distribution": task_distribution,
                "model_distribution": model_distribution
            }

        except Exception as e:
            self.logger.error(f"Failed to generate reconstruction summary: {e}")
            return {"error": str(e)}

    def _generate_anomaly_summary(self, anomalies: List[Any]) -> Dict[str, Any]:
        """Generate anomaly detection summary"""

        try:
            if not anomalies:
                return {"total_anomalies": 0}

            # Calculate statistics
            total_anomalies = len(anomalies)
            average_confidence = sum(a.confidence for a in anomalies) / total_anomalies
            average_score = sum(a.score for a in anomalies) / total_anomalies

            # Severity distribution
            severity_distribution = {}
            for anomaly in anomalies:
                severity = anomaly.severity.value
                severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

            # Type distribution
            type_distribution = {}
            for anomaly in anomalies:
                anomaly_type = anomaly.anomaly_type.value
                type_distribution[anomaly_type] = type_distribution.get(anomaly_type, 0) + 1

            return {
                "total_anomalies": total_anomalies,
                "average_confidence": average_confidence,
                "average_score": average_score,
                "severity_distribution": severity_distribution,
                "type_distribution": type_distribution
            }

        except Exception as e:
            self.logger.error(f"Failed to generate anomaly summary: {e}")
            return {"error": str(e)}

    def _generate_threat_summary(self, threat_intelligence: List[Any]) -> Dict[str, Any]:
        """Generate threat intelligence summary"""

        try:
            if not threat_intelligence:
                return {"total_threats": 0}

            # Calculate statistics
            total_threats = len(threat_intelligence)
            average_confidence = sum(ti.confidence for ti in threat_intelligence) / total_threats

            # Severity distribution
            severity_distribution = {}
            for threat in threat_intelligence:
                severity = threat.severity
                severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

            # Threat type distribution
            type_distribution = {}
            for threat in threat_intelligence:
                threat_type = threat.threat_type
                type_distribution[threat_type] = type_distribution.get(threat_type, 0) + 1

            return {
                "total_threats": total_threats,
                "average_confidence": average_confidence,
                "severity_distribution": severity_distribution,
                "type_distribution": type_distribution
            }

        except Exception as e:
            self.logger.error(f"Failed to generate threat summary: {e}")
            return {"error": str(e)}

    def _save_ml_results(self, results: Dict[str, Any], binary_path: str) -> bool:
        """Save ML analysis results"""

        try:
            # Create output filename
            binary_name = Path(binary_path).stem
            output_file = os.path.join(self.config.output_directory, f"{binary_name}_ml_analysis.json")

            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)

            self.logger.info(f"ML analysis results saved to: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save ML results: {e}")
            return False

    def get_model_status(self) -> Dict[str, Any]:
        """Get status of available ML models"""

        try:
            status = {
                "code_reconstruction": {
                    "available": self.code_reconstruction is not None,
                    "models": {}
                },
                "anomaly_detection": {
                    "available": self.anomaly_detection is not None,
                    "models": {}
                }
            }

            # Get code reconstruction model status
            if self.code_reconstruction:
                for model_type, model_info in self.code_reconstruction.models.items():
                    status["code_reconstruction"]["models"][model_type.value] = {
                        "loaded": model_info.get("loaded", False),
                        "local": model_info.get("local", False),
                        "config": model_info.get("config", {})
                    }

            # Get anomaly detection model status
            if self.anomaly_detection:
                for model_name, model in self.anomaly_detection.models.items():
                    status["anomaly_detection"]["models"][model_name] = {
                        "name": model.name,
                        "type": model.type.value,
                        "features": model.features,
                        "threshold": model.threshold,
                        "performance": model.performance
                    }

            return status

        except Exception as e:
            self.logger.error(f"Failed to get model status: {e}")
            return {"error": str(e)}

    def update_config(self, new_config: MLIntegrationConfig) -> bool:
        """Update ML integration configuration"""

        try:
            self.config = new_config

            # Reinitialize components if needed
            if new_config.enable_code_reconstruction and not self.code_reconstruction:
                self.code_reconstruction = MLCodeReconstruction()

            if new_config.enable_anomaly_detection and not self.anomaly_detection:
                self.anomaly_detection = MLAnomalyDetection()

            # Update output directory
            os.makedirs(self.config.output_directory, exist_ok=True)

            self.logger.info("ML integration configuration updated")
            return True

        except Exception as e:
            self.logger.error(f"Failed to update configuration: {e}")
            return False
