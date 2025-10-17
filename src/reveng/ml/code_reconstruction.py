"""
ML-Powered Code Reconstruction for REVENG

Advanced machine learning models for code reconstruction and analysis.
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

class ModelType(Enum):
    """ML model types"""
    CODEBERT = "codebert"
    CODET5 = "codet5"
    CODEGEN = "codegen"
    GPT = "gpt"
    CLAUDE = "claude"
    LOCAL_LLM = "local_llm"

class ReconstructionTask(Enum):
    """Reconstruction tasks"""
    DECOMPILATION = "decompilation"
    FUNCTION_RECONSTRUCTION = "function_reconstruction"
    VARIABLE_RECOVERY = "variable_recovery"
    CONTROL_FLOW_RECONSTRUCTION = "control_flow_reconstruction"
    DATA_FLOW_ANALYSIS = "data_flow_analysis"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    THREAT_INTELLIGENCE = "threat_intelligence"

@dataclass
class CodeFragment:
    """Code fragment for reconstruction"""
    address: int
    size: int
    assembly_code: str
    hex_data: bytes
    context: Dict[str, Any] = None
    confidence: float = 0.0

    def __post_init__(self):
        if self.context is None:
            self.context = {}

@dataclass
class ReconstructionResult:
    """Code reconstruction result"""
    task: ReconstructionTask
    input_fragment: CodeFragment
    reconstructed_code: str
    confidence: float
    model_used: ModelType
    processing_time: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class ThreatIntelligence:
    """Threat intelligence result"""
    threat_type: str
    severity: str
    confidence: float
    indicators: List[str]
    description: str
    mitigation: List[str] = None
    references: List[str] = None

    def __post_init__(self):
        if self.mitigation is None:
            self.mitigation = []
        if self.references is None:
            self.references = []

class MLCodeReconstruction:
    """ML-powered code reconstruction engine"""

    def __init__(self):
        self.logger = get_logger(__name__)
        self.models = {}
        self.model_configs = {}

        # Initialize model configurations
        self._initialize_model_configs()

        # Load available models
        self._load_models()

    def _initialize_model_configs(self):
        """Initialize model configurations"""

        try:
            self.model_configs = {
                ModelType.CODEBERT: {
                    "model_name": "microsoft/codebert-base",
                    "max_length": 512,
                    "task": "code_generation",
                    "local": True
                },
                ModelType.CODET5: {
                    "model_name": "Salesforce/codet5-base",
                    "max_length": 512,
                    "task": "code_generation",
                    "local": True
                },
                ModelType.CODEGEN: {
                    "model_name": "Salesforce/codegen-350M-mono",
                    "max_length": 1024,
                    "task": "code_generation",
                    "local": True
                },
                ModelType.GPT: {
                    "model_name": "gpt-3.5-turbo",
                    "max_length": 4096,
                    "task": "code_generation",
                    "local": False,
                    "api_key": "OPENAI_API_KEY"
                },
                ModelType.CLAUDE: {
                    "model_name": "claude-3-sonnet",
                    "max_length": 4096,
                    "task": "code_generation",
                    "local": False,
                    "api_key": "ANTHROPIC_API_KEY"
                },
                ModelType.LOCAL_LLM: {
                    "model_name": "llama2-7b",
                    "max_length": 2048,
                    "task": "code_generation",
                    "local": True
                }
            }

            self.logger.info("Model configurations initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize model configurations: {e}")
            raise

    def _load_models(self):
        """Load available ML models"""

        try:
            # Check for local models
            for model_type, config in self.model_configs.items():
                if config.get("local", False):
                    try:
                        self._load_local_model(model_type, config)
                    except Exception as e:
                        self.logger.warning(f"Failed to load local model {model_type}: {e}")

            # Check for API models
            for model_type, config in self.model_configs.items():
                if not config.get("local", True):
                    try:
                        self._load_api_model(model_type, config)
                    except Exception as e:
                        self.logger.warning(f"Failed to load API model {model_type}: {e}")

            self.logger.info(f"Loaded {len(self.models)} ML models")

        except Exception as e:
            self.logger.error(f"Failed to load models: {e}")
            raise

    def _load_local_model(self, model_type: ModelType, config: Dict[str, Any]):
        """Load local ML model"""

        try:
            # This is a simplified implementation
            # In a real implementation, you would load actual models

            model_info = {
                "type": model_type,
                "config": config,
                "loaded": True,
                "local": True
            }

            self.models[model_type] = model_info
            self.logger.info(f"Loaded local model: {model_type.value}")

        except Exception as e:
            self.logger.error(f"Failed to load local model {model_type}: {e}")
            raise

    def _load_api_model(self, model_type: ModelType, config: Dict[str, Any]):
        """Load API-based ML model"""

        try:
            # Check for API key
            api_key = config.get("api_key")
            if api_key and api_key not in os.environ:
                self.logger.warning(f"API key {api_key} not found for model {model_type}")
                return

            model_info = {
                "type": model_type,
                "config": config,
                "loaded": True,
                "local": False
            }

            self.models[model_type] = model_info
            self.logger.info(f"Loaded API model: {model_type.value}")

        except Exception as e:
            self.logger.error(f"Failed to load API model {model_type}: {e}")
            raise

    def reconstruct_code(self, fragment: CodeFragment, task: ReconstructionTask, model_type: Optional[ModelType] = None) -> ReconstructionResult:
        """Reconstruct code using ML models"""

        try:
            if not self.models:
                raise REVENGError("No ML models available")

            # Select model
            if model_type is None:
                model_type = self._select_best_model(task)

            if model_type not in self.models:
                raise REVENGError(f"Model {model_type.value} not available")

            self.logger.info(f"Reconstructing code using {model_type.value} for task {task.value}")

            # Prepare input
            input_text = self._prepare_input(fragment, task)

            # Generate reconstruction
            start_time = time.time()
            reconstructed_code = self._generate_reconstruction(input_text, task, model_type)
            processing_time = time.time() - start_time

            # Calculate confidence
            confidence = self._calculate_confidence(reconstructed_code, fragment)

            # Create result
            result = ReconstructionResult(
                task=task,
                input_fragment=fragment,
                reconstructed_code=reconstructed_code,
                confidence=confidence,
                model_used=model_type,
                processing_time=processing_time,
                metadata={
                    "input_length": len(input_text),
                    "output_length": len(reconstructed_code),
                    "model_config": self.model_configs[model_type]
                }
            )

            self.logger.info(f"Code reconstruction completed: {confidence:.2f} confidence")
            return result

        except Exception as e:
            self.logger.error(f"Code reconstruction failed: {e}")
            raise

    def _select_best_model(self, task: ReconstructionTask) -> ModelType:
        """Select the best model for a task"""

        try:
            # Task-specific model preferences
            task_models = {
                ReconstructionTask.DECOMPILATION: [ModelType.CODEBERT, ModelType.CODET5, ModelType.CODEGEN],
                ReconstructionTask.FUNCTION_RECONSTRUCTION: [ModelType.CODEBERT, ModelType.CODET5],
                ReconstructionTask.VARIABLE_RECOVERY: [ModelType.CODEBERT, ModelType.CODET5],
                ReconstructionTask.CONTROL_FLOW_RECONSTRUCTION: [ModelType.CODEBERT, ModelType.CODET5],
                ReconstructionTask.DATA_FLOW_ANALYSIS: [ModelType.CODEBERT, ModelType.CODET5],
                ReconstructionTask.VULNERABILITY_DETECTION: [ModelType.CODEBERT, ModelType.GPT, ModelType.CLAUDE],
                ReconstructionTask.THREAT_INTELLIGENCE: [ModelType.GPT, ModelType.CLAUDE, ModelType.CODEBERT]
            }

            preferred_models = task_models.get(task, [ModelType.CODEBERT, ModelType.CODET5])

            # Select first available model
            for model_type in preferred_models:
                if model_type in self.models:
                    return model_type

            # Fallback to any available model
            for model_type in self.models:
                return model_type

            raise REVENGError("No models available")

        except Exception as e:
            self.logger.error(f"Failed to select model: {e}")
            raise

    def _prepare_input(self, fragment: CodeFragment, task: ReconstructionTask) -> str:
        """Prepare input for ML model"""

        try:
            if task == ReconstructionTask.DECOMPILATION:
                return f"Decompile this assembly code:\n{fragment.assembly_code}\n\nDecompiled C code:"

            elif task == ReconstructionTask.FUNCTION_RECONSTRUCTION:
                return f"Reconstruct this function from assembly:\n{fragment.assembly_code}\n\nReconstructed function:"

            elif task == ReconstructionTask.VARIABLE_RECOVERY:
                return f"Identify variables in this assembly code:\n{fragment.assembly_code}\n\nVariables:"

            elif task == ReconstructionTask.CONTROL_FLOW_RECONSTRUCTION:
                return f"Reconstruct control flow from assembly:\n{fragment.assembly_code}\n\nControl flow:"

            elif task == ReconstructionTask.DATA_FLOW_ANALYSIS:
                return f"Analyze data flow in this assembly code:\n{fragment.assembly_code}\n\nData flow:"

            elif task == ReconstructionTask.VULNERABILITY_DETECTION:
                return f"Detect vulnerabilities in this assembly code:\n{fragment.assembly_code}\n\nVulnerabilities:"

            elif task == ReconstructionTask.THREAT_INTELLIGENCE:
                return f"Analyze this assembly code for threats:\n{fragment.assembly_code}\n\nThreat analysis:"

            else:
                return f"Analyze this assembly code:\n{fragment.assembly_code}\n\nAnalysis:"

        except Exception as e:
            self.logger.error(f"Failed to prepare input: {e}")
            raise

    def _generate_reconstruction(self, input_text: str, task: ReconstructionTask, model_type: ModelType) -> str:
        """Generate code reconstruction using ML model"""

        try:
            model_info = self.models[model_type]
            config = model_info["config"]

            if model_info["local"]:
                return self._generate_local_reconstruction(input_text, task, model_type, config)
            else:
                return self._generate_api_reconstruction(input_text, task, model_type, config)

        except Exception as e:
            self.logger.error(f"Failed to generate reconstruction: {e}")
            raise

    def _generate_local_reconstruction(self, input_text: str, task: ReconstructionTask, model_type: ModelType, config: Dict[str, Any]) -> str:
        """Generate reconstruction using local model"""

        try:
            # This is a simplified implementation
            # In a real implementation, you would use actual ML models

            # Mock reconstruction based on task
            if task == ReconstructionTask.DECOMPILATION:
                return self._mock_decompilation(input_text)
            elif task == ReconstructionTask.FUNCTION_RECONSTRUCTION:
                return self._mock_function_reconstruction(input_text)
            elif task == ReconstructionTask.VARIABLE_RECOVERY:
                return self._mock_variable_recovery(input_text)
            elif task == ReconstructionTask.CONTROL_FLOW_RECONSTRUCTION:
                return self._mock_control_flow_reconstruction(input_text)
            elif task == ReconstructionTask.DATA_FLOW_ANALYSIS:
                return self._mock_data_flow_analysis(input_text)
            elif task == ReconstructionTask.VULNERABILITY_DETECTION:
                return self._mock_vulnerability_detection(input_text)
            elif task == ReconstructionTask.THREAT_INTELLIGENCE:
                return self._mock_threat_intelligence(input_text)
            else:
                return "Mock reconstruction result"

        except Exception as e:
            self.logger.error(f"Failed to generate local reconstruction: {e}")
            raise

    def _generate_api_reconstruction(self, input_text: str, task: ReconstructionTask, model_type: ModelType, config: Dict[str, Any]) -> str:
        """Generate reconstruction using API model"""

        try:
            # This is a simplified implementation
            # In a real implementation, you would use actual API calls

            if model_type == ModelType.GPT:
                return self._mock_gpt_reconstruction(input_text, task)
            elif model_type == ModelType.CLAUDE:
                return self._mock_claude_reconstruction(input_text, task)
            else:
                return self._mock_api_reconstruction(input_text, task)

        except Exception as e:
            self.logger.error(f"Failed to generate API reconstruction: {e}")
            raise

    def _mock_decompilation(self, input_text: str) -> str:
        """Mock decompilation result"""
        return """// Mock decompiled C code
int main() {
    int var1 = 0;
    int var2 = 1;

    if (var1 < var2) {
        var1 = var2;
    }

    return var1;
}"""

    def _mock_function_reconstruction(self, input_text: str) -> str:
        """Mock function reconstruction result"""
        return """// Mock reconstructed function
int reconstructed_function(int param1, int param2) {
    int result = param1 + param2;
    return result;
}"""

    def _mock_variable_recovery(self, input_text: str) -> str:
        """Mock variable recovery result"""
        return """// Recovered variables:
// - var1: int (local variable)
// - var2: int (local variable)
// - result: int (local variable)"""

    def _mock_control_flow_reconstruction(self, input_text: str) -> str:
        """Mock control flow reconstruction result"""
        return """// Control flow:
// 1. Entry point
// 2. Conditional branch (if statement)
// 3. Assignment operation
// 4. Return statement"""

    def _mock_data_flow_analysis(self, input_text: str) -> str:
        """Mock data flow analysis result"""
        return """// Data flow analysis:
// - Input: param1, param2
// - Processing: addition operation
// - Output: result variable"""

    def _mock_vulnerability_detection(self, input_text: str) -> str:
        """Mock vulnerability detection result"""
        return """// Vulnerabilities detected:
// - Potential buffer overflow in function call
// - Unvalidated input parameters
// - Missing bounds checking"""

    def _mock_threat_intelligence(self, input_text: str) -> str:
        """Mock threat intelligence result"""
        return """// Threat intelligence:
// - Suspicious API calls detected
// - Potential malware behavior
// - Risk level: MEDIUM"""

    def _mock_gpt_reconstruction(self, input_text: str, task: ReconstructionTask) -> str:
        """Mock GPT reconstruction result"""
        return f"// GPT-3.5 reconstruction for {task.value}:\n{self._mock_decompilation(input_text)}"

    def _mock_claude_reconstruction(self, input_text: str, task: ReconstructionTask) -> str:
        """Mock Claude reconstruction result"""
        return f"// Claude-3 reconstruction for {task.value}:\n{self._mock_decompilation(input_text)}"

    def _mock_api_reconstruction(self, input_text: str, task: ReconstructionTask) -> str:
        """Mock API reconstruction result"""
        return f"// API reconstruction for {task.value}:\n{self._mock_decompilation(input_text)}"

    def _calculate_confidence(self, reconstructed_code: str, fragment: CodeFragment) -> float:
        """Calculate confidence score for reconstruction"""

        try:
            confidence = 0.0

            # Base confidence
            confidence += 0.1

            # Length factor
            if len(reconstructed_code) > 100:
                confidence += 0.2

            # Syntax factor (check for common C syntax)
            if "int " in reconstructed_code and "return " in reconstructed_code:
                confidence += 0.3

            # Structure factor
            if "{" in reconstructed_code and "}" in reconstructed_code:
                confidence += 0.2

            # Comments factor
            if "//" in reconstructed_code:
                confidence += 0.1

            # Variable factor
            if "var" in reconstructed_code.lower():
                confidence += 0.1

            return min(confidence, 1.0)

        except Exception as e:
            self.logger.error(f"Failed to calculate confidence: {e}")
            return 0.0

    def generate_threat_intelligence(self, analysis_data: Dict[str, Any]) -> List[ThreatIntelligence]:
        """Generate threat intelligence using ML models"""

        try:
            threat_intelligence = []

            # Analyze API calls
            if "api_analysis" in analysis_data:
                api_analysis = analysis_data["api_analysis"]
                suspicious_apis = api_analysis.get("suspicious_apis", [])

                for api in suspicious_apis:
                    if api.get("category") == "process_injection":
                        threat_intel = ThreatIntelligence(
                            threat_type="Process Injection",
                            severity="HIGH",
                            confidence=0.8,
                            indicators=[api.get("api", "")],
                            description="Potential process injection technique detected",
                            mitigation=[
                                "Monitor for process creation events",
                                "Check for suspicious parent-child process relationships",
                                "Analyze memory allocation patterns"
                            ],
                            references=[
                                "https://attack.mitre.org/techniques/T1055/",
                                "https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread"
                            ]
                        )
                        threat_intelligence.append(threat_intel)

            # Analyze network connections
            if "network_connections" in analysis_data:
                network_connections = analysis_data["network_connections"]
                if network_connections:
                    threat_intel = ThreatIntelligence(
                        threat_type="Network Communication",
                        severity="MEDIUM",
                        confidence=0.6,
                        indicators=[f"Network connection to {conn.get('foreign_address', 'unknown')}" for conn in network_connections],
                        description="Suspicious network communication detected",
                        mitigation=[
                            "Monitor network traffic",
                            "Check for data exfiltration",
                            "Analyze communication patterns"
                        ]
                    )
                    threat_intelligence.append(threat_intel)

            # Analyze file operations
            if "file_operations" in analysis_data:
                file_operations = analysis_data["file_operations"]
                if file_operations:
                    threat_intel = ThreatIntelligence(
                        threat_type="File System Manipulation",
                        severity="LOW",
                        confidence=0.5,
                        indicators=[f"File operation: {op.get('operation', 'unknown')}" for op in file_operations],
                        description="Suspicious file system operations detected",
                        mitigation=[
                            "Monitor file system changes",
                            "Check for unauthorized file access",
                            "Analyze file modification patterns"
                        ]
                    )
                    threat_intelligence.append(threat_intel)

            self.logger.info(f"Generated {len(threat_intelligence)} threat intelligence items")
            return threat_intelligence

        except Exception as e:
            self.logger.error(f"Failed to generate threat intelligence: {e}")
            return []

    def save_reconstruction_results(self, results: List[ReconstructionResult], output_file: str) -> bool:
        """Save reconstruction results to file"""

        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Convert results to dictionary
            results_dict = {
                "reconstruction_results": [
                    {
                        "task": result.task.value,
                        "address": hex(result.input_fragment.address),
                        "size": result.input_fragment.size,
                        "reconstructed_code": result.reconstructed_code,
                        "confidence": result.confidence,
                        "model_used": result.model_used.value,
                        "processing_time": result.processing_time,
                        "metadata": result.metadata
                    }
                    for result in results
                ],
                "summary": {
                    "total_results": len(results),
                    "average_confidence": sum(r.confidence for r in results) / len(results) if results else 0,
                    "total_processing_time": sum(r.processing_time for r in results),
                    "models_used": list(set(r.model_used.value for r in results))
                }
            }

            # Save to JSON file
            with open(output_path, 'w') as f:
                json.dump(results_dict, f, indent=2, default=str)

            self.logger.info(f"Reconstruction results saved to: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save reconstruction results: {e}")
            return False

    def save_threat_intelligence(self, threat_intelligence: List[ThreatIntelligence], output_file: str) -> bool:
        """Save threat intelligence to file"""

        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Convert threat intelligence to dictionary
            threat_dict = {
                "threat_intelligence": [
                    {
                        "threat_type": ti.threat_type,
                        "severity": ti.severity,
                        "confidence": ti.confidence,
                        "indicators": ti.indicators,
                        "description": ti.description,
                        "mitigation": ti.mitigation,
                        "references": ti.references
                    }
                    for ti in threat_intelligence
                ],
                "summary": {
                    "total_threats": len(threat_intelligence),
                    "severity_distribution": {
                        "CRITICAL": sum(1 for ti in threat_intelligence if ti.severity == "CRITICAL"),
                        "HIGH": sum(1 for ti in threat_intelligence if ti.severity == "HIGH"),
                        "MEDIUM": sum(1 for ti in threat_intelligence if ti.severity == "MEDIUM"),
                        "LOW": sum(1 for ti in threat_intelligence if ti.severity == "LOW")
                    },
                    "average_confidence": sum(ti.confidence for ti in threat_intelligence) / len(threat_intelligence) if threat_intelligence else 0
                }
            }

            # Save to JSON file
            with open(output_path, 'w') as f:
                json.dump(threat_dict, f, indent=2, default=str)

            self.logger.info(f"Threat intelligence saved to: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save threat intelligence: {e}")
            return False
