"""
REVENG Unified API
=================

Unified programmatic API for the REVENG platform.
Designed for AI agents, automation scripts, and integration with other tools.

Author: REVENG Development Team
Version: 4.0.0
License: MIT
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .analyzer import REVENGAnalyzer
from .app_reverse_engineering import AppCorpusEntry, create_default_framework, run_app_corpus_sync
from .core.exceptions import (
    AnalysisError,
    ValidationError,
)
from .core.validation import validate_analysis_config, validate_file_path
from .ml import MLIntegration
from .result_contracts import (
    AnalysisResultContract,
    MalwareDetectionResultContract,
    ReconstructionResultContract,
    make_evidence_item,
    make_trace_reference,
)

logger = logging.getLogger(__name__)

try:
    from scripts.run_app_reverse_engineering_corpus import load_app_corpus_config
except Exception:  # pragma: no cover - script import fallback
    load_app_corpus_config = None


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class REVENGAPI:
    """
    Unified API for programmatic access.

    Designed for:
    - AI agents (Claude, GPT, etc.)
    - Automation scripts
    - Integration with other tools

    Example:
        >>> from reveng.api import REVENGAPI
        >>> api = REVENGAPI()
        >>> result = api.analyze_binary('/path/to/malware.exe')
        >>> print(result['malware_classification'])
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize API with optional configuration.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.analyzer = REVENGAnalyzer()
        self.ml = MLIntegration()

        # Validate configuration
        try:
            self.config = validate_analysis_config(self.config)
        except Exception as e:
            logger.warning(f"Invalid configuration: {e}, using defaults")
            self.config = validate_analysis_config({})

    def analyze_binary(
        self,
        binary_path: Union[str, Path],
        enhanced: bool = False,
        modules: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze binary file.

        Args:
            binary_path: Path to binary file
            enhanced: Enable ML-enhanced analysis
            modules: List of specific modules to run

        Returns:
            Standardized analysis result:
            {
                'metadata': {...},        # File info
                'classification': {...},  # Binary type
                'analysis': {...},        # Analysis results
                'ml': {...},             # ML insights (if enhanced=True)
                'confidence': 0.95       # Overall confidence score
            }

        Raises:
            ValidationError: If binary path invalid
            AnalysisError: If analysis fails
        """
        try:
            # Validate input
            path = validate_file_path(
                binary_path, max_size_mb=self.config.get("max_file_size_mb", 500)
            )
        except Exception as e:
            raise ValidationError(f"Invalid binary path: {e}") from e

        try:
            # Run analysis
            logger.info(f"Starting analysis of {path}")

            analysis_summary = self.analyzer.analyze_binary(str(path))
            if (
                not isinstance(analysis_summary, dict)
                or analysis_summary.get("status") != "success"
            ):
                error_message = "Analysis failed"
                if isinstance(analysis_summary, dict):
                    error_message = (
                        analysis_summary.get("error")
                        or analysis_summary.get("message")
                        or error_message
                    )
                raise AnalysisError(error_message)

            ghidra_data = analysis_summary.get("ghidra_analysis", {})
            step_results = analysis_summary.get("results", {})
            metadata = step_results.get("metadata", {})

            # Enhanced ML analysis if requested
            ml_insights = {}
            if enhanced:
                try:
                    ml_insights = self.ml.analyze_binary(str(path), ghidra_data)
                except Exception as e:
                    logger.warning(f"ML analysis failed: {e}")

            file_type = analysis_summary.get("binary", {}).get("file_type") or {}
            classification_confidence = float(file_type.get("confidence", 0.0) or 0.0)

            warnings = []
            errors = step_results.get("errors", [])[:]
            for step_name, info in step_results.items():
                if not isinstance(info, dict):
                    continue
                status = info.get("status")
                message = info.get("error") or info.get("message") or info.get("output")
                if status == "warning" and message:
                    warnings.append(f"{step_name}: {message}")
                if status == "error" and message:
                    errors.append(f"{step_name}: {message}")

            result = AnalysisResultContract(
                result_type="analysis_result",
                version="4.0.0",
                timestamp=_utc_timestamp(),
                binary={
                    "path": str(path),
                    "size_bytes": path.stat().st_size,
                    "sha256": self._calculate_hash(path, "sha256"),
                    "type": self._detect_binary_type(path),
                    "architecture": self._detect_architecture(path),
                },
                classification={
                    "language": file_type.get("language", "unknown"),
                    "framework": "unknown",
                    "gui_type": "unknown",
                    "application_type": "unknown",
                    "confidence": classification_confidence,
                },
                analysis={
                    "imports": ghidra_data.get("imports", []),
                    "exports": ghidra_data.get("exports", []),
                    "resources": step_results.get("resources", []),
                    "strings": ghidra_data.get("strings", []),
                    "functions": ghidra_data.get("functions", []),
                    "decompiled_functions": len(ghidra_data.get("decompiled_code", {})),
                },
                ml_insights=ml_insights,
                errors=errors,
                warnings=warnings,
                metadata={
                    "analysis_time_seconds": metadata.get("duration_seconds", 0),
                    "tools_used": ["ghidra"] if ghidra_data else [],
                    "reveng_version": "4.0.0",
                    "analysis_folder": analysis_summary.get("analysis_folder"),
                },
                confidence=0.0,
                provenance=self._build_analysis_provenance(
                    path=path,
                    analysis_summary=analysis_summary,
                    ghidra_data=ghidra_data,
                    enhanced=enhanced,
                ),
            ).to_dict()

            # Calculate overall confidence
            result["confidence"] = self._calculate_confidence(result)

            logger.info(f"Analysis completed for {path}")
            return result

        except AnalysisError:
            raise
        except Exception as e:
            raise AnalysisError(f"Analysis failed: {e}") from e

    def reconstruct_binary(
        self, binary_path: Union[str, Path], output_format: str = "c"
    ) -> Dict[str, Any]:
        """
        Reconstruct binary to source code.

        Args:
            binary_path: Path to binary file
            output_format: Output format ('c', 'java', 'csharp', 'python')

        Returns:
            Reconstruction results with source code and metadata
        """
        try:
            path = validate_file_path(binary_path)
        except Exception as e:
            raise ValidationError(f"Invalid binary path: {e}") from e

        try:
            # Use ML integration for code reconstruction
            reconstruction_result = self.ml.reconstruct_code(str(path), output_format=output_format)

            return ReconstructionResultContract(
                result_type="reconstruction_result",
                version="4.0.0",
                timestamp=_utc_timestamp(),
                binary={"path": str(path), "size_bytes": path.stat().st_size},
                reconstruction={
                    "format": output_format,
                    "source_files": reconstruction_result.get("source_files", []),
                    "main_file": reconstruction_result.get("main_file", ""),
                    "dependencies": reconstruction_result.get("dependencies", []),
                    "build_instructions": reconstruction_result.get("build_instructions", []),
                },
                quality={
                    "completeness": reconstruction_result.get("completeness", 0.0),
                    "readability": reconstruction_result.get("readability", 0.0),
                    "compilability": reconstruction_result.get("compilability", 0.0),
                },
                errors=reconstruction_result.get("errors", []),
                warnings=reconstruction_result.get("warnings", []),
                provenance=self._build_reconstruction_provenance(
                    path=path,
                    output_format=output_format,
                    reconstruction_result=reconstruction_result,
                ),
            ).to_dict()

        except Exception as e:
            raise AnalysisError(f"Reconstruction failed: {e}") from e

    def detect_malware(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Detect malware and classify threats.

        Args:
            binary_path: Path to binary file

        Returns:
            Malware detection results with threat classification
        """
        try:
            path = validate_file_path(binary_path)
        except Exception as e:
            raise ValidationError(f"Invalid binary path: {e}") from e

        try:
            # Use ML integration for malware detection
            detection_result = self.ml.detect_threats(str(path))

            return MalwareDetectionResultContract(
                result_type="malware_detection_result",
                version="4.0.0",
                timestamp=_utc_timestamp(),
                binary={
                    "path": str(path),
                    "size_bytes": path.stat().st_size,
                    "sha256": self._calculate_hash(path, "sha256"),
                },
                threat_assessment={
                    "is_malware": detection_result.get("is_malware", False),
                    "threat_level": detection_result.get("threat_level", "unknown"),
                    "malware_family": detection_result.get("malware_family", "unknown"),
                    "confidence": detection_result.get("confidence", 0.0),
                },
                indicators={
                    "suspicious_apis": detection_result.get("suspicious_apis", []),
                    "network_indicators": detection_result.get("network_indicators", []),
                    "file_indicators": detection_result.get("file_indicators", []),
                    "behavioral_indicators": detection_result.get("behavioral_indicators", []),
                },
                mitre_attacks=detection_result.get("mitre_attacks", []),
                recommendations=detection_result.get("recommendations", []),
                errors=detection_result.get("errors", []),
                warnings=detection_result.get("warnings", []),
                provenance=self._build_malware_provenance(path=path),
            ).to_dict()

        except Exception as e:
            raise AnalysisError(f"Malware detection failed: {e}") from e

    def reverse_engineer_app(
        self,
        input_path: Union[str, Path],
        *,
        language: str = "auto",
        output_dir: Optional[Union[str, Path]] = None,
        input_root: Optional[Union[str, Path]] = None,
        skip_patterns: Optional[List[str]] = None,
        max_snippets: int = 12,
        snippet_context: int = 2,
        run_deobfuscator: bool = False,
    ) -> Dict[str, Any]:
        """
        Reverse-engineer an application package or source entrypoint into a normalized app contract.

        Returns the same machine-readable contract emitted by the shared app framework.
        """
        try:
            path = Path(input_path).expanduser().resolve()
            if not path.exists():
                raise ValidationError(f"Invalid input path: {path}")

            resolved_output_dir = (
                Path(output_dir).expanduser().resolve()
                if output_dir is not None
                else Path.cwd() / f"analysis_{path.stem}"
            )
            framework = create_default_framework()
            result = asyncio.run(
                framework.reverse_engineer(
                    str(path),
                    str(resolved_output_dir),
                    language=language,
                    input_root=(
                        str(Path(input_root).expanduser().resolve()) if input_root else None
                    ),
                    skip_patterns=skip_patterns,
                    max_snippets=max_snippets,
                    snippet_context=snippet_context,
                    run_deobfuscator=run_deobfuscator,
                )
            )
            return dict(result.metadata)
        except ValidationError:
            raise
        except Exception as e:
            raise AnalysisError(f"App reverse engineering failed: {e}") from e

    def run_app_reverse_engineering_corpus(
        self,
        *,
        config_path: Optional[Union[str, Path]] = None,
        selected_names: Optional[List[str]] = None,
        output_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """Run the manifest-driven app reverse-engineering corpus and return the rollup report."""
        if load_app_corpus_config is None:
            raise AnalysisError("App corpus loader is not available")

        try:
            resolved_config = Path(config_path).expanduser().resolve() if config_path else None
            config = (
                load_app_corpus_config(resolved_config)
                if resolved_config
                else load_app_corpus_config()
            )
            entries = config.get("entries", [])
            if selected_names:
                selected = set(selected_names)
                entries = [entry for entry in entries if entry["name"] in selected]

            corpus_entries = [AppCorpusEntry(**entry) for entry in entries]
            resolved_output_dir = (
                Path(output_dir).expanduser().resolve()
                if output_dir is not None
                else Path.cwd() / "reports" / "app_reverse_engineering_corpus"
            )
            return run_app_corpus_sync(corpus_entries, str(resolved_output_dir))
        except Exception as e:
            raise AnalysisError(f"App corpus execution failed: {e}") from e

    def _calculate_hash(self, path: Path, algorithm: str) -> str:
        """Calculate file hash using specified algorithm."""
        import hashlib

        with open(path, "rb") as f:
            content = f.read()
            if algorithm == "sha256":
                return hashlib.sha256(content).hexdigest()
            elif algorithm == "sha512":
                return hashlib.sha512(content).hexdigest()
            else:
                return hashlib.sha256(content).hexdigest()

    def _detect_binary_type(self, path: Path) -> str:
        """Detect binary type (PE, ELF, Mach-O, etc.)."""
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic.startswith(b"MZ"):
                    return "PE32"
                elif magic.startswith(b"\x7fELF"):
                    return "ELF"
                elif magic.startswith(b"\xfe\xed\xfa"):
                    return "Mach-O"
                elif magic.startswith(b"PK"):
                    return "JAR/ZIP"
                else:
                    return "Unknown"
        except Exception:
            return "Unknown"

    def _detect_architecture(self, path: Path) -> str:
        """Detect binary architecture."""
        # Simplified detection - real implementation would be more sophisticated
        try:
            with open(path, "rb") as f:
                magic = f.read(8)
                if b"x86-64" in magic or b"AMD64" in magic:
                    return "x86-64"
                elif b"x86" in magic or b"i386" in magic:
                    return "x86"
                elif b"ARM" in magic:
                    return "ARM"
                else:
                    return "Unknown"
        except Exception:
            return "Unknown"

    def _build_analysis_provenance(
        self,
        path: Path,
        analysis_summary: Dict[str, Any],
        ghidra_data: Dict[str, Any],
        enhanced: bool,
    ) -> Dict[str, Any]:
        analysis_folder = analysis_summary.get("analysis_folder")
        report_path = None
        binary_trace_id = f"binary:{path.name}"
        if analysis_folder:
            report_path = str(Path(analysis_folder) / "universal_analysis_report.json")

        tools = []
        if ghidra_data:
            tools.append("ghidra")
        if enhanced:
            tools.append("ml_integration")

        references = []
        if analysis_folder:
            references.append(
                make_trace_reference(
                    "derived_from",
                    str(analysis_folder),
                    trace_id=f"{binary_trace_id}:analysis-folder",
                    metadata={"kind": "analysis_folder"},
                )
            )
        if report_path:
            references.append(
                make_trace_reference(
                    "documents",
                    report_path,
                    trace_id=f"{binary_trace_id}:analysis-report",
                    confidence=0.9,
                    metadata={"kind": "analysis_report"},
                )
            )

        return {
            "inputs": [self._binary_artifact(path, trace_id=binary_trace_id)],
            "artifacts": [],
            "stages": ["binary_validation", "analyzer_execution", "result_contract_serialization"],
            "references": references,
            "tools": tools,
        }

    def _build_reconstruction_provenance(
        self,
        path: Path,
        output_format: str,
        reconstruction_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        artifacts = [
            make_evidence_item(
                "reconstructed_source",
                path=source_file,
                trace_id=f"reconstruction:{Path(path).stem}:{index}",
                evidence_kind="generated_source",
                confidence=reconstruction_result.get("compilability", 0.0),
                source_result_type="reconstruction_result",
                format=output_format,
            )
            for index, source_file in enumerate(
                reconstruction_result.get("source_files", []), start=1
            )
        ]

        return {
            "inputs": [self._binary_artifact(path, trace_id=f"binary:{path.name}")],
            "artifacts": artifacts,
            "stages": ["binary_validation", "ml_reconstruction", "result_contract_serialization"],
            "references": (
                [
                    make_trace_reference(
                        "primary_output",
                        reconstruction_result.get("main_file", ""),
                        trace_id=f"reconstruction:{Path(path).stem}:main",
                        confidence=reconstruction_result.get("compilability", 0.0),
                        metadata={"kind": "main_source"},
                    )
                ]
                if reconstruction_result.get("main_file")
                else []
            ),
            "tools": ["ml_integration"],
        }

    def _build_malware_provenance(self, path: Path) -> Dict[str, Any]:
        return {
            "inputs": [self._binary_artifact(path, trace_id=f"binary:{path.name}")],
            "artifacts": [],
            "stages": ["binary_validation", "malware_detection", "result_contract_serialization"],
            "references": [],
            "tools": ["ml_integration"],
        }

    def _binary_artifact(self, path: Path, *, trace_id: str) -> Dict[str, Any]:
        return make_evidence_item(
            "binary_input",
            path=str(path),
            trace_id=trace_id,
            evidence_kind="input_binary",
            confidence=1.0,
            source_result_type="analysis_result",
            size_bytes=path.stat().st_size,
            sha256=self._calculate_hash(path, "sha256"),
        )

    def _calculate_confidence(self, result: Dict[str, Any]) -> float:
        """Calculate overall confidence score."""
        try:
            # Weighted average of different confidence measures
            classification_conf = result.get("classification", {}).get("confidence", 0.0)
            ml_conf = result.get("ml_insights", {}).get("confidence", 0.0)

            # Simple average for now
            return (classification_conf + ml_conf) / 2.0
        except Exception:
            return 0.0


# Convenience functions for common operations
def analyze_binary(binary_path: Union[str, Path], **kwargs) -> Dict[str, Any]:
    """Convenience function for binary analysis."""
    api = REVENGAPI()
    return api.analyze_binary(binary_path, **kwargs)


def detect_malware(binary_path: Union[str, Path]) -> Dict[str, Any]:
    """Convenience function for malware detection."""
    api = REVENGAPI()
    return api.detect_malware(binary_path)


def reconstruct_binary(binary_path: Union[str, Path], output_format: str = "c") -> Dict[str, Any]:
    """Convenience function for binary reconstruction."""
    api = REVENGAPI()
    return api.reconstruct_binary(binary_path, output_format)


def reverse_engineer_app(input_path: Union[str, Path], **kwargs) -> Dict[str, Any]:
    """Convenience function for app reverse engineering."""
    api = REVENGAPI()
    return api.reverse_engineer_app(input_path, **kwargs)


def run_app_reverse_engineering_corpus(**kwargs) -> Dict[str, Any]:
    """Convenience function for the app reverse-engineering corpus."""
    api = REVENGAPI()
    return api.run_app_reverse_engineering_corpus(**kwargs)
