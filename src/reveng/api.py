"""
REVENG Unified API
=================

Unified programmatic API for the REVENG platform.
Designed for AI agents, automation scripts, and integration with other tools.

Author: REVENG Development Team
Version: 2.1.0
License: MIT
"""

from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import logging
import json
from datetime import datetime

from .analyzer import REVENGAnalyzer
from .ml import MLIntegration
from .core.exceptions import (
    REVENGException, AnalysisError, ValidationError,
    SecurityError, DependencyError
)
from .core.validation import validate_file_path, validate_analysis_config

logger = logging.getLogger(__name__)

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
        modules: Optional[List[str]] = None
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
                binary_path,
                max_size_mb=self.config.get('max_file_size_mb', 500)
            )
        except Exception as e:
            raise ValidationError(f"Invalid binary path: {e}") from e

        try:
            # Run analysis
            logger.info(f"Starting analysis of {path}")

            # Basic analysis
            analysis_result = self.analyzer.analyze_binary(str(path))

            # Enhanced ML analysis if requested
            ml_insights = {}
            if enhanced:
                try:
                    ml_insights = self.ml.analyze_binary(str(path))
                except Exception as e:
                    logger.warning(f"ML analysis failed: {e}")

            # Standardize output format
            result = {
                'version': '2.1.0',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'binary': {
                    'path': str(path),
                    'size_bytes': path.stat().st_size,
                    'sha256': self._calculate_hash(path, 'sha256'),
                    'type': self._detect_binary_type(path),
                    'architecture': self._detect_architecture(path)
                },
                'classification': {
                    'language': analysis_result.get('language', 'unknown'),
                    'framework': analysis_result.get('framework', 'unknown'),
                    'gui_type': analysis_result.get('gui_type', 'unknown'),
                    'application_type': analysis_result.get('application_type', 'unknown'),
                    'confidence': analysis_result.get('confidence', 0.0)
                },
                'analysis': {
                    'imports': analysis_result.get('imports', []),
                    'exports': analysis_result.get('exports', []),
                    'resources': analysis_result.get('resources', []),
                    'strings': analysis_result.get('strings', []),
                    'functions': analysis_result.get('functions', [])
                },
                'ml_insights': ml_insights,
                'errors': analysis_result.get('errors', []),
                'warnings': analysis_result.get('warnings', []),
                'metadata': {
                    'analysis_time_seconds': analysis_result.get('analysis_time', 0),
                    'tools_used': analysis_result.get('tools_used', []),
                    'reveng_version': '2.1.0'
                }
            }

            # Calculate overall confidence
            result['confidence'] = self._calculate_confidence(result)

            logger.info(f"Analysis completed for {path}")
            return result

        except Exception as e:
            raise AnalysisError(f"Analysis failed: {e}") from e

    def reconstruct_binary(
        self,
        binary_path: Union[str, Path],
        output_format: str = 'c'
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
            reconstruction_result = self.ml.reconstruct_code(
                str(path),
                output_format=output_format
            )

            return {
                'version': '2.1.0',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'binary': {
                    'path': str(path),
                    'size_bytes': path.stat().st_size
                },
                'reconstruction': {
                    'format': output_format,
                    'source_files': reconstruction_result.get('source_files', []),
                    'main_file': reconstruction_result.get('main_file', ''),
                    'dependencies': reconstruction_result.get('dependencies', []),
                    'build_instructions': reconstruction_result.get('build_instructions', [])
                },
                'quality': {
                    'completeness': reconstruction_result.get('completeness', 0.0),
                    'readability': reconstruction_result.get('readability', 0.0),
                    'compilability': reconstruction_result.get('compilability', 0.0)
                },
                'errors': reconstruction_result.get('errors', []),
                'warnings': reconstruction_result.get('warnings', [])
            }

        except Exception as e:
            raise AnalysisError(f"Reconstruction failed: {e}") from e

    def detect_malware(
        self,
        binary_path: Union[str, Path]
    ) -> Dict[str, Any]:
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

            return {
                'version': '2.1.0',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'binary': {
                    'path': str(path),
                    'size_bytes': path.stat().st_size,
                    'sha256': self._calculate_hash(path, 'sha256')
                },
                'threat_assessment': {
                    'is_malware': detection_result.get('is_malware', False),
                    'threat_level': detection_result.get('threat_level', 'unknown'),
                    'malware_family': detection_result.get('malware_family', 'unknown'),
                    'confidence': detection_result.get('confidence', 0.0)
                },
                'indicators': {
                    'suspicious_apis': detection_result.get('suspicious_apis', []),
                    'network_indicators': detection_result.get('network_indicators', []),
                    'file_indicators': detection_result.get('file_indicators', []),
                    'behavioral_indicators': detection_result.get('behavioral_indicators', [])
                },
                'mitre_attacks': detection_result.get('mitre_attacks', []),
                'recommendations': detection_result.get('recommendations', []),
                'errors': detection_result.get('errors', []),
                'warnings': detection_result.get('warnings', [])
            }

        except Exception as e:
            raise AnalysisError(f"Malware detection failed: {e}") from e

    def _calculate_hash(self, path: Path, algorithm: str) -> str:
        """Calculate file hash using specified algorithm."""
        import hashlib

        with open(path, 'rb') as f:
            content = f.read()
            if algorithm == 'sha256':
                return hashlib.sha256(content).hexdigest()
            elif algorithm == 'sha512':
                return hashlib.sha512(content).hexdigest()
            else:
                return hashlib.sha256(content).hexdigest()

    def _detect_binary_type(self, path: Path) -> str:
        """Detect binary type (PE, ELF, Mach-O, etc.)."""
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                if magic.startswith(b'MZ'):
                    return 'PE32'
                elif magic.startswith(b'\x7fELF'):
                    return 'ELF'
                elif magic.startswith(b'\xfe\xed\xfa'):
                    return 'Mach-O'
                elif magic.startswith(b'PK'):
                    return 'JAR/ZIP'
                else:
                    return 'Unknown'
        except:
            return 'Unknown'

    def _detect_architecture(self, path: Path) -> str:
        """Detect binary architecture."""
        # Simplified detection - real implementation would be more sophisticated
        try:
            with open(path, 'rb') as f:
                magic = f.read(8)
                if b'x86-64' in magic or b'AMD64' in magic:
                    return 'x86-64'
                elif b'x86' in magic or b'i386' in magic:
                    return 'x86'
                elif b'ARM' in magic:
                    return 'ARM'
                else:
                    return 'Unknown'
        except:
            return 'Unknown'

    def _calculate_confidence(self, result: Dict[str, Any]) -> float:
        """Calculate overall confidence score."""
        try:
            # Weighted average of different confidence measures
            classification_conf = result.get('classification', {}).get('confidence', 0.0)
            ml_conf = result.get('ml_insights', {}).get('confidence', 0.0)

            # Simple average for now
            return (classification_conf + ml_conf) / 2.0
        except:
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

def reconstruct_binary(binary_path: Union[str, Path], output_format: str = 'c') -> Dict[str, Any]:
    """Convenience function for binary reconstruction."""
    api = REVENGAPI()
    return api.reconstruct_binary(binary_path, output_format)
