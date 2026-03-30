"""
REVENG v6.0 - JavaScript Deobfuscation & Decompilation

Multi-stage pipeline for JavaScript reverse engineering:
- Webpack/Browserify unbundling
- Source map recovery
- obfuscator.io deobfuscation
- Control flow unflattening
- ML-based variable renaming
- LLM semantic enhancement
- Code beautification

Integrates best-of-breed open source tools:
- webcrack (deobfuscation)
- unwebpack-sourcemap (source recovery)
- UnuglifyJS (ML renaming)
- Humanify (LLM enhancement)
- Prettier (formatting)
"""

from .deobfuscator import (
    DeobfuscationResult,
    DeobfuscationStage,
    JavaScriptDeobfuscator,
    ObfuscationType,
)
from .bundle_reverse_engineer import (
    BundleReverseEngineeringResult,
    JavaScriptBundleReverseEngineer,
)
from .detectors import DetectionResult, ObfuscationDetector
from .source_map_recoverer import SourceMapRecoverer, SourceMapResult

__all__ = [
    "JavaScriptDeobfuscator",
    "JavaScriptBundleReverseEngineer",
    "BundleReverseEngineeringResult",
    "DeobfuscationResult",
    "ObfuscationType",
    "DeobfuscationStage",
    "ObfuscationDetector",
    "DetectionResult",
    "SourceMapRecoverer",
    "SourceMapResult",
]

__version__ = "4.0.0"  # JavaScript module version aligned with REVENG platform
