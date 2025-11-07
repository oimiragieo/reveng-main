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
    JavaScriptDeobfuscator,
    DeobfuscationResult,
    ObfuscationType,
    DeobfuscationStage
)

from .detectors import (
    ObfuscationDetector,
    DetectionResult
)

from .source_map_recoverer import (
    SourceMapRecoverer,
    SourceMapResult
)

__all__ = [
    "JavaScriptDeobfuscator",
    "DeobfuscationResult",
    "ObfuscationType",
    "DeobfuscationStage",
    "ObfuscationDetector",
    "DetectionResult",
    "SourceMapRecoverer",
    "SourceMapResult",
]

__version__ = "6.0.0"
