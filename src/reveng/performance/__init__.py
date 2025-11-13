"""
REVENG v4.0 - High-Performance Computing Module

Provides massive speedup through:
- GPU acceleration for ML models (10-100x speedup)
- Parallel batch processing
- Distributed analysis across machines
- Optimized memory management
"""

from .gpu_accelerator import GPUAcceleratedAnalyzer, ParallelDecompiler, BatchProcessor

__all__ = [
    "GPUAcceleratedAnalyzer",
    "ParallelDecompiler",
    "BatchProcessor",
]
