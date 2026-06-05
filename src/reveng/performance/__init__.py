"""Compatibility exports for the canonical ML GPU accelerator module."""

from reveng.ml import gpu_accelerator
from reveng.ml.gpu_accelerator import (
    BatchDecompiler,
    BatchProcessingResult,
    DeviceType,
    GPUAccelerator,
    GPUInfo,
)

__all__ = [
    "gpu_accelerator",
    "BatchDecompiler",
    "BatchProcessingResult",
    "DeviceType",
    "GPUAccelerator",
    "GPUInfo",
]
