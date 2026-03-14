"""Enterprise feature modules and canonical GPU accelerator exports."""

from reveng.ml import gpu_accelerator
from reveng.ml.gpu_accelerator import (
    BatchDecompiler,
    BatchProcessingResult,
    DeviceType,
    GPUAccelerator,
    GPUInfo,
)

from . import audit_trail, enhanced_health_monitor, plugin_system

__all__ = [
    "audit_trail",
    "enhanced_health_monitor",
    "gpu_accelerator",
    "plugin_system",
    "BatchDecompiler",
    "BatchProcessingResult",
    "DeviceType",
    "GPUAccelerator",
    "GPUInfo",
]
