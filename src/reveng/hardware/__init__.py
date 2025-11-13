"""
REVENG v5.0 - Hardware-Assisted Analysis

Intel Processor Trace (PT) and hardware analysis:
- High-performance execution tracing
- Complete control flow reconstruction
- Coverage-guided analysis
- Performance profiling at hardware level
- Zero-overhead tracing
"""

from .intel_pt_analyzer import (
    IntelPTAnalyzer,
    TraceResult,
    ControlFlowTrace,
    CoverageMap,
    PerformanceProfile,
)

from .hardware_breakpoint_engine import HardwareBreakpointEngine, Breakpoint, WatchType

__all__ = [
    "IntelPTAnalyzer",
    "TraceResult",
    "ControlFlowTrace",
    "CoverageMap",
    "PerformanceProfile",
    "HardwareBreakpointEngine",
    "Breakpoint",
    "WatchType",
]
