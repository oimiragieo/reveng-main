"""
REVENG v5.0 - Hardware-Assisted Analysis

Intel Processor Trace (PT) and hardware analysis:
- High-performance execution tracing
- Complete control flow reconstruction
- Coverage-guided analysis
- Performance profiling at hardware level
- Zero-overhead tracing

IoT & Embedded Systems Analysis:
- Firmware extraction and analysis
- CAN bus reverse engineering
- JTAG interface discovery
- Side-channel attacks (ChipWhisperer)
"""

from .intel_pt_analyzer import (
    IntelPTAnalyzer,
    TraceResult,
    ControlFlowTrace,
    CoverageMap,
    PerformanceProfile,
)

from .hardware_breakpoint_engine import HardwareBreakpointEngine, Breakpoint, WatchType

from .firmware_analyzer import FirmwareAnalyzer, FirmwareType, Architecture
from .can_bus_analyzer import CANBusAnalyzer, CANFrame, CANSignal
from .jtag_scanner import JTAGScanner, JTAGPin
from .chipwhisperer_integration import ChipWhispererIntegration

__all__ = [
    "IntelPTAnalyzer",
    "TraceResult",
    "ControlFlowTrace",
    "CoverageMap",
    "PerformanceProfile",
    "HardwareBreakpointEngine",
    "Breakpoint",
    "WatchType",
    "FirmwareAnalyzer",
    "FirmwareType",
    "Architecture",
    "CANBusAnalyzer",
    "CANFrame",
    "CANSignal",
    "JTAGScanner",
    "JTAGPin",
    "ChipWhispererIntegration",
]
