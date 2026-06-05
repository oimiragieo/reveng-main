# `claude.md` — `hardware`

**Repository path:** `src/reveng/hardware/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** REVENG v5.0 - Hardware-Assisted Analysis

### `can_bus_analyzer.py`
- **Summary:** CAN Bus Analyzer
- **Classes:**
  - `CANFrameType` — CAN frame types
  - `CANFrame` — CAN bus frame
  - `CANSignal` — Identified CAN signal
  - `CANBusAnalyzer` — CAN bus reverse engineering and exploitation engine.

### `chipwhisperer_integration.py`
- **Summary:** ChipWhisperer Integration
- **Classes:**
  - `PowerTrace` — Power consumption trace
  - `ChipWhispererIntegration` — ChipWhisperer-based hardware attack platform.

### `firmware_analyzer.py`
- **Summary:** Firmware Analyzer
- **Classes:**
  - `FirmwareType` — Types of firmware
  - `Architecture` — Supported architectures
  - `FirmwareMetadata` — Firmware metadata
  - `ExtractedFilesystem` — Extracted filesystem information
  - `FirmwareAnalyzer` — Advanced firmware analysis engine.

### `hardware_breakpoint_engine.py`
- **Summary:** Hardware Breakpoint Engine
- **Classes:**
  - `WatchType` — Types of hardware watchpoints
  - `BreakpointCondition` — Breakpoint conditions
  - `Breakpoint` — Hardware breakpoint
  - `HardwareBreakpointEngine` — Hardware breakpoint management using CPU debug registers

### `intel_pt_analyzer.py`
- **Summary:** Intel Processor Trace (PT) Analyzer
- **Classes:**
  - `BasicBlock` — A basic block in the execution trace
  - `Branch` — A branch in the execution
  - `ControlFlowTrace` — Complete control flow trace
  - `CoverageMap` — Code coverage information
  - `PerformanceProfile` — Performance profiling data
  - `TraceResult` — Result from Intel PT tracing
  - `IntelPTAnalyzer` — Intel Processor Trace analyzer for hardware-level tracing

### `jtag_scanner.py`
- **Summary:** JTAG Scanner
- **Classes:**
  - `JTAGPin` — JTAG pin configuration
  - `JTAGScanner` — JTAG pinout scanner (JTAGulator implementation).

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
