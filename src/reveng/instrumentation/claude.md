# `claude.md` — `instrumentation`

**Repository path:** `src/reveng/instrumentation/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Dynamic Instrumentation Module

### `dynamic_instrumentation_engine.py`
- **Summary:** Dynamic Instrumentation Engine
- **Classes:**
  - `InstrumentationMode` — Instrumentation attachment modes
  - `TargetPlatform` — Supported target platforms
  - `InstrumentationTarget` — Target process information
  - `HookResult` — Result from a hook execution
  - `InstrumentationSession` — Active instrumentation session
  - `DynamicInstrumentationEngine` — Advanced dynamic instrumentation engine for runtime code manipulation.
- **Functions / coroutines:**
  - `def quick_bypass()` — Quick bypass of common security controls.

### `function_hooker.py`
- **Summary:** Function Hooker
- **Classes:**
  - `HookStrategy` — Hook implementation strategies
  - `FunctionSignature` — Function signature information
  - `HookInfo` — Hook installation information
  - `FunctionHooker` — Advanced function hooking engine.

### `hook_manager.py`
- **Summary:** Hook Manager
- **Classes:**
  - `HookType` — Types of hooks
  - `Hook` — Hook configuration
  - `HookEvent` — Event data from hook execution
  - `HookManager` — Manages function hooks and interception callbacks.

### `memory_scanner.py`
- **Summary:** Memory Scanner
- **Classes:**
  - `ScanType` — Memory scan types
  - `MemoryRegion` — Memory region information
  - `ScanResult` — Memory scan result
  - `MemoryScanner` — Memory scanning and pattern matching engine.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
