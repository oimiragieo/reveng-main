# `claude.md` — `evasion`

**Repository path:** `src/reveng/evasion/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** EDR Evasion Module

### `api_unhooking.py`
- **Summary:** API Unhooking Module
- **Classes:**
  - `APIHook` — Information about a hooked API
  - `APIUnhooker` — API unhooking engine for EDR bypass.

### `edr_evasion_engine.py`
- **Summary:** EDR Evasion Engine
- **Classes:**
  - `EvasionTechnique` — EDR evasion techniques
  - `EDRHook` — Detected EDR hook information
  - `RWXSection` — RWX memory section information
  - `EvasionResult` — Result of evasion technique
  - `EDREvasionEngine` — Advanced EDR evasion engine implementing cutting-edge bypass techniques.

### `environmental_keying.py`
- **Summary:** Environmental Keying Module
- **Classes:**
  - `EnvironmentType` — Types of analysis environments
  - `EnvironmentCheck` — Single environment check result
  - `EnvironmentProfile` — Complete environment analysis
  - `EnvironmentalKeying` — Environmental detection and keying engine.

### `process_mockingjay.py`
- **Summary:** Process Mockingjay Implementation
- **Classes:**
  - `MockingjayTarget` — Target DLL for Process Mockingjay
  - `ProcessMockingjayEngine` — Process Mockingjay exploitation engine.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
