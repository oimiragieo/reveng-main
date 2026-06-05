# `claude.md` — `tools/threat_intel`

**Repository path:** `src/reveng/tools/threat_intel/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Threat Intelligence Tools

### `virustotal_connector.py`
- **Summary:** VirusTotal Integration for REVENG
- **Classes:**
  - `VTEnrichment` — VirusTotal enrichment data
  - `VirusTotalConnector` — VirusTotal API connector for threat intelligence enrichment.
- **Functions / coroutines:**
  - `def quick_lookup()` — Quick VirusTotal lookup for a file.

### `yara_generator.py`
- **Summary:** YARA Rule Generator for REVENG
- **Classes:**
  - `YARARule` — YARA rule representation
  - `YARAGenerator` — Automatic YARA rule generator from binary analysis.
- **Functions / coroutines:**
  - `def quick_generate()` — Quick YARA rule generation from file.

### `yara_scanner.py`
- **Summary:** Backwards-compatible threat-intel wrapper for the built-in YARA scanner.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
