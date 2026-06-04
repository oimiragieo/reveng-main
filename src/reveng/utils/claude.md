# `claude.md` — `utils`

**Repository path:** `src/reveng/utils/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `security.py`
- **Summary:** Security utilities for REVENG
- **Classes:**
  - `PathTraversalError` — Raised when a path traversal attack is detected in an archive
- **Functions / coroutines:**
  - `def safe_extract_zip()` — Safely extract a ZIP file, preventing path traversal attacks.
  - `def safe_extract_tar()` — Safely extract a TAR file, preventing path traversal attacks.
  - `def safe_extract_archive()` — Safely extract an archive (ZIP or TAR), auto-detecting the format.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
