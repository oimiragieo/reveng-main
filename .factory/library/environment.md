# Environment Setup

Environment variables, external dependencies, and setup notes.

**Gotchas**:
- On Windows, always set `PYTHONIOENCODING=utf8` to avoid charmap codec errors during CLI output generation.
- The Ghidra server runs locally on port 5000.
- Ensure the `pytest-xdist` plugin is installed for concurrent test execution.
