# Validation Surface

The primary validation surfaces for the REVENG toolkit are:
1. The **CLI Engine** (`src/reveng/cli/reveng.py` and `reveng` executable).
2. The **Python Test Suite** (`pytest` via the `tests/` directory).

## Setup & Gotchas
- **Windows CLI Output:** When running the CLI tests or automation in Windows, you MUST set `PYTHONIOENCODING=utf8` to prevent `charmap` codec errors (e.g. `cmd /c "set PYTHONIOENCODING=utf8 && python reveng.py --help"`).
- **Absolute vs Relative Paths:** Some existing unit tests fail if absolute paths are evaluated against expected relative paths in temp directories. Be mindful when writing new test assertions.

## Validation Concurrency
Based on the dry run and available headroom (where multiple large applications like VSCode, Chrome, Docker are active):
- **Test Suite (Pytest):** Max concurrent workers for `pytest-xdist` should be `4`.
- **CLI Validation (`tuistory` / subprocess execution):** Max concurrent validators is **3**. Running more concurrent instances of Ghidra, angr, and ML models simultaneously will cause severe memory bottlenecks.
