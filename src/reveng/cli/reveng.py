#!/usr/bin/env python3
"""Direct CLI wrapper for manual `python src/reveng/cli/reveng.py ...` execution."""

from __future__ import annotations

import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path[:] = [p for p in sys.path if p and Path(p).resolve() != _SCRIPT_DIR]
_src = str(SRC_ROOT)
if _src in sys.path:
    sys.path.remove(_src)
sys.path.insert(0, _src)

from reveng.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
