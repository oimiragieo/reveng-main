#!/usr/bin/env python3
"""Direct CLI wrapper for manual `python src/reveng/cli/reveng.py ...` execution."""

from __future__ import annotations

import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from reveng.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
