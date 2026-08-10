"""JS recovery toolkit — multi-strategy climb toward higher attribution coverage.

Orchestrates hermetic REVENG stages plus **optional** external CLIs discovered
via Exa research (2026-08-09). Wave 8 adds structural MinHash, Bun
SerializedSourceMap (zstd) decode, singleton literals, and coverage union.
Does **not** claim exe decode, R-RALPH-2 close, or enterprise GA.

External tools (invoke when present; never hard-vendored into git)::

- Bun extract: ``reveng.tools.anti_analysis.bun_extractor`` (in-tree)
- Optional CLIs: ``webcrack``, ``@wakaru/cli``, ``humanify``, ``unbun``
  (see ``docs/architecture/research-js-recovery-toolkit-2026-08-09.md``
  and ``research-wave8-structural-bun-100-2026-08-09.md``)
"""

from __future__ import annotations

from .pipeline import ToolkitReport, run_recovery_toolkit

__all__ = ["ToolkitReport", "run_recovery_toolkit"]
