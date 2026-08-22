"""JS recovery toolkit — multi-strategy climb toward higher attribution coverage.

Orchestrates hermetic REVENG stages plus **optional** external CLIs discovered
via Exa research (2026-08-09+). Wave map:

- 7: ensemble fingerprint
- 8: structural MinHash, Bun SerializedSourceMap (zstd), singleton literals, coverage union
- 8.5: iterative defrag + TF-IDF word_map (Option C metrics)
- 9 / 9b: readable normalize, semantic digest, LLM digest + tag-boost; webcrack/wakaru adapters
- 10: Hungarian soft_assign + unique-token tombstones + recoverable_oracle_coverage

Does **not** claim exe decode, R-RALPH-2 close, or enterprise GA.

Option C: ship bar = survivor/unlockable **1.0**; ``oracle_coverage`` aspirational; report BOTH.
See ``.cursor/skills/reveng-js-recovery-climb/``.

External tools (invoke when present; never hard-vendored into git)::

- Bun extract: ``reveng.tools.anti_analysis.bun_extractor`` (in-tree)
- Optional CLIs: ``webcrack``, ``@wakaru/cli``, ``humanify``, ``unbun``
  (see ``docs/architecture/research-js-recovery-toolkit-2026-08-09.md``
  and ``research-wave8-structural-bun-100-2026-08-09.md`` /
  ``research-wave10-soft-assignment-2026-08-10.md``)
"""

from __future__ import annotations

from .pipeline import ToolkitReport, run_recovery_toolkit

__all__ = ["ToolkitReport", "run_recovery_toolkit"]
