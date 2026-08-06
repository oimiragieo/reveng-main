"""
High-level analysis workflow templates (malware / .NET / triage).

This package is intentionally separate from ``reveng.pipeline``:

- ``reveng.pipeline`` — stage engine + step runners used by the main analyzer CLI.
- ``reveng.pipelines`` — opinionated multi-tool workflow templates (this package).

Do not merge the packages without an import-linter migration plan (M5-PIPE).
"""

from .automated_analysis import AutomatedAnalysisPipeline

__all__ = ["AutomatedAnalysisPipeline"]
