"""
Pipeline stage engine and step runners for the REVENG analyzer.

Distinct from ``reveng.pipelines`` (high-level workflow templates). See
``reveng.pipelines`` package docstring and backlog item M5-PIPE before any merge.
"""

from . import steps

__all__ = ["steps"]
