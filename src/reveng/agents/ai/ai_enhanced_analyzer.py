"""Backwards-compatibility shim — renamed to :mod:`reveng.agents.ai.ai_enhanced_orchestrator`.

Renamed to disambiguate from ``ai_provider_registry`` (formerly
``ai_analyzer_enhanced``). This shim re-exports the orchestrator so existing
importers keep working.
"""

from .ai_enhanced_orchestrator import *  # noqa: F401,F403
