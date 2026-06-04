"""Backwards-compatibility shim — renamed to :mod:`reveng.agents.ai.ai_provider_registry`.

Renamed to disambiguate from the similarly-named ``ai_enhanced_orchestrator``
(formerly ``ai_enhanced_analyzer``). This shim re-exports the multi-provider
registry/factory so existing importers keep working.
"""

from .ai_provider_registry import *  # noqa: F401,F403
