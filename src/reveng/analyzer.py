"""Backwards-compatibility shim — moved to :mod:`reveng.analysis.analyzer`.

The core REVENGAnalyzer now lives in the analysis domain. This shim re-exports
it so existing ``reveng.analyzer`` / ``from reveng import analyzer`` importers
keep working.
"""

from .analysis.analyzer import *  # noqa: F401,F403
