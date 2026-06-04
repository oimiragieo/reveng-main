"""Backwards-compatibility shim — moved to :mod:`reveng.core.ir`.

The shared reverse-engineering IR now lives under ``reveng.core``. This shim
re-exports it so existing ``reveng.ir`` importers keep working.
"""

from .core.ir import *  # noqa: F401,F403
