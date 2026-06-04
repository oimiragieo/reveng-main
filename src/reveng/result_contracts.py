"""Backwards-compatibility shim — moved to :mod:`reveng.core.result_contracts`.

The versioned result/evidence contracts are a cross-cutting concern and now live
under ``reveng.core``. This shim re-exports them so existing
``reveng.result_contracts`` importers keep working.
"""

from .core.result_contracts import *  # noqa: F401,F403
