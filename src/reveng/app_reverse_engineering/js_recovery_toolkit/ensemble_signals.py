"""Expanded signal extractors for fingerprint transfer (ensemble).

Adds error/help/slash/path-like tokens on top of Wave 5 literal+export signals.
Still unique-to-one-source + length floors at index time.
"""

from __future__ import annotations

import re
from typing import List, Tuple

# Reuse Wave 5 patterns where possible
_LITERAL_RE = re.compile(r"""['"]([A-Za-z][A-Za-z0-9_./:\- ]{11,160})['"]""")
_EXPORT_RE = re.compile(
    r"\bexport\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]{4,})"
)
_ERROR_RE = re.compile(
    r"""(?:throw\s+new\s+Error|console\.(?:error|warn)|createError)\s*\(\s*['"]([^'"]{12,160})['"]"""
)
_SLASH_RE = re.compile(r"""['"](/[a-z][a-z0-9_\-/]{3,80})['"]""")
_FLAG_RE = re.compile(r"""['"](--[a-z][a-z0-9\-]{3,60})['"]""")
_PATHISH_RE = re.compile(r"""['"]((?:src|lib|packages)/[A-Za-z0-9_./\-]{6,120})['"]""")
_DISPLAY_RE = re.compile(
    r"""(?:displayName|this\.name)\s*=\s*['"]([A-Za-z][A-Za-z0-9_]{3,80})['"]"""
)


def extract_ensemble_signals(text: str) -> List[Tuple[str, str]]:
    """Return ``(kind, value)`` candidates from source or bundle text."""
    out: List[Tuple[str, str]] = []
    body = text or ""
    for lit in _LITERAL_RE.findall(body):
        if lit.startswith("http") or "node_modules" in lit:
            continue
        if lit.lower() in {"application/json", "text/plain", "content-type"}:
            continue
        out.append(("literal", lit.strip()))
    for name in _EXPORT_RE.findall(body):
        out.append(("export_name", name))
    for msg in _ERROR_RE.findall(body):
        out.append(("error_string", msg))
    for slash in _SLASH_RE.findall(body):
        out.append(("slash_cmd", slash))
    for flag in _FLAG_RE.findall(body):
        out.append(("cli_flag", flag))
    for path in _PATHISH_RE.findall(body):
        out.append(("pathish", path.replace("\\", "/")))
    for disp in _DISPLAY_RE.findall(body):
        out.append(("display_name", disp))
    return out
