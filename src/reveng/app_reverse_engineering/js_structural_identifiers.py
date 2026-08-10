"""Collect generic structural identifier *hints* from JS/TS text (Wave 4).

Hints are advisory only — never applied as a rewrite/demangler. No vendor-
specific name tables.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Set

_EXPORT_NAME = re.compile(
    r"\b(?:export\s+(?:async\s+)?(?:function|class|const|let|var)\s+|exports\.|module\.exports\.)"
    r"([A-Za-z_$][\w$]*)"
)
_NAMED_EXPORT_BRACE = re.compile(r"\bexport\s*\{([^}]+)\}")
_STRING_KEY = re.compile(r"""['"]([A-Za-z_$][\w$]{2,})['"]\s*:""")
_FUNCTION_DECL = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(")


def collect_structural_identifier_hints(source_path: Path) -> Dict[str, Any]:
    """Return a JSON-serializable hint payload for ``source_path``.

    Does not mutate the source. Empty/missing files yield empty hint lists.
    """
    path = Path(source_path)
    hints: Dict[str, List[str]] = {
        "export_like_names": [],
        "string_object_keys": [],
        "function_names": [],
    }
    notes: List[str] = []
    if not path.is_file():
        return {
            "schema_version": "1.0",
            "source_path": str(path),
            "hints": hints,
            "notes": ["source_missing"],
            "rewrite_applied": False,
        }

    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return {
            "schema_version": "1.0",
            "source_path": str(path),
            "hints": hints,
            "notes": ["source_empty"],
            "rewrite_applied": False,
        }

    export_names: Set[str] = set(_EXPORT_NAME.findall(text))
    for block in _NAMED_EXPORT_BRACE.findall(text):
        for part in block.split(","):
            token = part.strip().split(" as ")[0].strip()
            if re.match(r"^[A-Za-z_$][\w$]*$", token):
                export_names.add(token)
    string_keys = set(_STRING_KEY.findall(text))
    functions = set(_FUNCTION_DECL.findall(text))

    hints["export_like_names"] = sorted(export_names)
    hints["string_object_keys"] = sorted(string_keys)
    hints["function_names"] = sorted(functions)
    notes.append("hints_only_no_rewrite")
    return {
        "schema_version": "1.0",
        "source_path": str(path),
        "hints": hints,
        "notes": notes,
        "rewrite_applied": False,
    }


__all__ = ["collect_structural_identifier_hints"]
