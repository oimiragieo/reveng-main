"""Soft import-graph completion after fingerprint confirms.

Infers additional path attributions when an anonymous module's static import
string set is a unique subset of a confirmed module's imports (precision-first).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Set

_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[^'"]+\s+from\s+)?|require\s*\(\s*|from\s+)['"]([^'"]+)['"]"""
)


@dataclass
class GraphHint:
    anonymous_id: str
    inferred_path: str
    shared_imports: int
    note: str


def _imports_of(text: str) -> Set[str]:
    return {m.replace("\\", "/") for m in _IMPORT_RE.findall(text or "") if m}


def suggest_graph_completions(
    *,
    confirmed_path_to_body: Dict[str, str],
    anonymous_modules: Dict[str, str],
    min_shared: int = 3,
) -> List[GraphHint]:
    """Suggest anonymous→path links when import sets uniquely identify a confirm."""
    confirmed_imports = {p: _imports_of(b) for p, b in confirmed_path_to_body.items()}
    hints: List[GraphHint] = []
    for anon_id, body in anonymous_modules.items():
        imports = _imports_of(body)
        if len(imports) < min_shared:
            continue
        matches = []
        for path, conf_imps in confirmed_imports.items():
            shared = imports & conf_imps
            if len(shared) >= min_shared and imports <= conf_imps:
                matches.append((path, len(shared)))
        if len(matches) != 1:
            continue
        path, n = matches[0]
        hints.append(
            GraphHint(
                anonymous_id=anon_id,
                inferred_path=path,
                shared_imports=n,
                note="unique_import_subset",
            )
        )
    return hints
