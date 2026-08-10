"""Singleton high-confidence attribution + coverage union toward 100% of survivors."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_LITERAL_RE = re.compile(r"""['"]([A-Za-z][A-Za-z0-9_./:\-]{19,160})['"]""")
_VENDOR = ("node_modules/", "/vendor/")


def _norm_path(raw: str) -> Optional[str]:
    text = (raw or "").strip().replace("\\", "/")
    if not text or any(v in text for v in _VENDOR):
        return None
    if "src/" in text:
        text = text[text.index("src/") :]
    return text or None


def _digest(value: str) -> str:
    return hashlib.sha256(f"reveng-w8-singleton|{value}".encode("utf-8")).hexdigest()


@dataclass
class CoverageReport:
    oracle_count: int
    attributed_count: int
    survivor_count: int
    attributed_of_survivors: int
    oracle_coverage: float
    survivor_coverage: float
    by_method: Dict[str, int]
    notes: List[str]

    def to_serializable(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "oracle_count": self.oracle_count,
            "attributed_count": self.attributed_count,
            "survivor_count": self.survivor_count,
            "attributed_of_survivors": self.attributed_of_survivors,
            "oracle_coverage": self.oracle_coverage,
            "survivor_coverage": self.survivor_coverage,
            "by_method": dict(self.by_method),
            "notes": list(self.notes),
            "decoded_exe_claim": False,
        }


def load_map_sources(map_path: Path) -> Dict[str, str]:
    data = json.loads(Path(map_path).read_text(encoding="utf-8"))
    out: Dict[str, str] = {}
    for src, body in zip(data.get("sources") or [], data.get("sourcesContent") or []):
        if body is None:
            continue
        p = _norm_path(str(src))
        if p and p not in out:
            out[p] = str(body)
    return out


def singleton_literal_hits(sources: Dict[str, str], bundle_text: str) -> Tuple[Set[str], Set[str]]:
    """Confirm paths with a unique ≥20-char literal that appears in the bundle.

    Returns (confirmed_paths, survivor_paths_with_any_unique_literal_in_bundle).
    """
    owners: Dict[str, Set[str]] = {}
    for path, body in sources.items():
        for lit in _LITERAL_RE.findall(body or ""):
            if lit.startswith("http") or "node_modules" in lit:
                continue
            owners.setdefault(lit, set()).add(path)
    unique = {lit: next(iter(paths)) for lit, paths in owners.items() if len(paths) == 1}
    survivors: Set[str] = set()
    confirmed: Set[str] = set()
    for lit, path in unique.items():
        if lit in bundle_text:
            survivors.add(path)
            confirmed.add(path)
    return confirmed, survivors


def union_coverage(
    *,
    oracle_paths: Set[str],
    attributed: Dict[str, str],
    survivor_paths: Set[str],
) -> CoverageReport:
    """attributed: path -> method name."""
    attr_set = set(attributed)
    by_method: Dict[str, int] = {}
    for method in attributed.values():
        by_method[method] = by_method.get(method, 0) + 1
    surv_hit = len(attr_set & survivor_paths)
    notes = [
        "oracle_coverage=attributed/oracle",
        "survivor_coverage=attributed∩survivors/survivors",
        "survivor=unique_long_literal_still_in_bundle",
        "100pct_means_all_survivors_attributed_or_full_map_materialize",
        "not_decoded_exe",
    ]
    return CoverageReport(
        oracle_count=len(oracle_paths),
        attributed_count=len(attr_set),
        survivor_count=len(survivor_paths),
        attributed_of_survivors=surv_hit,
        oracle_coverage=round(len(attr_set) / len(oracle_paths), 4) if oracle_paths else 0.0,
        survivor_coverage=round(surv_hit / len(survivor_paths), 4) if survivor_paths else 0.0,
        by_method=by_method,
        notes=notes,
    )
