"""Filename-set JS oracle scorecard (honest reconstruction metrics).

This is **not** the RALPH-2 token engine. Scores are derived from relative-path /
basename file matching only (`reconstruction_mode="filename_set"`).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

_SKIP_DIR_NAMES = frozenset({"node_modules", ".git"})
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+")


def _basename_tokens(name: str) -> Set[str]:
    return {t for t in _TOKEN_SPLIT.split(name) if t}


def _iter_oracle_relpaths(oracle_dir: Path) -> List[str]:
    root = oracle_dir.resolve()
    out: List[str] = []
    if not root.is_dir():
        return out
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        out.append(path.relative_to(root).as_posix())
    return out


def _dedupe_existing(paths: Sequence[Path]) -> List[Path]:
    seen: Set[Path] = set()
    out: List[Path] = []
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            continue
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _recovered_rel_or_none(path: Path, recovered_root: Optional[Path]) -> Optional[str]:
    if recovered_root is None:
        return None
    root = recovered_root.resolve()
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return None


def compute_js_project_file_scorecard(
    oracle_dir: Path,
    recovered_paths: Sequence[Path],
    *,
    recovered_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Compute filename-set recall/precision and aggregate scores."""
    notes: List[str] = []
    oracle_rels = _iter_oracle_relpaths(Path(oracle_dir))
    recovered = _dedupe_existing(recovered_paths)

    if recovered_root is None:
        notes.append("no_recovered_root")

    if not oracle_rels:
        notes.append("empty_oracle")
        return {
            "project_file_recall": 0.0,
            "project_file_precision": 0.0,
            "matched_oracle_file_count": 0,
            "oracle_file_count": 0,
            "recovered_file_count": len(recovered),
            "reconstruction_mode": "filename_set",
            "match_mode": "none",
            "overall_score": 0.0,
            "token_signal_score": 0.0,
            "token_signal_mode": "filename_set_basename_jaccard_all",
            "notes": notes,
        }

    unmatched_oracle = set(oracle_rels)
    unmatched_recovered: List[Tuple[Path, Optional[str]]] = [
        (path, _recovered_rel_or_none(path, recovered_root)) for path in recovered
    ]

    matched_pairs: List[Tuple[str, Path]] = []
    used_recovered: Set[Path] = set()

    # Pass 1: relative path
    still_unmatched: List[Tuple[Path, Optional[str]]] = []
    for path, rel in unmatched_recovered:
        if rel is not None and rel in unmatched_oracle:
            unmatched_oracle.remove(rel)
            used_recovered.add(path)
            matched_pairs.append((rel, path))
        else:
            still_unmatched.append((path, rel))

    relative_matches = len(matched_pairs)

    # Pass 2: basename (lexicographic oracle order)
    basename_index: Dict[str, List[str]] = {}
    for orel in sorted(unmatched_oracle):
        basename_index.setdefault(Path(orel).name, []).append(orel)

    collision = False
    for path, _rel in still_unmatched:
        if path in used_recovered:
            continue
        name = path.name
        candidates = basename_index.get(name) or []
        if not candidates:
            continue
        if len(candidates) > 1:
            collision = True
        orel = candidates.pop(0)
        unmatched_oracle.discard(orel)
        used_recovered.add(path)
        matched_pairs.append((orel, path))

    if collision:
        notes.append("basename_collision")

    matched = len(matched_pairs)
    oracle_count = len(oracle_rels)
    recovered_count = len(recovered)
    recall = matched / oracle_count if oracle_count else 0.0
    precision = matched / recovered_count if recovered_count else 0.0
    overall = (recall + precision) / 2.0

    if relative_matches > 0:
        match_mode = "relative_path"
    elif matched > 0:
        match_mode = "basename"
    else:
        match_mode = "none"

    oracle_tokens: Set[str] = set()
    for orel in oracle_rels:
        oracle_tokens |= _basename_tokens(Path(orel).name)
    recovered_tokens: Set[str] = set()
    for path in recovered:
        recovered_tokens |= _basename_tokens(path.name)
    union = oracle_tokens | recovered_tokens
    token_signal = (len(oracle_tokens & recovered_tokens) / len(union)) if union else 0.0

    return {
        "project_file_recall": recall,
        "project_file_precision": precision,
        "matched_oracle_file_count": matched,
        "oracle_file_count": oracle_count,
        "recovered_file_count": recovered_count,
        "reconstruction_mode": "filename_set",
        "match_mode": match_mode,
        "overall_score": overall,
        "token_signal_score": token_signal,
        "token_signal_mode": "filename_set_basename_jaccard_all",
        "notes": notes,
    }


__all__ = ["compute_js_project_file_scorecard"]
