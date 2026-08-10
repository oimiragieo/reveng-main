"""Ensemble fingerprint index/scan using expanded signal kinds."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .ensemble_signals import extract_ensemble_signals

_VENDOR_MARKERS = ("node_modules/", "/vendor/")
_DEFAULT_SALT = "reveng-wave7-ensemble-v1"
_MIN_SIGNALS = 2


def _is_vendor(path: str) -> bool:
    text = path.replace("\\", "/")
    return any(m in text for m in _VENDOR_MARKERS)


def _normalize(raw: str) -> Optional[str]:
    text = (raw or "").strip().replace("\\", "/")
    if not text or _is_vendor(text):
        return None
    if "src/" in text:
        text = text[text.index("src/") :]
    if _is_vendor(text) or not text:
        return None
    return text


def _digest(salt: str, kind: str, value: str) -> str:
    return hashlib.sha256(f"{salt}|{kind}|{value}".encode("utf-8")).hexdigest()


@dataclass
class EnsembleIndex:
    salt: str
    digest_to_path: Dict[str, str] = field(default_factory=dict)
    digest_to_kind: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_serializable(self) -> Dict[str, Any]:
        entries = [
            {
                "digest": d,
                "kind": self.digest_to_kind.get(d, "unknown"),
                "source_path": p,
            }
            for d, p in sorted(self.digest_to_path.items())
        ]
        return {
            "schema_version": "1.0",
            "index_type": "ensemble_fingerprint_index",
            "salt_id": self.salt,
            "entry_count": len(entries),
            "entries": entries,
            "notes": list(self.notes) + ["hashed_only", "raw_values_omitted"],
        }


@dataclass
class EnsembleHit:
    source_path: str
    signal_count: int
    kinds: List[str]
    provenance_confidence: float


def build_ensemble_index_from_sourcemap(
    map_path: Path, *, salt: str = _DEFAULT_SALT
) -> EnsembleIndex:
    data = json.loads(Path(map_path).read_text(encoding="utf-8"))
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    owners: Dict[Tuple[str, str], Set[str]] = {}
    notes = ["ensemble_signals", "unique_to_one_source", "vendor_excluded"]
    for src, body in zip(sources, contents):
        if body is None:
            continue
        path = _normalize(str(src))
        if path is None:
            continue
        for kind, value in extract_ensemble_signals(str(body)):
            owners.setdefault((kind, value), set()).add(path)
    digest_to_path: Dict[str, str] = {}
    digest_to_kind: Dict[str, str] = {}
    skipped = 0
    for (kind, value), paths in owners.items():
        if len(paths) != 1:
            skipped += 1
            continue
        path = next(iter(paths))
        digest = _digest(salt, kind, value)
        digest_to_path[digest] = path
        digest_to_kind[digest] = kind
    notes.append(f"skipped_non_unique:{skipped}")
    notes.append(f"indexed:{len(digest_to_path)}")
    return EnsembleIndex(
        salt=salt, digest_to_path=digest_to_path, digest_to_kind=digest_to_kind, notes=notes
    )


def scan_ensemble(
    index: EnsembleIndex, bundle_text: str, *, min_signals: int = _MIN_SIGNALS
) -> List[EnsembleHit]:
    hits: Dict[str, List[str]] = {}
    seen: Set[str] = set()
    for kind, value in extract_ensemble_signals(bundle_text):
        digest = _digest(index.salt, kind, value)
        path = index.digest_to_path.get(digest)
        if path is None or digest in seen:
            continue
        seen.add(digest)
        hits.setdefault(path, []).append(index.digest_to_kind.get(digest, kind))
    confirmed: List[EnsembleHit] = []
    for path, kinds in sorted(hits.items()):
        if len(kinds) < min_signals:
            continue
        provenance = min(1.0, 0.5 + 0.25 * (len(kinds) - min_signals + 1))
        confirmed.append(
            EnsembleHit(
                source_path=path,
                signal_count=len(kinds),
                kinds=sorted(set(kinds)),
                provenance_confidence=round(provenance, 4),
            )
        )
    return confirmed
