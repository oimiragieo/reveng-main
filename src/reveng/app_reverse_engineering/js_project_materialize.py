"""Materialize ``output_dir/project`` for JS oracle scorecards (Wave 4)."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_PROJECT_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx"}
_SAFE_REL = re.compile(r"^[A-Za-z0-9_./\\-]+$")
_SCHEME_PREFIX = re.compile(
    r"^(?:webpack(?:-internal)?|vite|rollup|ng|turbopack):/+",
    re.IGNORECASE,
)
_SYNTHETIC = re.compile(r"(?:\s(?:lazy|sync)\s|[!|]|\(webpack\)|namespace object)", re.I)


@dataclass
class ProjectMaterializeResult:
    recovered_root: Optional[Path]
    mode: str
    files_written: int
    notes: List[str] = field(default_factory=list)


def _wipe_project(output_dir: Path) -> None:
    project = output_dir / "project"
    if project.exists():
        shutil.rmtree(project)


def _sanitize_relpath(raw: str) -> Optional[str]:
    text = (raw or "").strip().replace("\\", "/")
    if not text:
        return None
    text = text.split("?", 1)[0].split("#", 1)[0]
    text = _SCHEME_PREFIX.sub("", text)
    # turbopack://[project]/src/... → drop bracket token
    text = re.sub(r"^\[project\]/?", "", text)
    if text.startswith("/") or re.match(r"^[A-Za-z]:/", text):
        return None
    if _SYNTHETIC.search(text):
        return None
    # Drop leading ../ noise from esbuild sources like ../js_tracked_bundle_source/src/...
    parts: List[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        if part.startswith(".") and part not in {".", ".."}:
            return None
        parts.append(part)
    if not parts:
        return None
    joined = "/".join(parts)
    if "src/" in joined:
        joined = joined[joined.index("src/") :]
    if not _SAFE_REL.match(joined):
        return None
    return joined


def _write_text(dest: Path, content: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")


def _find_sibling_map(
    input_path: Optional[Path], normalized_bundle: Optional[Path]
) -> Optional[Path]:
    candidates: List[Path] = []
    for base in (input_path, normalized_bundle):
        if base is None:
            continue
        candidates.append(Path(str(base) + ".map"))
        candidates.append(base.with_suffix(base.suffix + ".map"))
        if base.suffix:
            candidates.append(base.with_name(base.name + ".map"))
    # Also: input_dir/bundle.js.map classic
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _materialize_from_sourcemap(map_path: Path, project: Path) -> ProjectMaterializeResult:
    data = json.loads(map_path.read_text(encoding="utf-8"))
    sources = data.get("sources") or []
    contents = data.get("sourcesContent")
    if not isinstance(sources, list) or not sources:
        return ProjectMaterializeResult(None, "absent", 0, ["sourcemap_missing_sources"])
    if not isinstance(contents, list) or len(contents) != len(sources):
        return ProjectMaterializeResult(None, "absent", 0, ["sourcemap_missing_sourcesContent"])

    written = 0
    notes: List[str] = [f"sourcemap:{map_path.name}"]
    for src, body in zip(sources, contents):
        if body is None:
            notes.append(f"skip_null_content:{src}")
            continue
        rel = _sanitize_relpath(str(src))
        if not rel:
            notes.append(f"skip_unsafe_path:{src}")
            continue
        suffix = Path(rel).suffix.lower()
        if suffix and suffix not in _PROJECT_SUFFIXES:
            notes.append(f"skip_suffix:{rel}")
            continue
        _write_text(project / rel, str(body))
        written += 1
    if written == 0:
        return ProjectMaterializeResult(None, "absent", 0, notes + ["sourcemap_wrote_zero"])
    return ProjectMaterializeResult(project, "source_map", written, notes)


def _materialize_from_bun_vfs(bun_vfs_dir: Path, project: Path) -> ProjectMaterializeResult:
    root = bun_vfs_dir / "root"
    if not root.is_dir():
        return ProjectMaterializeResult(None, "absent", 0, ["bun_vfs_root_missing"])
    written = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _PROJECT_SUFFIXES:
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        safe = _sanitize_relpath(rel)
        if not safe:
            continue
        dest = project / safe
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        written += 1
    if written == 0:
        return ProjectMaterializeResult(None, "absent", 0, ["bun_vfs_no_project_files"])
    return ProjectMaterializeResult(project, "bun_vfs", written, ["bun_vfs"])


def materialize_js_project_tree(
    *,
    output_dir: Path,
    normalized_bundle: Optional[Path] = None,
    input_path: Optional[Path] = None,
    bun_vfs_dir: Optional[Path] = None,
) -> ProjectMaterializeResult:
    """Create ``output_dir/project`` for filename-set oracle scoring.

    Prefer source-map ``sourcesContent``, then Bun VFS. Empty inputs stay absent.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _wipe_project(output_dir)
    project = output_dir / "project"

    map_path = _find_sibling_map(
        Path(input_path) if input_path else None,
        Path(normalized_bundle) if normalized_bundle else None,
    )
    if map_path is not None:
        result = _materialize_from_sourcemap(map_path, project)
        if result.recovered_root is not None:
            return result

    vfs = Path(bun_vfs_dir) if bun_vfs_dir else (output_dir / "bunfs")
    if vfs.is_dir():
        result = _materialize_from_bun_vfs(vfs, project)
        if result.recovered_root is not None:
            return result

    # Non-empty fallback only — still marks fallback; ship gate prefers source_map.
    if normalized_bundle and Path(normalized_bundle).is_file():
        text = Path(normalized_bundle).read_text(encoding="utf-8", errors="replace")
        if text.strip():
            project.mkdir(parents=True, exist_ok=True)
            _write_text(project / "index.js", text)
            return ProjectMaterializeResult(
                project,
                "fallback_index",
                1,
                ["materialization_fallback_index"],
            )

    return ProjectMaterializeResult(None, "absent", 0, ["no_materialization_inputs"])
