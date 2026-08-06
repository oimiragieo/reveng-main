"""Structured capability dimensions for app reverse-engineering results."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple, cast

CAPABILITY_REPORT_SCHEMA_VERSION = "1.0"

_JS_SYNTAX_SUFFIXES = {".js", ".cjs", ".mjs"}
_TS_SYNTAX_SUFFIXES = {".ts", ".tsx", ".mts", ".cts"}

# Size-scaled probe timeouts (P3-BP-4): keep small trees snappy, give large trees room.
_JS_PROBE_TIMEOUT_BASE_SEC = 25.0
_JS_PROBE_TIMEOUT_MID_SEC = 60.0
_JS_PROBE_TIMEOUT_LARGE_SEC = 90.0
_JS_PROBE_TIMEOUT_MAX_SEC = 120.0
_JS_NPM_PROBE_TIMEOUT_BASE_SEC = 90.0
_JS_NPM_PROBE_TIMEOUT_MAX_SEC = 180.0


def project_tree_stats(project_dir: Path) -> Dict[str, int]:
    """Count files and bytes under a reconstructed project (skips node_modules)."""
    root = project_dir.expanduser().resolve()
    file_count = 0
    total_bytes = 0
    if not root.is_dir():
        return {"file_count": 0, "total_bytes": 0}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if "node_modules" in {p.lower() for p in path.parts}:
            continue
        file_count += 1
        try:
            total_bytes += path.stat().st_size
        except OSError:
            continue
    return {"file_count": file_count, "total_bytes": total_bytes}


def resolve_javascript_probe_timeout_sec(
    project_dir: Path,
    *,
    explicit: Optional[float] = None,
    base_sec: float = _JS_PROBE_TIMEOUT_BASE_SEC,
    for_npm: bool = False,
) -> float:
    """
    Pick a subprocess timeout from tree size unless the caller set ``explicit``.

    Rough bands (file_count, excluding node_modules):
    - ≤50 files → base (25s help / 90s npm)
    - ≤500 files → mid (60s / 120s)
    - larger → large (90s / 180s), hard-capped
    """
    if explicit is not None and explicit > 0:
        return float(explicit)
    stats = project_tree_stats(project_dir)
    n = stats["file_count"]
    if for_npm:
        if n <= 50:
            return _JS_NPM_PROBE_TIMEOUT_BASE_SEC
        if n <= 500:
            return min(_JS_NPM_PROBE_TIMEOUT_MAX_SEC, 120.0)
        return _JS_NPM_PROBE_TIMEOUT_MAX_SEC
    if n <= 50:
        return base_sec
    if n <= 500:
        return _JS_PROBE_TIMEOUT_MID_SEC
    return min(_JS_PROBE_TIMEOUT_LARGE_SEC, _JS_PROBE_TIMEOUT_MAX_SEC)


def _safe_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_oracle_alignment(payload: Mapping[str, Any]) -> Dict[str, Any]:
    scorecard = payload.get("benchmark_scorecard")
    if not isinstance(scorecard, Mapping):
        return {"present": False}
    out: Dict[str, Any] = {"present": True}
    for key in (
        "project_file_recall",
        "project_file_precision",
        "domain_recall",
        "domain_precision",
        "matched_oracle_file_count",
        "reconstruction_mode",
    ):
        if key in scorecard:
            out[key] = scorecard.get(key)
    return out


def _artifact_presence(primary_artifacts: Mapping[str, Path]) -> Dict[str, bool]:
    return {name: path.exists() for name, path in primary_artifacts.items()}


def _collect_js_syntax_candidates(
    project_dir: Path, package_data: Any, *, max_files: int
) -> List[Path]:
    candidates: List[Path] = []
    seen: set[str] = set()

    def _push(rel: Optional[str]) -> None:
        if not rel or not isinstance(rel, str):
            return
        p = (project_dir / rel).resolve()
        try:
            p.relative_to(project_dir.resolve())
        except ValueError:
            return
        if p.suffix.lower() not in _JS_SYNTAX_SUFFIXES or not p.is_file():
            return
        key = str(p)
        if key not in seen:
            seen.add(key)
            candidates.append(p)

    if isinstance(package_data, dict):
        _push(package_data.get("main"))
        _push(package_data.get("module"))
        bin_field = package_data.get("bin")
        if isinstance(bin_field, str):
            _push(bin_field)
        elif isinstance(bin_field, dict):
            for val in bin_field.values():
                if isinstance(val, str):
                    _push(val)

    extra: List[Tuple[int, Path]] = []
    for path in project_dir.rglob("*"):
        if not path.is_file():
            continue
        parts_lower = {x.lower() for x in path.parts}
        if "node_modules" in parts_lower:
            continue
        if path.suffix.lower() not in _JS_SYNTAX_SUFFIXES:
            continue
        key = str(path.resolve())
        if key in seen:
            continue
        depth = len(path.relative_to(project_dir).parts)
        extra.append((depth, path))

    extra.sort(key=lambda t: (t[0], str(t[1]).lower()))
    for _, path in extra:
        if len(candidates) >= max_files:
            break
        _push(str(path.relative_to(project_dir)))

    return candidates[:max_files]


def _resolve_package_cli_entry(project_dir: Path, package_data: Any) -> Optional[Path]:
    """
    Pick a Node entry for ``node <entry> --help``: ``bin``, then ``main``, then
    ``reveng.behavior_probe_main`` (REVENG stub for TS-only ``main``).

    Only returns paths under ``project_dir`` with a recognized JS suffix.
    """
    if not isinstance(package_data, dict):
        return None
    pkg = cast(Dict[str, Any], package_data)
    candidates: List[str] = []
    bin_field = pkg.get("bin")
    if isinstance(bin_field, str):
        candidates.append(bin_field)
    elif isinstance(bin_field, dict) and bin_field:
        first_key = sorted(bin_field.keys())[0]
        val = bin_field[first_key]
        if isinstance(val, str):
            candidates.append(val)
    main = pkg.get("main")
    if isinstance(main, str):
        candidates.append(main)
    rev = pkg.get("reveng")
    if isinstance(rev, dict):
        bpm = rev.get("behavior_probe_main")
        if isinstance(bpm, str):
            candidates.append(bpm)

    root = project_dir.resolve()
    for rel in candidates:
        if not rel.strip():
            continue
        entry = (project_dir / rel).resolve()
        try:
            entry.relative_to(root)
        except ValueError:
            continue
        if entry.suffix.lower() not in _JS_SYNTAX_SUFFIXES or not entry.is_file():
            continue
        return entry
    return None


def _resolve_typescript_cli_entry(project_dir: Path, package_data: Any) -> Optional[Path]:
    """Pick a TypeScript entry (``bin`` / ``main``) when no JS entry resolves."""
    if not isinstance(package_data, dict):
        return None
    pkg = cast(Dict[str, Any], package_data)
    candidates: List[str] = []
    bin_field = pkg.get("bin")
    if isinstance(bin_field, str):
        candidates.append(bin_field)
    elif isinstance(bin_field, dict) and bin_field:
        first_key = sorted(bin_field.keys())[0]
        val = bin_field[first_key]
        if isinstance(val, str):
            candidates.append(val)
    main = pkg.get("main")
    if isinstance(main, str):
        candidates.append(main)

    root = project_dir.resolve()
    for rel in candidates:
        if not rel.strip():
            continue
        entry = (project_dir / rel).resolve()
        try:
            entry.relative_to(root)
        except ValueError:
            continue
        if entry.suffix.lower() not in _TS_SYNTAX_SUFFIXES or not entry.is_file():
            continue
        return entry
    return None


def run_javascript_behavior_probe(
    project_dir: Path,
    *,
    timeout_sec: Optional[float] = None,
    run_probe: bool = True,
) -> Dict[str, Any]:
    """
    Run ``node <entry> --help`` from the project root (npm-style CLI smoke).

    Persists evidence tails and a small ``tier`` for ranking (0=none, 1=help-like output,
    2=exit code 0). When ``timeout_sec`` is omitted, scales by project tree size (P3-BP-4).
    """
    root = project_dir.expanduser().resolve()
    effective_timeout = resolve_javascript_probe_timeout_sec(root, explicit=timeout_sec)
    section: Dict[str, Any] = {
        "project_dir": str(root),
        "skipped": True,
        "reason": "disabled",
        "tier": 0,
        "entry_relative": None,
        "command": None,
        "exit_code": None,
        "stdout_tail": "",
        "stderr_tail": "",
        "summary": "skipped",
        "timeout_sec": effective_timeout,
    }
    if not run_probe:
        section["reason"] = "disabled"
        return section
    if not root.is_dir():
        section["reason"] = "project_dir_missing"
        return section

    pkg = root / "package.json"
    if not pkg.is_file():
        section["reason"] = "no_package_json"
        return section
    try:
        package_data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        section["reason"] = f"package_json_parse_error:{exc.__class__.__name__}"
        return section

    entry = _resolve_package_cli_entry(root, package_data)
    runner = "node"
    runner_exe: Optional[str] = None
    if entry is not None:
        runner_exe = which("node")
        if not runner_exe:
            section["reason"] = "node_not_found"
            return section
    else:
        entry = _resolve_typescript_cli_entry(root, package_data)
        if entry is None:
            section["reason"] = "no_cli_entry"
            return section
        runner = "tsx"
        runner_exe = which("tsx")
        if not runner_exe:
            section["reason"] = "tsx_not_found"
            return section

    rel_posix = entry.relative_to(root).as_posix()
    cmd = [runner_exe, rel_posix, "--help"]
    section["entry_relative"] = rel_posix
    section["command"] = cmd
    section["runner"] = runner

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        section["skipped"] = False
        section["reason"] = "timeout"
        section["summary"] = "cli_help_timeout"
        return section
    except OSError as exc:
        section["skipped"] = False
        section["reason"] = f"os_error:{exc.__class__.__name__}"
        section["summary"] = "cli_help_os_error"
        return section

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    section["stdout_tail"] = stdout[-800:]
    section["stderr_tail"] = stderr[-800:]
    section["exit_code"] = proc.returncode
    section["skipped"] = False

    combined = (stdout + stderr).lower()
    hints = (
        "usage",
        "options:",
        "option:",
        "--help",
        "help:",
        "commands:",
        "arguments:",
    )
    has_hint = any(h in combined for h in hints)
    ec = proc.returncode
    if ec == 0:
        section["tier"] = 2
        section["reason"] = "exit_zero"
        section["summary"] = "cli_help_exit_zero"
    elif has_hint:
        section["tier"] = 1
        section["reason"] = "help_like_output"
        section["summary"] = "cli_help_like_nonzero_exit"
    else:
        section["tier"] = 0
        section["reason"] = f"nonzero_exit:{ec}"
        section["summary"] = "cli_no_help_hints"

    return section


def run_javascript_npm_lifecycle_probe(
    project_dir: Path,
    *,
    timeout_sec: Optional[float] = None,
    run_probe: bool = False,
) -> Dict[str, Any]:
    """
    Optional ``npm pack --dry-run`` smoke for reconstructed Node projects (P3-BP-2).

    Default-off: packaging can be slow and needs ``npm`` on PATH. When enabled,
    records whether ``npm pack --dry-run`` exits 0 (tier 2) or emits pack-like
    output with a non-zero exit (tier 1). Timeout scales by tree size when omitted.
    """
    root = project_dir.expanduser().resolve()
    effective_timeout = resolve_javascript_probe_timeout_sec(
        root, explicit=timeout_sec, for_npm=True
    )
    section: Dict[str, Any] = {
        "project_dir": str(root),
        "skipped": True,
        "reason": "disabled",
        "tier": 0,
        "command": None,
        "exit_code": None,
        "stdout_tail": "",
        "stderr_tail": "",
        "summary": "skipped",
        "timeout_sec": effective_timeout,
    }
    if not run_probe:
        return section
    if not root.is_dir():
        section["reason"] = "project_dir_missing"
        return section
    pkg = root / "package.json"
    if not pkg.is_file():
        section["reason"] = "no_package_json"
        return section

    npm_exe = which("npm")
    if not npm_exe:
        section["reason"] = "npm_not_found"
        return section

    cmd = [npm_exe, "pack", "--dry-run", "--ignore-scripts"]
    section["command"] = cmd
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        section["skipped"] = False
        section["reason"] = "timeout"
        section["summary"] = "npm_pack_timeout"
        return section
    except OSError as exc:
        section["skipped"] = False
        section["reason"] = f"os_error:{exc.__class__.__name__}"
        section["summary"] = "npm_pack_os_error"
        return section

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    section["stdout_tail"] = stdout[-800:]
    section["stderr_tail"] = stderr[-800:]
    section["exit_code"] = proc.returncode
    section["skipped"] = False

    combined = (stdout + stderr).lower()
    pack_hints = (".tgz", "npm notice", "package:", "filename:")
    has_hint = any(h in combined for h in pack_hints)
    if proc.returncode == 0:
        section["tier"] = 2
        section["reason"] = "exit_zero"
        section["summary"] = "npm_pack_dry_run_ok"
    elif has_hint:
        section["tier"] = 1
        section["reason"] = "pack_like_output"
        section["summary"] = "npm_pack_like_nonzero_exit"
    else:
        section["tier"] = 0
        section["reason"] = f"nonzero_exit:{proc.returncode}"
        section["summary"] = "npm_pack_failed"

    return section


def _run_node_check(js_path: Path, *, timeout_sec: float = 60.0) -> Dict[str, Any]:
    node_exe = which("node")
    if not node_exe:
        return {
            "path": str(js_path),
            "ok": False,
            "skipped": True,
            "reason": "node_not_found",
        }
    try:
        proc = subprocess.run(
            [node_exe, "--check", str(js_path)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "path": str(js_path),
            "ok": False,
            "skipped": False,
            "reason": "timeout",
        }
    except OSError as exc:
        return {
            "path": str(js_path),
            "ok": False,
            "skipped": False,
            "reason": f"os_error:{exc.__class__.__name__}",
        }
    stderr = (proc.stderr or "").strip()
    return {
        "path": str(js_path),
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stderr_tail": stderr[-500:] if stderr else "",
    }


def analyze_js_reconstructed_project(
    project_dir: Path,
    *,
    max_syntax_files: int = 12,
    run_syntax_checks: bool = True,
) -> Dict[str, Any]:
    """Best-effort smoke metrics for a recovered JavaScript/TypeScript project tree."""
    root = project_dir.expanduser().resolve()
    section: Dict[str, Any] = {
        "project_dir": str(root),
        "package_json": {"present": False, "parse_ok": False, "error": None},
        "file_counts_by_suffix": {},
        "syntax_checks": [],
        "syntax_summary": "skipped",
    }

    if not root.is_dir():
        section["error"] = "project_dir_missing"
        return section

    suffix_counts: MutableMapping[str, int] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if "node_modules" in {p.lower() for p in path.parts}:
            continue
        suf = path.suffix.lower() or "(no_extension)"
        suffix_counts[suf] = suffix_counts.get(suf, 0) + 1
    section["file_counts_by_suffix"] = dict(
        sorted(suffix_counts.items(), key=lambda x: (-x[1], x[0]))
    )

    pkg = root / "package.json"
    package_data: Any = None
    if pkg.is_file():
        section["package_json"]["present"] = True
        try:
            package_data = json.loads(pkg.read_text(encoding="utf-8"))
            section["package_json"]["parse_ok"] = True
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            section["package_json"]["error"] = f"{exc.__class__.__name__}: {exc}"

    if not run_syntax_checks:
        section["syntax_summary"] = "disabled"
        return section

    if not which("node"):
        section["syntax_summary"] = "node_unavailable"
        return section

    candidates = _collect_js_syntax_candidates(root, package_data, max_files=max_syntax_files)
    if not candidates:
        section["syntax_summary"] = "no_js_candidates"
        return section

    checks = [_run_node_check(p) for p in candidates]
    section["syntax_checks"] = checks
    ok_n = sum(1 for c in checks if c.get("ok"))
    skipped_n = sum(1 for c in checks if c.get("skipped"))
    if skipped_n == len(checks):
        section["syntax_summary"] = "node_unavailable"
    elif ok_n == len(checks):
        section["syntax_summary"] = "all_checked_ok"
    elif ok_n > 0:
        section["syntax_summary"] = "partial_failures"
    else:
        section["syntax_summary"] = "all_checked_failed"

    return section


def build_capability_report(
    *,
    language: str,
    primary_artifacts: Mapping[str, Path],
    adapter_metadata: Mapping[str, Any],
    run_js_syntax_check: bool = True,
    run_js_behavior_probe: bool = True,
    run_js_npm_lifecycle_probe: bool = False,
) -> Dict[str, Any]:
    """Assemble the `capability_report` object persisted into app analysis.json."""
    oracle = _extract_oracle_alignment(adapter_metadata)
    artifacts = _artifact_presence(primary_artifacts)

    js_smoke: Optional[Dict[str, Any]] = None
    js_behavior: Optional[Dict[str, Any]] = None
    js_npm: Optional[Dict[str, Any]] = None
    if language == "javascript":
        recon = primary_artifacts.get("reconstructed_project")
        if recon is not None:
            js_smoke = analyze_js_reconstructed_project(
                recon,
                run_syntax_checks=run_js_syntax_check,
            )
            js_behavior = run_javascript_behavior_probe(
                recon,
                run_probe=run_js_behavior_probe,
            )
            js_npm = run_javascript_npm_lifecycle_probe(
                recon,
                run_probe=run_js_npm_lifecycle_probe,
            )

    recall = _safe_float(oracle.get("project_file_recall")) if oracle.get("present") else None
    precision = _safe_float(oracle.get("project_file_precision")) if oracle.get("present") else None

    headline_parts: List[str] = []
    if js_smoke:
        headline_parts.append(f"js_smoke={js_smoke.get('syntax_summary', 'unknown')}")
    if js_behavior and int(js_behavior.get("tier", 0) or 0) > 0:
        headline_parts.append(f"js_behavior={js_behavior.get('summary', 'tier')}")
    if js_npm and int(js_npm.get("tier", 0) or 0) > 0:
        headline_parts.append(f"js_npm={js_npm.get('summary', 'tier')}")
    if recall is not None and precision is not None:
        headline_parts.append(f"oracle_files recall={recall:.4f} precision={precision:.4f}")
    elif oracle.get("present"):
        headline_parts.append("oracle_scorecard=present")
    headline = "; ".join(headline_parts) if headline_parts else "capability_baseline"
    if headline == "capability_baseline" and oracle.get("present"):
        headline = "oracle_scorecard=present"

    return {
        "schema_version": CAPABILITY_REPORT_SCHEMA_VERSION,
        "headline": headline,
        "dimensions": {
            "artifacts": artifacts,
            "oracle_alignment": oracle,
            "javascript_smoke": js_smoke,
            "javascript_behavior_probe": js_behavior,
            "javascript_npm_lifecycle_probe": js_npm,
        },
    }
