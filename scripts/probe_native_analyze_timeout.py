"""Bounded-timeout native analyze probe (R-HEX-1)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


PROBE_VERSION = "1.2"

# Job result ids must be safe single path segments under runs/<id>/.
SAFE_RESULT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

# Strip secret-bearing lines before truncating tails (case-insensitive).
_SECRET_LINE = re.compile(
    r"(?i)^(.*(api[_-]?key|token|authorization|password)\s*[:=].*)$",
    re.MULTILINE,
)

# Nested JSON field used for native_fallback_empty when newly created under job_output_dir.
# Path: report["native_analysis"]["fallback_empty"] (bool). Absent → native_fallback_empty=None.
_NATIVE_FALLBACK_KEYS: Tuple[str, ...] = ("native_analysis", "fallback_empty")

_TAIL_LIMIT = 2000


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _empty_semantic() -> Dict[str, Any]:
    return {
        "process_status": "could_not_measure",
        "analysis_report_present": None,
        "native_fallback_empty": None,
        "semantic_reason": None,
        "job_output_dir": None,
    }


def _decode_captured(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def sanitize_tail(text: Optional[str]) -> str:
    """Remove secret key=value lines, then keep the last 2000 characters."""
    if not text:
        return ""
    cleaned_lines: List[str] = []
    for line in text.splitlines(keepends=True):
        if _SECRET_LINE.match(line.rstrip("\n\r")):
            continue
        cleaned_lines.append(line)
    cleaned = "".join(cleaned_lines)
    if len(cleaned) > _TAIL_LIMIT:
        return cleaned[-_TAIL_LIMIT:]
    return cleaned


def _tool_absent(analyze_cmd: Sequence[str]) -> Optional[str]:
    tool = analyze_cmd[0] if analyze_cmd else ""
    if not tool or (shutil.which(tool) is None and not Path(tool).is_file()):
        return tool
    return None


def _inject_output_dir(analyze_cmd: Sequence[str], job_output_dir: Path) -> List[str]:
    """
    If argv looks like a reveng-style CLI (`… analyze …`), insert global
    `--output-dir <dir>` immediately before the `analyze` subcommand.
    Otherwise leave argv unchanged (caller still sets REVENG_PROBE_OUT).
    """
    cmd = list(analyze_cmd)
    try:
        idx = cmd.index("analyze")
    except ValueError:
        return cmd
    return cmd[:idx] + ["--output-dir", str(job_output_dir)] + cmd[idx:]


def _recursive_json_inventory(root: Path) -> Dict[str, float]:
    """Map relative posix paths of *.json files to mtime (recursive)."""
    found: Dict[str, float] = {}
    if not root.is_dir():
        return found
    for path in root.rglob("*.json"):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            found[rel] = path.stat().st_mtime
    return found


def _dig_bool(data: Any, keys: Sequence[str]) -> Optional[bool]:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    if isinstance(cur, bool):
        return cur
    return None


def _attribute_semantic_from_dir(
    job_output_dir: Path,
    before: Dict[str, float],
) -> Tuple[Optional[bool], Optional[bool], Optional[str]]:
    """
    Compare recursive JSON inventories; only files created after spawn count.
    Returns (analysis_report_present, native_fallback_empty, semantic_reason).
    """
    after = _recursive_json_inventory(job_output_dir)
    new_rels = [rel for rel in after if rel not in before]
    if not new_rels:
        return False, None, None

    analysis_report_present = True
    native_fallback_empty: Optional[bool] = None
    semantic_reason: Optional[str] = None
    for rel in sorted(new_rels):
        path = job_output_dir / rel
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            semantic_reason = f"json_unreadable:{rel}:{exc.__class__.__name__}"
            continue
        dug = _dig_bool(payload, _NATIVE_FALLBACK_KEYS)
        if dug is not None:
            native_fallback_empty = dug
            break
    return analysis_report_present, native_fallback_empty, semantic_reason


def _prepare_job_output_dir(out_dir: Path, result_id: str) -> Path:
    """Fresh empty runs/<result_id>/ directory immediately before spawn."""
    if not SAFE_RESULT_ID.fullmatch(result_id):
        raise ValueError(f"unsafe result id: {result_id!r}")
    job_output_dir = out_dir / "runs" / result_id
    if job_output_dir.exists():
        shutil.rmtree(job_output_dir)
    job_output_dir.mkdir(parents=True, exist_ok=False)
    return job_output_dir


def probe_one(
    binary_path: Path,
    analyze_cmd: Sequence[str],
    timeout_s: float,
    now_iso: str,
    *,
    out_dir: Optional[Path] = None,
    result_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Run one analyze command under a hard timeout; never conflate outcomes."""
    semantic = _empty_semantic()
    result: Dict[str, Any] = {
        "binary": str(binary_path),
        "binary_sha256": None,
        "binary_size_bytes": None,
        "analyze_cmd": list(analyze_cmd),
        "timeout_budget_s": float(timeout_s),
        "elapsed_s": 0.0,
        "status": "could_not_measure",
        "returncode": None,
        "reason": None,
        "measured": False,
        "probe_version": PROBE_VERSION,
        "recorded_at_utc": now_iso,
        "stderr_tail": None,
        "stdout_tail": None,
        "semantic": semantic,
    }
    if result_id is not None:
        result["id"] = result_id

    if not binary_path.is_file():
        result["reason"] = f"input_absent:{binary_path}"
        semantic["semantic_reason"] = result["reason"]
        return result

    absent = _tool_absent(analyze_cmd)
    if absent is not None:
        result["reason"] = f"tool_absent:{absent}"
        semantic["semantic_reason"] = result["reason"]
        return result

    result["binary_sha256"] = _sha256_file(binary_path)
    result["binary_size_bytes"] = binary_path.stat().st_size

    job_output_dir: Optional[Path] = None
    before: Dict[str, float] = {}
    if out_dir is not None and result_id is not None:
        job_output_dir = _prepare_job_output_dir(out_dir, result_id)
        semantic["job_output_dir"] = str(job_output_dir)
        before = _recursive_json_inventory(job_output_dir)

    cmd = list(analyze_cmd)
    if job_output_dir is not None:
        cmd = _inject_output_dir(cmd, job_output_dir)
    cmd = cmd + [str(binary_path)]
    result["analyze_cmd"] = cmd

    env = os.environ.copy()
    if job_output_dir is not None:
        env["REVENG_PROBE_OUT"] = str(job_output_dir)

    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            env=env,
        )
        result["elapsed_s"] = time.perf_counter() - started
        result["returncode"] = proc.returncode
        result["stderr_tail"] = sanitize_tail(proc.stderr)
        result["stdout_tail"] = sanitize_tail(proc.stdout)
        if proc.returncode == 0:
            result["measured"] = True
            result["status"] = "completed"
            semantic["process_status"] = "completed"
        else:
            result["measured"] = True
            result["status"] = "could_not_measure"
            result["reason"] = f"nonzero_exit:{proc.returncode}"
            semantic["process_status"] = "could_not_measure"
            semantic["semantic_reason"] = result["reason"]
    except subprocess.TimeoutExpired as exc:
        result["elapsed_s"] = time.perf_counter() - started
        result["measured"] = True
        result["status"] = "timeout"
        result["reason"] = "timeout"
        semantic["process_status"] = "timeout"
        semantic["semantic_reason"] = "timeout"
        result["stderr_tail"] = sanitize_tail(_decode_captured(exc.stderr))
        result["stdout_tail"] = sanitize_tail(_decode_captured(exc.stdout))
    except OSError as exc:
        result["elapsed_s"] = time.perf_counter() - started
        result["reason"] = f"os_error:{exc.__class__.__name__}"
        semantic["semantic_reason"] = result["reason"]
        # Child never produced streams; tails stay None.
        if job_output_dir is not None:
            present, fallback, why = _attribute_semantic_from_dir(job_output_dir, before)
            semantic["analysis_report_present"] = present
            semantic["native_fallback_empty"] = fallback
            if why and not semantic["semantic_reason"]:
                semantic["semantic_reason"] = why
        return result

    if job_output_dir is not None:
        present, fallback, why = _attribute_semantic_from_dir(job_output_dir, before)
        semantic["analysis_report_present"] = present
        semantic["native_fallback_empty"] = fallback
        if why and semantic.get("semantic_reason") is None:
            semantic["semantic_reason"] = why

    return result


def write_report(results: List[Dict[str, Any]], out_dir: Path, now_iso: str) -> Path:
    """
    Write latest.json + one stamped sibling via temps/fsync, then delete obsolete
    20*.json stamps, then atomic-replace both targets (identical bytes).
    Preserves README, wave_a_job.json, and runs/.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = now_iso.replace(":", "").replace("+", "p")
    payload = {"probe_version": PROBE_VERSION, "recorded_at_utc": now_iso, "results": results}
    stamped = out_dir / f"{stamp}.json"
    latest = out_dir / "latest.json"
    text = json.dumps(payload, indent=2) + "\n"
    data = text.encode("utf-8")

    fd_latest, tmp_latest_name = tempfile.mkstemp(
        prefix=".latest.", suffix=".tmp", dir=str(out_dir)
    )
    fd_stamp, tmp_stamp_name = tempfile.mkstemp(prefix=".stamp.", suffix=".tmp", dir=str(out_dir))
    tmp_latest = Path(tmp_latest_name)
    tmp_stamp = Path(tmp_stamp_name)
    try:
        with os.fdopen(fd_latest, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        with os.fdopen(fd_stamp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

        # Both temps exist successfully — now drop obsolete stamps.
        for old in out_dir.glob("20*.json"):
            try:
                old.unlink()
            except OSError:
                pass

        os.replace(str(tmp_stamp), str(stamped))
        os.replace(str(tmp_latest), str(latest))
    except Exception:
        for path in (tmp_latest, tmp_stamp):
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
        raise

    return latest


def load_job(job_path: Path) -> List[Dict[str, Any]]:
    """Validate wave_a_job.json schema; duplicate/unsafe ids → SystemExit(2)."""
    try:
        raw = json.loads(job_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(2) from exc

    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise SystemExit(2)
    results = raw.get("results")
    if not isinstance(results, list) or not results:
        raise SystemExit(2)

    seen = set()
    entries: List[Dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            raise SystemExit(2)
        rid = item.get("id")
        binary = item.get("binary")
        analyze_cmd = item.get("analyze_cmd")
        timeout_s = item.get("timeout_s")
        if not isinstance(rid, str) or not SAFE_RESULT_ID.fullmatch(rid):
            raise SystemExit(2)
        if rid in seen:
            raise SystemExit(2)
        seen.add(rid)
        if not isinstance(binary, str) or not binary:
            raise SystemExit(2)
        if not isinstance(analyze_cmd, str) or not analyze_cmd.strip():
            raise SystemExit(2)
        if not isinstance(timeout_s, (int, float)) or not (timeout_s > 0):
            raise SystemExit(2)
        entries.append(
            {
                "id": rid,
                "binary": binary,
                "analyze_cmd": analyze_cmd,
                "timeout_s": float(timeout_s),
            }
        )
    return entries


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    import shlex
    from datetime import datetime, timezone

    parser = argparse.ArgumentParser(description="Bounded-timeout native analyze probe")
    parser.add_argument("--binary", action="append", default=[], help="Binary path (repeatable)")
    parser.add_argument(
        "--job",
        default=None,
        help="Multi-result job JSON (mutually exclusive with --binary)",
    )
    parser.add_argument("--timeout-s", type=float, default=120.0)
    parser.add_argument("--out-dir", default="reports/native_analyze_probe")
    parser.add_argument(
        "--analyze-cmd",
        default="reveng analyze",
        help="Analyze command prefix as a single shell-like string (binary path appended)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.job and args.binary:
        parser.error("--job and --binary are mutually exclusive")
        return 2
    if not args.job and not args.binary:
        parser.error("either --job or at least one --binary is required")
        return 2

    out_dir = Path(args.out_dir)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results: List[Dict[str, Any]] = []

    if args.job:
        entries = load_job(Path(args.job))
        for entry in entries:
            analyze_cmd = shlex.split(entry["analyze_cmd"])
            results.append(
                probe_one(
                    Path(entry["binary"]),
                    analyze_cmd,
                    entry["timeout_s"],
                    now_iso,
                    out_dir=out_dir,
                    result_id=entry["id"],
                )
            )
    else:
        analyze_cmd = shlex.split(args.analyze_cmd)
        for idx, binary in enumerate(args.binary):
            results.append(
                probe_one(
                    Path(binary),
                    analyze_cmd,
                    args.timeout_s,
                    now_iso,
                    out_dir=out_dir,
                    result_id=f"legacy_{idx}",
                )
            )

    write_report(results, out_dir, now_iso)
    if any(r.get("status") == "could_not_measure" for r in results):
        raise SystemExit(2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
