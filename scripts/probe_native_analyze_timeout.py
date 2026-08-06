"""Bounded-timeout native analyze probe (R-HEX-1)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


PROBE_VERSION = "1.0"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def probe_one(
    binary_path: Path,
    analyze_cmd: Sequence[str],
    timeout_s: float,
    now_iso: str,
) -> Dict[str, Any]:
    """Run one analyze command under a hard timeout; never conflate outcomes."""
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
    }
    if not binary_path.is_file():
        result["reason"] = f"binary_absent:{binary_path}"
        return result

    result["binary_sha256"] = _sha256_file(binary_path)
    result["binary_size_bytes"] = binary_path.stat().st_size

    cmd = list(analyze_cmd) + [str(binary_path)]
    result["analyze_cmd"] = cmd
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        result["elapsed_s"] = time.perf_counter() - started
        result["returncode"] = proc.returncode
        result["measured"] = True
        if proc.returncode == 0:
            result["status"] = "completed"
        else:
            result["status"] = "completed"
            result["reason"] = f"nonzero_exit:{proc.returncode}"
        return result
    except subprocess.TimeoutExpired:
        result["elapsed_s"] = time.perf_counter() - started
        result["measured"] = True
        result["status"] = "timeout"
        result["reason"] = "timeout"
        return result
    except OSError as exc:
        result["elapsed_s"] = time.perf_counter() - started
        result["reason"] = f"os_error:{exc.__class__.__name__}"
        return result


def write_report(results: List[Dict[str, Any]], out_dir: Path, now_iso: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = now_iso.replace(":", "").replace("+", "p")
    payload = {"probe_version": PROBE_VERSION, "recorded_at_utc": now_iso, "results": results}
    stamped = out_dir / f"{stamp}.json"
    latest = out_dir / "latest.json"
    text = json.dumps(payload, indent=2) + "\n"
    stamped.write_text(text, encoding="utf-8")
    latest.write_text(text, encoding="utf-8")
    return latest


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    from datetime import datetime, timezone

    parser = argparse.ArgumentParser(description="Bounded-timeout native analyze probe")
    parser.add_argument("--binary", action="append", default=[], help="Binary path (repeatable)")
    parser.add_argument("--timeout-s", type=float, default=120.0)
    parser.add_argument("--out-dir", default="reports/native_analyze_probe")
    parser.add_argument(
        "--analyze-cmd",
        default="reveng analyze",
        help="Analyze command prefix as a single shell-like string (binary path appended)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.binary:
        parser.error("at least one --binary is required")

    import shlex

    analyze_cmd = shlex.split(args.analyze_cmd)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results = [probe_one(Path(b), analyze_cmd, args.timeout_s, now_iso) for b in args.binary]
    write_report(results, Path(args.out_dir), now_iso)
    if any(r.get("status") == "could_not_measure" for r in results):
        raise SystemExit(2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
