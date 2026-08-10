"""Optional external CLI adapters (Exa-discovered tools). Never hard-required."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ExternalToolResult:
    tool: str
    available: bool
    ran: bool
    exit_code: Optional[int] = None
    output_dir: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def probe_external_tools() -> Dict[str, bool]:
    return {
        "npx": _which("npx") is not None,
        "node": _which("node") is not None,
        "webcrack": _which("webcrack") is not None,
        "unbun": _which("unbun") is not None,
        "bun_extractor_in_tree": True,
    }


def try_webcrack(bundle: Path, output_dir: Path, *, timeout_s: int = 120) -> ExternalToolResult:
    """Unpack/unminify via ``npx webcrack`` when Node is available.

    Prefer an empty ``output_dir`` — webcrack refuses if the directory exists.
    For large Bun SEAs allow a high ``timeout_s`` (tens of minutes).
    """
    out = ExternalToolResult(tool="webcrack", available=False, ran=False)
    if _which("npx") is None:
        out.notes.append("npx_absent")
        return out
    out.available = True
    if output_dir.exists():
        # webcrack errors with "output directory already exists"
        import shutil as _shutil

        _shutil.rmtree(output_dir, ignore_errors=True)
    # Do NOT mkdir — webcrack creates the output path itself
    cmd = [
        "npx",
        "--yes",
        "webcrack",
        str(bundle),
        "-o",
        str(output_dir),
        "-f",
        "--no-jsx",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        out.ran = True
        out.exit_code = proc.returncode
        out.output_dir = str(output_dir)
        if proc.returncode != 0:
            out.error = (proc.stderr or proc.stdout or "")[:800]
            out.notes.append("webcrack_nonzero")
        else:
            out.notes.append("webcrack_ok")
            # Count outputs
            try:
                files = list(output_dir.rglob("*"))
                out.notes.append(f"output_entries:{len(files)}")
            except OSError:
                pass
    except subprocess.TimeoutExpired as exc:
        out.ran = True
        out.exit_code = -1
        out.error = f"timeout:{timeout_s}s"
        out.notes.append("webcrack_timeout")
        out.notes.append(str(exc)[:200])
    except Exception as exc:  # pragma: no cover
        out.error = str(exc)
        out.notes.append("webcrack_failed")
    return out


def try_wakaru(bundle: Path, output_dir: Path, *, timeout_s: int = 120) -> ExternalToolResult:
    """Unpack via ``npx @wakaru/cli`` when available."""
    out = ExternalToolResult(tool="wakaru", available=False, ran=False)
    if _which("npx") is None:
        out.notes.append("npx_absent")
        return out
    out.available = True
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["npx", "--yes", "@wakaru/cli", str(bundle), "--unpack", "-o", str(output_dir)]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        out.ran = True
        out.exit_code = proc.returncode
        out.output_dir = str(output_dir)
        if proc.returncode != 0:
            out.error = (proc.stderr or proc.stdout or "")[:500]
            out.notes.append("wakaru_nonzero")
        else:
            out.notes.append("wakaru_ok")
    except Exception as exc:  # pragma: no cover
        out.error = str(exc)
        out.notes.append("wakaru_failed")
    return out


def try_bun_extract_in_tree(binary: Path, output_dir: Path) -> ExternalToolResult:
    """Use REVENG in-tree Bun extractor (inspired by unbun / bun-demincer research)."""
    out = ExternalToolResult(tool="bun_extractor", available=True, ran=False)
    try:
        from reveng.tools.anti_analysis.bun_extractor import (
            detect_bun_executable,
            extract_bun_javascript,
        )

        info = detect_bun_executable(str(binary))
        if not getattr(info, "is_bun_executable", False):
            out.notes.append("not_bun_executable")
            return out
        output_dir.mkdir(parents=True, exist_ok=True)
        result = extract_bun_javascript(str(binary), str(output_dir))
        out.ran = True
        out.exit_code = 0 if getattr(result, "success", False) else 1
        out.output_dir = str(output_dir)
        out.notes.append("bun_extractor_ok" if out.exit_code == 0 else "bun_extractor_fail")
        if out.exit_code != 0:
            out.error = str(getattr(result, "error", None) or getattr(result, "message", ""))[:500]
    except Exception as exc:
        out.error = str(exc)
        out.notes.append("bun_extractor_import_or_run_failed")
    return out


def write_tool_probe_json(path: Path) -> Dict[str, Any]:
    payload = {"schema_version": "1.0", "tools": probe_external_tools()}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload
