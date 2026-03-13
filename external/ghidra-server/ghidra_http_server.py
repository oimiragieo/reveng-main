#!/usr/bin/env python3
"""REST API for running Ghidra headless analysis."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
except ImportError as exc:
    print(f"ERROR: Missing dependencies: {exc}")
    print("Install with: pip install flask flask-cors")
    sys.exit(1)


app = Flask(__name__)
CORS(app)

DEFAULT_GHIDRA_DIST_NAME = "ghidra_12.0.4_PUBLIC"
GHIDRA_HEADLESS_TIMEOUT = 120


class GhidraUnavailableError(RuntimeError):
    """Raised when Ghidra headless analysis is unavailable."""


def get_headless_script_name() -> str:
    """Return the platform-specific headless launcher name."""
    return "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"


def get_headless_script_path(ghidra_path: Path) -> Path:
    """Return the expected Ghidra headless launcher path."""
    return ghidra_path / "support" / get_headless_script_name()


def resolve_ghidra_path(external_root: Path | None = None) -> Path:
    """Prefer the binary distribution, then fall back to the source checkout."""
    external_root = external_root or Path(__file__).resolve().parents[1]
    preferred_path = external_root / "ghidra-dist" / DEFAULT_GHIDRA_DIST_NAME
    fallback_path = external_root / "ghidra"

    for candidate in (preferred_path, fallback_path):
        if get_headless_script_path(candidate).exists():
            return candidate

    if preferred_path.exists():
        return preferred_path
    return fallback_path


GHIDRA_PATH = resolve_ghidra_path()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _env_flag(name: str) -> bool:
    """Return whether an environment variable is set to a truthy value."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def get_ghidra_status(ghidra_path: Path | None = None) -> dict[str, object]:
    """Return current Ghidra availability details for the health endpoint."""
    resolved_path = ghidra_path or GHIDRA_PATH
    headless_path = get_headless_script_path(resolved_path)
    mock_requested = _env_flag("GHIDRA_MOCK")
    ghidra_available = headless_path.exists() and not mock_requested

    return {
        "service": "ghidra-analysis-server",
        "status": "healthy" if ghidra_available else "unavailable",
        "ghidra_available": ghidra_available,
        "ghidra_path": str(resolved_path),
        "headless_path": str(headless_path),
        "mock_requested": mock_requested,
    }


def require_ghidra_available(ghidra_path: Path | None = None) -> dict[str, object]:
    """Ensure Ghidra headless execution is available before starting analysis."""
    status = get_ghidra_status(ghidra_path)
    if not status["ghidra_available"]:
        raise GhidraUnavailableError("Ghidra unavailable")
    return status


def normalize_analysis_data(analysis_data: dict[str, object]) -> dict[str, object]:
    """Normalize exported analysis JSON for API consumers."""
    normalized = dict(analysis_data)
    functions = []

    for function in normalized.get("functions", []):
        if not isinstance(function, dict):
            continue

        normalized_function = dict(function)
        source = normalized_function.get("source") or normalized_function.get("decompiled") or ""
        normalized_function["source"] = source
        if source and not normalized_function.get("decompiled"):
            normalized_function["decompiled"] = source
        functions.append(normalized_function)

    functions.sort(key=lambda item: len(item.get("source", "")), reverse=True)
    normalized["functions"] = functions
    normalized.pop("mock", None)
    return normalized


def build_headless_command(
    *,
    ghidra_path: Path,
    binary_path: Path,
    project_dir: Path,
    project_name: str,
    scripts_dir: Path,
    output_json: Path,
) -> list[str]:
    """Build a Windows-safe analyzeHeadless invocation."""
    export_script = get_export_script_path(scripts_dir)
    return [
        str(get_headless_script_path(ghidra_path)),
        str(project_dir),
        project_name,
        "-import",
        str(binary_path),
        "-scriptPath",
        str(scripts_dir),
        "-postScript",
        export_script.name,
        str(output_json),
        "-deleteProject",
    ]


def get_export_script_path(scripts_dir: Path) -> Path:
    """Resolve the best available export script for headless analysis."""
    for script_name in ("ExportAnalysisJSON.java", "ExportAnalysisJSON.py"):
        candidate = scripts_dir / script_name
        if candidate.exists():
            return candidate
    raise RuntimeError(f"Export script not found in {scripts_dir}")


def load_analysis_json(output_json: Path) -> dict[str, object]:
    """Load and normalize the Ghidra analysis JSON output."""
    with output_json.open("r", encoding="utf-8") as handle:
        return normalize_analysis_data(json.load(handle))


def run_ghidra_analysis(
    binary_path: Path | str,
    ghidra_path: Path | None = None,
    timeout: int = GHIDRA_HEADLESS_TIMEOUT,
) -> dict[str, object]:
    """Run Ghidra headless analysis and return normalized JSON results."""
    resolved_ghidra_path = ghidra_path or GHIDRA_PATH
    require_ghidra_available(resolved_ghidra_path)

    resolved_binary_path = Path(binary_path).expanduser().resolve()
    scripts_dir = (Path(__file__).parent / "scripts").resolve()
    get_export_script_path(scripts_dir)

    with tempfile.TemporaryDirectory() as temp_dir:
        workspace_dir = Path(temp_dir)
        project_dir = workspace_dir / "ghidra project"
        project_dir.mkdir(parents=True, exist_ok=True)
        output_json = workspace_dir / "analysis.json"

        command = build_headless_command(
            ghidra_path=resolved_ghidra_path,
            binary_path=resolved_binary_path,
            project_dir=project_dir,
            project_name="temp_project",
            scripts_dir=scripts_dir,
            output_json=output_json,
        )

        logger.info("Running Ghidra command: %s", command)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(resolved_ghidra_path),
        )

        logger.info("Ghidra exit code: %s", result.returncode)
        if result.returncode != 0 and not output_json.exists():
            logger.error("Ghidra STDERR: %s", result.stderr[:2000])
            logger.error("Ghidra STDOUT: %s", result.stdout[:2000])
            raise RuntimeError("Ghidra analysis failed")

        if not output_json.exists():
            raise RuntimeError("Ghidra analysis did not produce JSON output")

        return load_analysis_json(output_json)


def _process_analysis_request() -> tuple[object, int]:
    """Handle both /analyze and /decompile requests."""
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "No JSON data provided"}), 400

    binary_path = payload.get("binary_path")
    if not binary_path:
        return jsonify({"error": "binary_path not specified"}), 400

    binary_file = Path(binary_path)
    if not binary_file.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    logger.info("Analyzing binary: %s", binary_file)

    try:
        analysis_data = run_ghidra_analysis(binary_file)
        return jsonify(analysis_data), 200
    except GhidraUnavailableError:
        logger.warning("Ghidra unavailable for analysis request")
        return jsonify({"error": "Ghidra unavailable"}), 503
    except subprocess.TimeoutExpired:
        logger.error("Ghidra analysis timeout after %ss", GHIDRA_HEADLESS_TIMEOUT)
        return jsonify({"error": f"Analysis timeout ({GHIDRA_HEADLESS_TIMEOUT}s)"}), 504
    except Exception as exc:
        logger.error("Ghidra execution error: %s", exc, exc_info=True)
        return jsonify({"error": f"Ghidra error: {exc}"}), 500


@app.route("/", methods=["GET"])
def index():
    """Root endpoint - server info."""
    return jsonify(
        {
            "service": "ghidra-analysis-server",
            "version": "1.0.0",
            "status": "running",
            "endpoints": {
                "/health": "GET - Health check",
                "/analyze": "POST - Analyze binary (legacy alias)",
                "/decompile": "POST - Decompile binary",
            },
        }
    )


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    logger.info("Health check requested")
    response = get_ghidra_status()
    logger.info("Health check: %s", response)
    return jsonify(response), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    """Legacy analysis endpoint kept for compatibility."""
    logger.info("Analysis requested")
    return _process_analysis_request()


@app.route("/decompile", methods=["POST"])
def decompile():
    """Decompile a binary using Ghidra headless analysis."""
    logger.info("Decompile requested")
    return _process_analysis_request()


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500


def main():
    """Main entry point."""
    port = int(os.environ.get("PORT", 13370))
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    status = get_ghidra_status()

    logger.info("=" * 60)
    logger.info("Ghidra HTTP Analysis Server")
    logger.info("=" * 60)
    logger.info("Server: http://%s:%s", host, port)
    logger.info("Ghidra: %s", GHIDRA_PATH)
    logger.info("Ghidra available: %s", status["ghidra_available"])
    logger.info("=" * 60)

    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    except Exception as exc:
        logger.error("Failed to start server: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
