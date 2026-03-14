"""End-to-end CLI integration coverage for the native sample pipeline."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import requests


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = REPO_ROOT / "src" / "reveng" / "cli" / "reveng.py"
SAMPLE_BINARY = REPO_ROOT / "test_samples" / "sample.exe"
GHIDRA_HEALTH_URL = "http://127.0.0.1:13370/health"
OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
OLLAMA_MODEL = "qwen2.5-coder:32b-instruct"


def _build_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def _require_local_services() -> None:
    try:
        ghidra_response = requests.get(GHIDRA_HEALTH_URL, timeout=5)
        ghidra_response.raise_for_status()
        ghidra_health = ghidra_response.json()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Ghidra service unavailable: {exc}")

    if not ghidra_health.get("ghidra_available"):
        pytest.skip("Ghidra health endpoint is up but reports ghidra_available=false")

    try:
        ollama_response = requests.get(OLLAMA_TAGS_URL, timeout=5)
        ollama_response.raise_for_status()
        ollama_payload = ollama_response.json()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Ollama service unavailable: {exc}")

    available_models = {model.get("name") for model in ollama_payload.get("models", [])}
    if OLLAMA_MODEL not in available_models:
        pytest.skip(f"Required Ollama model not available: {OLLAMA_MODEL}")


def _run_cli(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=_build_env(),
        timeout=timeout,
    )


def test_analyze_sample_produces_yara_enriched_report(tmp_path: Path):
    if not SAMPLE_BINARY.exists():
        pytest.skip("Native sample binary not found")

    _require_local_services()

    output_dir = tmp_path / "analysis_sample"
    result = _run_cli(
        "--output-dir",
        str(output_dir),
        "analyze",
        str(SAMPLE_BINARY),
    )
    combined_output = f"{result.stdout}\n{result.stderr}"

    assert result.returncode == 0, combined_output
    assert "ModuleNotFoundError" not in combined_output

    report_path = output_dir / "reports" / "unified_analysis_report.json"
    assert report_path.exists(), "Unified analysis report was not generated"

    report = json.loads(report_path.read_text(encoding="utf-8"))

    for key in (
        "decompiled_functions",
        "recompilation_result",
        "yara_matches",
        "vulnerabilities",
    ):
        assert key in report, f"Missing report key: {key}"

    assert isinstance(report["decompiled_functions"], list)
    assert len(report["decompiled_functions"]) >= 1
    assert isinstance(report["recompilation_result"], dict)
    assert isinstance(report["yara_matches"], list)
    assert isinstance(report["vulnerabilities"], list)

    source_dir = output_dir / "source"
    assert source_dir.exists(), "Expected source directory was not created"
    assert list(source_dir.glob("*.c")), "Expected at least one generated C source file"
