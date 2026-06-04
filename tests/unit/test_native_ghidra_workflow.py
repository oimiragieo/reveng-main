"""Unit tests for native Ghidra workflow helpers."""

from __future__ import annotations

from reveng.analysis.native.ghidra_workflow import _analyze_with_lock_retry, candidate_ghidra_urls


def test_candidate_ghidra_urls_prefers_current_server_port():
    assert candidate_ghidra_urls() == [
        "http://127.0.0.1:13370",
    ]


def test_analyze_with_lock_retry_retries_once_on_temp_project_lock():
    class _FakeEngine:
        def __init__(self) -> None:
            self.calls = 0

        def analyze_binary(self, binary_path: str):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError(
                    "Ghidra error: [WinError 32] The process cannot access the file because "
                    "it is being used by another process: "
                    "'C:\\\\Temp\\\\ghidra project\\\\temp_project.lock~'"
                )
            return {"binary_path": binary_path, "functions": []}

    engine = _FakeEngine()

    result = _analyze_with_lock_retry(ghidra_engine=engine, binary_path="C:\\dev\\droid.exe")

    assert engine.calls == 2
    assert result["binary_path"] == "C:\\dev\\droid.exe"
