"""Regression tests for the foundation critical bug fixes."""

from pathlib import Path

import ollama
import pytest
import yara

from reveng.integrations.ghidra.ghidra_engine import GhidraEngine
from reveng.malware.behavioral_monitor import BehavioralMonitor


class _DummyResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_ghidra_engine_decompile_calls_decompile_endpoint():
    engine = GhidraEngine(server_url="http://example.test", fail_fast=False)
    calls = []

    def fake_post(url, json, timeout):
        calls.append((url, json, timeout))
        return _DummyResponse(
            200,
            {
                "functions": [
                    {
                        "entry_point": "0x401000",
                        "name": "main",
                        "source": "int main(void) { return 0; }",
                    }
                ]
            },
        )

    engine.session.post = fake_post

    result = engine.decompile("test_samples/sample.exe")

    assert calls == [
        (
            "http://example.test/decompile",
            {"binary_path": "test_samples/sample.exe"},
            engine.timeout,
        )
    ]
    assert result["functions"][0]["source"] == "int main(void) { return 0; }"
    assert result["decompiled_code"]["0x401000"] == "int main(void) { return 0; }"


def test_behavioral_monitor_entropy_uses_log2_without_attribute_errors():
    entropy = BehavioralMonitor()._calculate_entropy(bytes(range(256)))

    assert 7.9 < entropy <= 8.0


@pytest.mark.parametrize("module", [yara, ollama])
def test_runtime_dependency_imports(module):
    assert module is not None


def test_requirements_include_yara_python_and_ollama():
    requirements = (Path(__file__).resolve().parents[2] / "requirements.txt").read_text(
        encoding="utf-8"
    )

    assert "yara-python" in requirements
    assert "ollama" in requirements


def test_init_script_installs_yara_python_and_ollama():
    init_script = (Path(__file__).resolve().parents[2] / ".factory" / "init.sh").read_text(
        encoding="utf-8"
    )

    assert "yara-python" in init_script
    assert "ollama" in init_script
