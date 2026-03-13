from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "external" / "ghidra-server" / "ghidra_http_server.py"


def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, SERVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop(name, None)
    spec.loader.exec_module(module)
    return module


def test_health_endpoint_reports_ghidra_availability(monkeypatch):
    server = _load_module("test_ghidra_server_health")
    monkeypatch.setattr(
        server,
        "get_ghidra_status",
        lambda ghidra_path=None: {
            "status": "healthy",
            "ghidra_available": True,
            "ghidra_path": "C:/ghidra",
            "headless_path": "C:/ghidra/support/analyzeHeadless.bat",
        },
    )

    response = server.app.test_client().get("/health")

    assert response.status_code == 200
    assert response.get_json()["ghidra_available"] is True
    assert response.get_json()["status"] == "healthy"


def test_decompile_endpoint_returns_503_without_mock_data_when_unavailable(
    monkeypatch, tmp_path: Path
):
    server = _load_module("test_ghidra_server_unavailable")
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ")

    monkeypatch.setattr(
        server,
        "get_ghidra_status",
        lambda ghidra_path=None: {
            "status": "unavailable",
            "ghidra_available": False,
            "ghidra_path": "C:/missing-ghidra",
            "headless_path": "C:/missing-ghidra/support/analyzeHeadless.bat",
        },
    )

    response = server.app.test_client().post(
        "/decompile", json={"binary_path": str(binary_path)}
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Ghidra unavailable"}


def test_build_headless_command_preserves_windows_paths_with_spaces(tmp_path: Path):
    server = _load_module("test_ghidra_server_command")
    ghidra_path = tmp_path / "ghidra dist" / server.DEFAULT_GHIDRA_DIST_NAME
    binary_path = tmp_path / "binary inputs" / "sample program.exe"
    project_dir = tmp_path / "temp project dir"
    scripts_dir = tmp_path / "script path"
    output_json = tmp_path / "json output" / "analysis.json"
    scripts_dir.mkdir(parents=True)
    (scripts_dir / "ExportAnalysisJSON.java").write_text("// test\n", encoding="utf-8")

    command = server.build_headless_command(
        ghidra_path=ghidra_path,
        binary_path=binary_path,
        project_dir=project_dir,
        project_name="temp_project",
        scripts_dir=scripts_dir,
        output_json=output_json,
    )

    assert command[0] == str(server.get_headless_script_path(ghidra_path))
    assert command[1] == str(project_dir)
    assert command[2] == "temp_project"
    assert command[command.index("-import") + 1] == str(binary_path)
    assert command[command.index("-scriptPath") + 1] == str(scripts_dir)
    assert command[command.index("-postScript") + 1] == server.get_export_script_path(scripts_dir).name
    assert command[command.index("-postScript") + 2] == str(output_json)
    assert command[-1] == "-deleteProject"


def test_run_ghidra_analysis_uses_120_second_timeout_and_returns_source(
    monkeypatch, tmp_path: Path
):
    server = _load_module("test_ghidra_server_run")
    ghidra_path = tmp_path / server.DEFAULT_GHIDRA_DIST_NAME
    headless_path = ghidra_path / "support" / server.get_headless_script_name()
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ")
    headless_path.parent.mkdir(parents=True)
    headless_path.write_text("echo ready\n", encoding="utf-8")

    call_details: dict[str, object] = {}

    class _TempDir:
        def __enter__(self):
            self.path = tmp_path / "workspace with spaces"
            self.path.mkdir(parents=True, exist_ok=True)
            return str(self.path)

        def __exit__(self, exc_type, exc, tb):
            return False

    def _fake_run(cmd, capture_output, text, timeout, cwd):
        call_details["cmd"] = cmd
        call_details["timeout"] = timeout
        call_details["cwd"] = cwd
        output_json = Path(cmd[cmd.index("-postScript") + 2])
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(
            json.dumps(
                {
                    "status": "success",
                    "functions": [
                        {"name": "thunk", "source": "", "decompiled": None},
                        {
                            "name": "main",
                            "source": "",
                            "decompiled": "int main(void) {\n    puts(\"hello\");\n    return 0;\n}",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        class _Result:
            returncode = 0
            stdout = "ok"
            stderr = ""

        return _Result()

    monkeypatch.setattr(server.tempfile, "TemporaryDirectory", lambda: _TempDir())
    monkeypatch.setattr(server.subprocess, "run", _fake_run)

    result = server.run_ghidra_analysis(binary_path=binary_path, ghidra_path=ghidra_path)

    assert call_details["timeout"] == 120
    assert call_details["cwd"] == str(ghidra_path)
    assert result["functions"][0]["name"] == "main"
    assert result["functions"][0]["source"].startswith("int main(void)")
