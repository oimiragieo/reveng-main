"""Tests for Volatility3-backed memory dump analysis."""

from datetime import UTC, datetime

import pytest

from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import (
    REVENGEnterpriseServer,
)
from reveng.malware.memory_forensics import MemoryForensics
from reveng.malware.volatility_analyzer import VolatilityAnalyzer


def test_memory_dump_uses_volatility_analyzer_instead_of_wmic(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    """Dump analysis should use Volatility-backed data instead of host WMIC calls."""
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"dump")

    analyzer = VolatilityAnalyzer()
    monkeypatch.setattr(
        analyzer,
        "analyze_dump",
        lambda path: {
            "analysis_timestamp": "2026-03-14T00:00:00Z",
            "processes": [
                {
                    "process_id": 4242,
                    "process_name": "malware.exe",
                    "parent_id": 4,
                    "command_line": "malware.exe --stealth",
                    "working_directory": "C:/malware",
                }
            ],
            "network_connections": [
                {
                    "protocol": "TCPv4",
                    "local_address": "10.0.0.5",
                    "local_port": 4444,
                    "foreign_address": "198.51.100.10",
                    "foreign_port": 80,
                    "state": "ESTABLISHED",
                    "process_id": 4242,
                    "process_name": "malware.exe",
                }
            ],
        },
    )
    monkeypatch.setattr(
        "reveng.malware.memory_forensics.VolatilityAnalyzer",
        lambda: analyzer,
    )
    monkeypatch.setattr(
        "reveng.malware.memory_forensics.subprocess.run",
        lambda *args, **kwargs: pytest.fail("subprocess.run should not be used for dump analysis"),
    )

    forensics = MemoryForensics()
    monkeypatch.setattr(forensics, "_save_analysis_results", lambda analysis, output_dir: None)

    analysis = forensics.analyze_memory(str(dump_path), str(tmp_path / "out"))

    assert analysis.total_processes == 1
    assert analysis.processes[0].process_name == "malware.exe"
    assert analysis.processes[0].command_line == "malware.exe --stealth"
    assert analysis.network_connections[0]["process_id"] == 4242


def test_volatility_analyzer_skip_env_returns_mock_results(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    """CI skip mode should return a minimal structured result."""
    dump_path = tmp_path / "sample.mem"
    dump_path.write_bytes(b"dump")
    monkeypatch.setenv("SKIP_VOLATILITY", "1")

    analysis = VolatilityAnalyzer().analyze_dump(str(dump_path))

    assert analysis["mode"] == "mock"
    assert analysis["analysis_timestamp"].endswith("+00:00")
    assert analysis["processes"]
    assert analysis["processes"][0]["process_name"]


@pytest.mark.asyncio
async def test_analyze_memory_dump_mcp_tool_supports_skip_volatility(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    """The MCP tool should succeed end-to-end when Volatility is skipped in CI."""
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"dump")
    monkeypatch.setenv("SKIP_VOLATILITY", "1")

    server = REVENGEnterpriseServer(enable_rate_limiting=False, enable_audit_log=False)

    response = await server.analyze_memory_dump(
        {"path": str(dump_path), "output_dir": str(tmp_path / "analysis")}
    )

    assert response["analysis"]["processes"]
    assert response["analysis"]["binary_path"] == str(dump_path)
    assert "Memory Forensics Analysis" in response["content"][0]["text"]


def test_volatility_analyzer_requires_existing_dump(tmp_path):
    """Analyzer should reject missing dump paths before attempting plugin execution."""
    missing_dump = tmp_path / "missing.dmp"

    with pytest.raises(FileNotFoundError):
        VolatilityAnalyzer().analyze_dump(str(missing_dump))


def test_volatility_analyzer_uses_timezone_aware_timestamp(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """Real analysis responses should emit timezone-aware UTC timestamps."""
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"dump")

    analyzer = VolatilityAnalyzer()

    class _FixedDateTime:
        @staticmethod
        def now(tz=None):
            assert tz is UTC
            return datetime(2026, 3, 14, 12, 0, 0, tzinfo=UTC)

    monkeypatch.setattr(
        "reveng.malware.volatility_analyzer.dt.datetime",
        _FixedDateTime,
    )
    monkeypatch.setattr(analyzer, "_ensure_plugins_loaded", lambda: None)
    monkeypatch.setattr(
        analyzer,
        "_run_plugin",
        lambda dump, plugin_class: [{"PID": 7, "PPID": 4, "ImageFileName": "sample.exe"}]
        if plugin_class is analyzer.WINDOWS_PLUGINS["pslist"]
        else [],
    )

    analysis = analyzer.analyze_dump(str(dump_path))

    assert analysis["mode"] == "volatility3"
    assert analysis["analysis_timestamp"] == "2026-03-14T12:00:00+00:00"
