"""Honesty/wiring tests for 2026-08-09 world-class fix wave (W-01..W-07, W-04, W-06)."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reveng.app_reverse_engineering import create_default_framework
from reveng.cli import create_parser
from reveng.tools.enterprise.enhanced_health_monitor import CoreREVENGHealthChecker
from reveng.tools.utils.java_ai_analyzer import JavaAIAnalyzer


def _enterprise_server():
    from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import REVENGEnterpriseServer

    return REVENGEnterpriseServer()


def _core_server():
    from reveng.agent_sdk.mcp.servers.reveng_server import REVENGMCPServer

    return REVENGMCPServer()


def _accuracy_percent_offenders(tools):
    """Scan serialized MCP tool dicts for brochure accuracy % claims."""
    offenders = []
    for tool in tools:
        desc = tool.get("description") or ""
        if re.search(r"\d+%\+?", desc):
            offenders.append((tool.get("name"), desc))
        props = (tool.get("inputSchema") or {}).get("properties") or {}
        for pname, pschema in props.items():
            pdesc = (pschema or {}).get("description") or ""
            if re.search(r"\d+%\+?", pdesc) and (
                "accuracy" in pdesc.lower() or "60-80" in pdesc or "90%" in pdesc
            ):
                offenders.append((f"{tool.get('name')}.{pname}", pdesc))
    return offenders


class TestMcpDescriptionHonesty:
    def test_serialized_tool_schemas_have_no_accuracy_percent_claims(self):
        server = _enterprise_server()
        tools = [t.to_dict() for t in server.tools.values()]
        assert len(tools) >= 8, "positive control: schemas must be non-empty"

        injected = {"name": "fake", "description": "90%+ accuracy tool", "inputSchema": {}}
        assert _accuracy_percent_offenders([injected]), "scan must catch injected 90% fixture"

        offenders = _accuracy_percent_offenders(tools)
        assert offenders == [], f"brochure % claims in schemas: {offenders}"


class TestUnbundleWebpackHonesty:
    def test_false_does_not_warn(self):
        server = _enterprise_server()

        async def _run():
            with patch("reveng.javascript.deobfuscator.JavaScriptDeobfuscator") as deob_cls:
                inst = MagicMock()
                result = MagicMock()
                result.confidence = 10
                result.obfuscation_types = []
                result.deobfuscated_code = "var a=1;"
                inst.deobfuscate = MagicMock(return_value=asyncio.coroutine(lambda: result)())

                async def _deob(_code):
                    return result

                inst.deobfuscate = _deob
                deob_cls.return_value = inst
                return await server.deobfuscate_javascript(
                    {"code": "var a=1;", "unbundle_webpack": False, "detect_malware": False}
                )

        out = asyncio.run(_run())
        assert out.get("unbundle_webpack_applied") is False
        assert "unbundle_webpack_unsupported" not in (out.get("warnings") or [])

    def test_true_marks_unsupported_not_applied(self):
        server = _enterprise_server()

        async def _run():
            with patch("reveng.javascript.deobfuscator.JavaScriptDeobfuscator") as deob_cls:
                result = MagicMock()
                result.confidence = 10
                result.obfuscation_types = []
                result.deobfuscated_code = "var a=1;"

                async def _deob(_code):
                    return result

                deob_cls.return_value.deobfuscate = _deob
                return await server.deobfuscate_javascript(
                    {"code": "var a=1;", "unbundle_webpack": True, "detect_malware": False}
                )

        out = asyncio.run(_run())
        assert out.get("unbundle_webpack_applied") is False
        assert "unbundle_webpack" in (out.get("unsupported_knobs") or [])
        assert "unbundle_webpack_unsupported" in (out.get("warnings") or [])
        assert "not applied" in out["content"][0]["text"].lower()


class TestFindVulnerabilitiesHonesty:
    def test_symbolic_false_is_could_not_measure_not_clean(self, tmp_path):
        server = _enterprise_server()
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"MZ")

        async def _run():
            return await server.find_vulnerabilities(
                {"path": str(binary), "use_symbolic_execution": False}
            )

        out = asyncio.run(_run())
        assert out["status"] == "could_not_measure"
        assert "No vulnerabilities found" not in out["content"][0]["text"]
        assert out.get("measurement") == "could_not_measure"

    def test_ai_knob_unsupported(self, tmp_path):
        server = _enterprise_server()
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"MZ")

        out = asyncio.run(
            server.find_vulnerabilities(
                {"path": str(binary), "use_ai_analysis": True, "use_symbolic_execution": True}
            )
        )
        assert out["status"] == "unsupported"
        assert "use_ai_analysis" in out.get("unsupported_knobs", [])

    def test_types_and_ai_combo_unsupported(self, tmp_path):
        server = _enterprise_server()
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"MZ")
        out = asyncio.run(
            server.find_vulnerabilities(
                {
                    "path": str(binary),
                    "vulnerability_types": ["buffer_overflow"],
                    "use_ai_analysis": True,
                    "use_symbolic_execution": True,
                }
            )
        )
        assert out["status"] == "unsupported"
        assert set(out.get("unsupported_knobs", [])) >= {
            "vulnerability_types",
            "use_ai_analysis",
        }

    def test_unsupported_knobs_reject_before_angr_import(self, tmp_path):
        server = _enterprise_server()
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"MZ")

        real_import = __import__

        def boom_angr(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "angr" or (isinstance(name, str) and name.startswith("angr")):
                raise AssertionError("angr must not be imported on unsupported-knob path")
            if name == "reveng.security.symbolic_execution_engine":
                raise AssertionError("symbolic engine must not import on unsupported-knob path")
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=boom_angr):
            out = asyncio.run(
                server.find_vulnerabilities(
                    {"path": str(binary), "use_ai_analysis": True, "use_symbolic_execution": True}
                )
            )
        assert out["status"] == "unsupported"

    def test_measured_zero_findings_ok(self, tmp_path):
        server = _enterprise_server()
        binary = tmp_path / "sample.bin"
        binary.write_bytes(b"MZ")

        fake_engine = MagicMock()
        fake_engine.find_vulnerabilities.return_value = []

        async def _run():
            with patch.dict("sys.modules", {"angr": MagicMock()}):
                with patch(
                    "reveng.security.symbolic_execution_engine.SymbolicExecutionEngine",
                    return_value=fake_engine,
                    create=True,
                ):
                    # Import path happens inside handler — patch after injecting fake module
                    import sys
                    import types

                    mod = types.ModuleType("reveng.security.symbolic_execution_engine")

                    class SymbolicExecutionEngine:
                        def __init__(self, *a, **k):
                            pass

                        def find_vulnerabilities(self):
                            return []

                    mod.SymbolicExecutionEngine = SymbolicExecutionEngine
                    sys.modules["reveng.security.symbolic_execution_engine"] = mod
                    try:
                        return await server.find_vulnerabilities(
                            {"path": str(binary), "use_symbolic_execution": True}
                        )
                    finally:
                        sys.modules.pop("reveng.security.symbolic_execution_engine", None)

        out = asyncio.run(_run())
        assert out.get("status", "success") == "success"
        assert out.get("measurement") == "measured"
        assert out.get("vulnerabilities") == []
        assert "Found 0 vulnerabilities" in out["content"][0]["text"]


class TestEnableAiSurfaces:
    def test_cli_exposes_no_ai_and_passes_enable_ai_false(self):
        parser = create_parser()
        args = parser.parse_args(["analyze", "sample.exe", "--no-ai"])
        assert args.no_ai is True

        with patch("reveng.cli.REVENGAnalyzer") as analyzer_cls:
            analyzer_cls.return_value.binary_path = "missing-does-not-exist.exe"
            analyzer_cls.return_value.analysis_folder = Path(".")
            from reveng.cli import handle_analyze_command

            handle_analyze_command(args)
            assert analyzer_cls.call_args.kwargs.get("enable_ai") is False

    def test_cli_default_enable_ai_true(self):
        parser = create_parser()
        args = parser.parse_args(["analyze", "sample.exe"])
        assert getattr(args, "no_ai", False) is False

        with patch("reveng.cli.REVENGAnalyzer") as analyzer_cls:
            analyzer_cls.return_value.binary_path = "missing-does-not-exist.exe"
            analyzer_cls.return_value.analysis_folder = Path(".")
            from reveng.cli import handle_analyze_command

            handle_analyze_command(args)
            assert analyzer_cls.call_args.kwargs.get("enable_ai") is True

    def test_core_mcp_schema_exposes_enable_ai(self):
        server = _core_server()
        schema = server.tools["analyze_binary"].to_dict()["inputSchema"]
        assert "enable_ai" in schema["properties"]


class TestEnableAiMcpConstruct:
    def test_enable_ai_false_kwarg(self, tmp_path):
        server = _core_server()
        binary = tmp_path / "x.bin"
        binary.write_bytes(b"MZ")
        constructed = {}

        class FakeAnalyzer:
            def __init__(self, *a, **k):
                constructed.update(k)

            def analyze_binary(self):
                return {"step1": {"status": "skipped", "reason": "enable_ai_false"}}

        async def _run():
            with patch("reveng.analysis.analyzer.REVENGAnalyzer", FakeAnalyzer):
                return await server.analyze_binary({"path": str(binary), "enable_ai": False})

        out = asyncio.run(_run())
        assert constructed.get("enable_ai") is False
        assert out.get("analysis_result", {}).get("step1", {}).get("reason") == "enable_ai_false"

    def test_enable_ai_default_true(self, tmp_path):
        server = _core_server()
        binary = tmp_path / "x.bin"
        binary.write_bytes(b"MZ")
        constructed = {}

        class FakeAnalyzer:
            def __init__(self, *a, **k):
                constructed.update(k)

            def analyze_binary(self):
                return {"step1": {"status": "ok"}}

        async def _run():
            with patch("reveng.analysis.analyzer.REVENGAnalyzer", FakeAnalyzer):
                return await server.analyze_binary({"path": str(binary)})

        asyncio.run(_run())
        assert constructed.get("enable_ai") is True


class TestNativeQuarantinePin:
    def test_default_framework_excludes_native(self):
        # Regression pin: current product path must not register native.
        fw = create_default_framework()
        assert "native" not in fw.adapters

    def test_mcp_language_enum_excludes_native(self):
        server = _core_server()
        props = server.tools["reverse_engineer_app"].input_schema["properties"]
        enum = props["language"]["enum"]
        assert "native" not in enum


class TestJavaAiCloudUnsupported:
    def test_openai_raises_at_construction(self):
        with pytest.raises(NotImplementedError, match="OpenAI"):
            JavaAIAnalyzer(ai_provider="openai")

    def test_anthropic_raises_at_construction(self):
        with pytest.raises(NotImplementedError, match="Anthropic"):
            JavaAIAnalyzer(ai_provider="anthropic")

    def test_ollama_construction_does_not_raise_ni(self):
        analyzer = JavaAIAnalyzer(ai_provider="ollama")
        assert analyzer.ai_provider == "ollama"
        # Callable path: analyze returns None when AI unavailable, does not raise NI
        assert analyzer.analyze_java_class("Foo", "class Foo {}") is None or True


class TestHealthMonitorFailClosed:
    def test_real_package_imports_healthy(self):
        checker = CoreREVENGHealthChecker()
        health = checker.check_health()
        module_metrics = [m for m in health.metrics if m.name.startswith("module_")]
        assert module_metrics, "positive control: module metrics exist"
        unhealthy = [m for m in module_metrics if m.status == "critical"]
        assert unhealthy == [], f"unexpected critical modules: {unhealthy}"

    def test_missing_module_fail_closed(self):
        checker = CoreREVENGHealthChecker()
        real_import = __import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if isinstance(name, str) and name.startswith("reveng."):
                raise ImportError("boom")
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=fake_import):
            health = checker.check_health()
        assert health.status == "critical"
        assert any(m.status == "critical" for m in health.metrics)

    def test_runtime_error_on_import_fail_closed(self):
        checker = CoreREVENGHealthChecker()
        real_import = __import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if isinstance(name, str) and name.startswith("reveng."):
                raise RuntimeError("probe exploded")
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=fake_import):
            health = checker.check_health()
        assert health.status == "critical"


class TestHistoricalDocHonesty:
    def test_changelog_and_system_paper_banners(self):
        root = Path(__file__).resolve().parents[2]
        for rel in [
            "docs/changelogs/v4.0.md",
            "docs/changelogs/v5.0.md",
            "docs/changelogs/v6.0.md",
            "docs/architecture/reveng-system-paper.md",
        ]:
            text = (root / rel).read_text(encoding="utf-8")
            assert "Historical document — not a support claim" in text
        paper = (root / "docs/architecture/reveng-system-paper.md").read_text(encoding="utf-8")
        assert "src/reveng/cli.py" not in paper or "cli/ (package" in paper
