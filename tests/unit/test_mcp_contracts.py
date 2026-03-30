"""Contract tests for MCP-facing REVENG server responses."""

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from reveng.agent_sdk.mcp.servers import reveng_enterprise_server, reveng_server
from reveng.app_reverse_engineering.models import AppReverseEngineeringResult


class _FakeAnalyzer:
    def __init__(self, binary_path=None, **kwargs):
        self.binary_path = binary_path

    def analyze_binary(self):
        return {
            "schema_version": "1.0",
            "result_type": "analysis_result",
            "binary": {"type": "PE32", "architecture": "x86-64"},
            "errors": ["suspicious import"],
            "provenance": {"inputs": [{"path": self.binary_path}]},
        }


class _FakeGhidraEngine:
    def __init__(self, *args, **kwargs):
        pass

    def decompile(self, path):
        return {
            "functions": [{"name": "main", "decompiled": "int main() { return 0; }"}],
            "imports": ["puts"],
            "strings": ["hello"],
        }


class _FakeYARAScanner:
    def classify_file(self, path, use_ollama_family_naming=False):
        return {
            "family": "test-family",
            "confidence": 0.84,
            "matched_rules": ["test_rule"],
            "indicators": ["network beaconing"],
            "yara_matches": [{"rule": "test_rule"}],
            "ml_assessment": {"score": 0.8},
            "feature_summary": {"entropy": 7.1},
        }


class _FakeJSDeobfuscator:
    def __init__(self, *args, **kwargs):
        pass

    async def deobfuscate(self, code):
        return SimpleNamespace(
            deobfuscated_code="const answer = 42;",
            confidence=88,
            obfuscation_types=["string-array"],
        )


class _FakeEnterpriseJSDeobfuscator:
    def __init__(self, *args, **kwargs):
        pass

    async def deobfuscate(self, code):
        return SimpleNamespace(
            deobfuscated_code="function main() { return 42; }",
            confidence=91,
            obfuscation_types=[SimpleNamespace(value="control-flow")],
        )


class _FakeMalwareDetector:
    def analyze(self, code):
        return SimpleNamespace(threat_score=17, is_malicious=False, indicators=[])


class _FakeMemoryForensics:
    def __init__(self, *args, **kwargs):
        pass

    def analyze_memory(self, path, output_dir):
        return {"path": path, "processes": [{"pid": 100, "name": "sample.exe"}]}


class _FakeBinaryDiffer:
    def diff(self, binary1, binary2, deep_analysis=False):
        return {
            "binary1": binary1,
            "binary2": binary2,
            "deep_analysis": deep_analysis,
            "changed_functions": [{"name": "main", "status": "modified"}],
        }


class _DenyRateLimiter:
    async def acquire(self):
        return False


class _AuditRecorder:
    def __init__(self):
        self.events = []

    def log_event(self, **kwargs):
        self.events.append(kwargs)


class _FakeSymbolicExecutionEngine:
    def __init__(self, binary_path, analysis_depth="shallow"):
        self.binary_path = binary_path
        self.analysis_depth = analysis_depth

    def find_vulnerabilities(self):
        return [
            SimpleNamespace(
                type="buffer_overflow",
                description="overflow in parser",
                address="0x401000",
                severity="high",
            )
        ]

    def run_cfg_fast(self):
        return "fake-cfg"

    def generate_exploit(self, vulnerability):
        return "exploit-template"


class _FakeAppFramework:
    async def reverse_engineer(self, input_path, output_dir, **kwargs):
        output_root = Path(output_dir)
        analysis_file = output_root / "analysis.json"
        return AppReverseEngineeringResult(
            language=str(kwargs.get("language") or "python"),
            adapter_name="python_app_workflow",
            input_path=Path(input_path),
            input_root=Path(input_path).parent,
            output_dir=output_root,
            specs_dir=output_root / "SPECS",
            domains_dir=output_root / "SPECS" / "domains",
            artifacts_dir=output_root / "artifacts",
            analysis_file=analysis_file,
            topic_files={},
            domain_files={},
            warnings=[],
            metadata={
                "schema_version": "1.0",
                "result_type": "app_reverse_engineering_result",
                "language": str(kwargs.get("language") or "python"),
                "validation": {
                    "grade": "evidence_backed",
                    "summary": "Recovered source and evidence.",
                    "evidence_count": 2,
                    "topic_evidence_count": 1,
                    "artifact_count": 1,
                    "warning_count": 0,
                },
                "evidence": [{"kind": "analysis_summary", "path": str(analysis_file)}],
                "provenance": {
                    "inputs": [{"path": str(input_path)}],
                    "artifacts": [{"path": str(analysis_file)}],
                    "stages": ["reverse_engineer_app"],
                    "references": [],
                    "tools": ["python_app_workflow"],
                },
            },
            primary_artifacts={},
            source_count=1,
            source_language="python",
            validation_grade="evidence_backed",
            validation_summary="Recovered source and evidence.",
            evidence=[{"kind": "analysis_summary", "path": str(analysis_file)}],
            provenance={
                "inputs": [{"path": str(input_path)}],
                "artifacts": [{"path": str(analysis_file)}],
                "stages": ["reverse_engineer_app"],
                "references": [],
                "tools": ["python_app_workflow"],
            },
        )


def _fake_corpus_report() -> dict:
    return {
        "schema_version": "1.0",
        "result_type": "app_reverse_engineering_corpus_report",
        "summary": {
            "total_entries": 1,
            "completed_entries": 1,
            "failed_entries": 0,
            "required_failed_entries": 0,
            "matrix_status": "pass",
        },
        "rows": [{"name": "python-sample-app", "language": "python", "status": "completed"}],
    }


def test_simple_mcp_analyze_binary_returns_versioned_contract(monkeypatch):
    import reveng.analyzer as analyzer_module

    monkeypatch.setattr(analyzer_module, "REVENGAnalyzer", _FakeAnalyzer)

    server = reveng_server.REVENGMCPServer()
    result = asyncio.run(server.analyze_binary({"path": "sample.exe", "quick_mode": True}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "analyze_binary"
    assert result["status"] == "success"
    assert result["analysis_result"]["result_type"] == "analysis_result"
    assert result["provenance"]["inputs"][0]["trace_id"] == "mcp:analyze:sample.exe"
    assert result["provenance"]["inputs"][0]["evidence_kind"] == "input_binary"


def test_enterprise_mcp_analyze_binary_wraps_analysis_result(monkeypatch):
    import reveng.analyzer as analyzer_module

    monkeypatch.setattr(analyzer_module, "REVENGAnalyzer", _FakeAnalyzer)
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    result = asyncio.run(server.analyze_binary({"path": "sample.exe"}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "analyze_binary"
    assert result["analysis_result"]["binary"]["type"] == "PE32"
    assert result["analysis_id"]
    assert result["provenance"]["references"][0]["relationship"] == "cached_as"


def test_enterprise_mcp_classify_malware_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)
    monkeypatch.setattr(
        reveng_enterprise_server, "YARAScanner", lambda: _FakeYARAScanner(), raising=False
    )

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    async def _fake_refine(path, classification):
        return "refined"

    monkeypatch.setattr(server, "_refine_malware_family_name", _fake_refine)

    import reveng.security.yara_scanner as yara_module

    monkeypatch.setattr(yara_module, "YARAScanner", _FakeYARAScanner)

    result = asyncio.run(server.classify_malware({"path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "classify_malware"
    assert result["family"] == "refined"
    assert result["provenance"]["references"][0]["relationship"] == "classified_as"
    assert result["provenance"]["references"][0]["confidence"] == 0.84


def test_simple_mcp_deobfuscate_js_returns_versioned_contract(monkeypatch):
    import reveng.javascript.deobfuscator as deobfuscator_module
    import reveng.javascript.malware_detector as detector_module

    monkeypatch.setattr(deobfuscator_module, "JavaScriptDeobfuscator", _FakeJSDeobfuscator)
    monkeypatch.setattr(detector_module, "MalwareDetector", _FakeMalwareDetector)

    server = reveng_server.REVENGMCPServer()
    result = asyncio.run(server.deobfuscate_js({"code": "obfuscated()", "detect_malware": True}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "deobfuscate_js"
    assert result["deobfuscated_code"] == "const answer = 42;"
    assert result["provenance"]["artifacts"][0]["evidence_kind"] == "generated_source"


def test_simple_mcp_reverse_engineer_app_returns_versioned_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.py"
    sample.write_text("def main():\n    return 1\n", encoding="utf-8")
    monkeypatch.setattr(
        reveng_server,
        "create_default_framework",
        lambda: _FakeAppFramework(),
        raising=False,
    )

    server = reveng_server.REVENGMCPServer()
    result = asyncio.run(
        server.reverse_engineer_app(
            {
                "path": str(sample),
                "language": "python",
                "output_dir": str(tmp_path / "analysis_out"),
            }
        )
    )

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "reverse_engineer_app"
    assert result["app_result"]["result_type"] == "app_reverse_engineering_result"
    assert result["app_result"]["validation"]["grade"] == "evidence_backed"
    assert result["provenance"]["inputs"][0]["path"] == str(sample)


def test_enterprise_mcp_decompile_binary_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    monkeypatch.setattr(
        server, "_get_ghidra_engine", lambda timeout_override=None: _FakeGhidraEngine()
    )

    result = asyncio.run(server.decompile_binary({"binary_path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "decompile_binary"
    assert result["binary_path"] == str(sample)
    assert result["provenance"]["references"][0]["relationship"] == "derived_from"


def test_enterprise_mcp_reverse_engineer_app_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.py"
    sample.write_text("def main():\n    return 1\n", encoding="utf-8")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)
    monkeypatch.setattr(
        reveng_enterprise_server,
        "create_default_framework",
        lambda: _FakeAppFramework(),
        raising=False,
    )

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    result = asyncio.run(
        server.reverse_engineer_app(
            {
                "path": str(sample),
                "language": "python",
                "output_dir": str(tmp_path / "analysis_out"),
            }
        )
    )

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "reverse_engineer_app"
    assert result["app_result"]["result_type"] == "app_reverse_engineering_result"
    assert result["analysis_id"]
    assert result["provenance"]["references"][0]["relationship"] == "cached_as"


def test_simple_mcp_run_app_corpus_returns_versioned_contract(monkeypatch):
    monkeypatch.setattr(
        reveng_server,
        "load_app_corpus_config",
        lambda config_path=None: {"entries": []},
        raising=False,
    )
    monkeypatch.setattr(
        reveng_server,
        "run_app_corpus_sync",
        lambda entries, output_dir, **kwargs: _fake_corpus_report(),
        raising=False,
    )

    server = reveng_server.REVENGMCPServer()
    result = asyncio.run(server.run_app_corpus({}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "run_app_corpus"
    assert result["corpus_report"]["result_type"] == "app_reverse_engineering_corpus_report"
    assert result["corpus_report"]["summary"]["matrix_status"] == "pass"


def test_enterprise_mcp_run_app_corpus_returns_versioned_contract(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)
    monkeypatch.setattr(
        reveng_enterprise_server,
        "load_app_corpus_config",
        lambda config_path=None: {"entries": []},
        raising=False,
    )
    monkeypatch.setattr(
        reveng_enterprise_server,
        "run_app_corpus_sync",
        lambda entries, output_dir, **kwargs: _fake_corpus_report(),
        raising=False,
    )

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    result = asyncio.run(server.run_app_corpus({}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "run_app_corpus"
    assert result["corpus_report"]["result_type"] == "app_reverse_engineering_corpus_report"
    assert result["analysis_id"]


def test_enterprise_mcp_recent_analyses_resource_is_versioned(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)
    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    server.results_cache = {"abc123": {"status": "success"}}

    resource = asyncio.run(server.read_resource("reveng://analyses/recent"))
    payload = json.loads(resource["text"])

    assert payload["schema_version"] == "1.0"
    assert payload["result_type"] == "mcp_resource_result"
    assert payload["resource_name"] == "recent_analyses"
    assert payload["analyses"] == ["abc123"]


def test_enterprise_missing_resource_is_versioned(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)
    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    resource = asyncio.run(server.read_resource("reveng://missing/resource"))
    payload = json.loads(resource["text"])

    assert payload["schema_version"] == "1.0"
    assert payload["result_type"] == "mcp_resource_result"
    assert payload["resource_name"] == "missing_resource"
    assert payload["status"] == "error"
    assert payload["uri"] == "reveng://missing/resource"
    assert payload["error"] == "Resource not found: reveng://missing/resource"


def test_enterprise_find_vulnerabilities_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    import reveng.security.symbolic_execution_engine as sym_module

    monkeypatch.setattr(sym_module, "SymbolicExecutionEngine", _FakeSymbolicExecutionEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    monkeypatch.setattr(
        server,
        "_serialize_vulnerability",
        lambda vulnerability: {"type": vulnerability.type, "severity": vulnerability.severity},
    )

    result = asyncio.run(server.find_vulnerabilities({"path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "find_vulnerabilities"
    assert result["vulnerabilities"][0]["type"] == "buffer_overflow"
    assert result["provenance"]["tools"] == [
        "find_vulnerabilities",
        "symbolic_execution_engine",
    ]


def test_enterprise_generate_exploit_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    import reveng.security.symbolic_execution_engine as sym_module

    monkeypatch.setattr(sym_module, "SymbolicExecutionEngine", _FakeSymbolicExecutionEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    monkeypatch.setattr(server, "_summarize_cfg", lambda cfg: {"function_count": 1})
    monkeypatch.setattr(server, "_vulnerability_matches_filters", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        server,
        "_serialize_exploit_candidate",
        lambda *args, **kwargs: {"name": "stack-smash", "confidence": 0.76},
    )
    monkeypatch.setattr(
        server,
        "_format_generate_exploit_results",
        lambda **kwargs: "Generated exploit candidates",
    )

    result = asyncio.run(server.generate_exploit({"binary_path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "generate_exploit"
    assert result["vulnerabilities"][0]["name"] == "stack-smash"
    assert result["provenance"]["artifacts"][0]["evidence_kind"] == "generated_exploit"


def test_enterprise_ai_code_reconstruction_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    async def _fake_decompile(args):
        return {
            "decompiled_source": "int main() { return 0; }",
            "decompiled_functions": [{"name": "main", "decompiled": "int main() { return 0; }"}],
        }

    async def _fake_cfg(binary_path):
        return {
            "context_text": "CFG summary",
            "function_count": 1,
            "node_count": 2,
            "edge_count": 1,
        }

    async def _fake_query_ollama_chat(**kwargs):
        return (
            '{"reconstructed_code":"int main(){return 42;}",'
            '"improvement_notes":"renamed variables"}'
        )

    monkeypatch.setattr(server, "decompile_binary", _fake_decompile)
    monkeypatch.setattr(server, "_extract_cfg_context", _fake_cfg)
    monkeypatch.setattr(server, "_query_ollama_chat", _fake_query_ollama_chat)
    monkeypatch.setattr(
        server,
        "_parse_reconstruction_response",
        lambda raw_response, fallback_source: ("int main(){return 42;}", "renamed variables"),
    )

    result = asyncio.run(server.ai_code_reconstruction({"binary_path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "ai_code_reconstruction"
    assert result["reconstructed_code"] == "int main(){return 42;}"
    assert (
        result["provenance"]["artifacts"][0]["metadata"]["cfg_context_sha256"]
        == hashlib.sha256("CFG summary".encode("utf-8")).hexdigest()
    )
    assert result["provenance"]["artifacts"][0]["metadata"]["model_host"] == server.ollama_chat_host
    assert result["provenance"]["artifacts"][0]["model"] == server.ollama_chat_model


def test_enterprise_server_resolves_ollama_routing_from_config(monkeypatch):
    import reveng.tools.config.config_manager as config_manager_module

    class _FakeConfigManager:
        def get_ai_config(self):
            return SimpleNamespace(
                provider="ollama",
                ollama_host="http://ollama.internal:22434/",
                ollama_model="codestral:22b",
                ollama_timeout=123,
            )

    monkeypatch.setattr(config_manager_module, "ConfigManager", _FakeConfigManager)
    monkeypatch.delenv("REVENG_MCP_OLLAMA_HOST", raising=False)
    monkeypatch.delenv("REVENG_MCP_OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("REVENG_MCP_OLLAMA_TIMEOUT", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_TIMEOUT", raising=False)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    assert server.ollama_chat_host == "http://ollama.internal:22434"
    assert server.ollama_chat_endpoint == "http://ollama.internal:22434/api/chat"
    assert server.ollama_chat_model == "codestral:22b"
    assert server.ollama_chat_timeout_seconds == 123


def test_enterprise_server_env_overrides_ollama_routing(monkeypatch):
    import reveng.tools.config.config_manager as config_manager_module

    class _FakeConfigManager:
        def get_ai_config(self):
            return SimpleNamespace(
                provider="ollama",
                ollama_host="http://config-host:11434",
                ollama_model="config-model",
                ollama_timeout=45,
            )

    monkeypatch.setattr(config_manager_module, "ConfigManager", _FakeConfigManager)
    monkeypatch.setenv("REVENG_MCP_OLLAMA_HOST", "http://env-host:33445/")
    monkeypatch.setenv("REVENG_MCP_OLLAMA_MODEL", "env-model")
    monkeypatch.setenv("REVENG_MCP_OLLAMA_TIMEOUT", "61")

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    assert server.ollama_chat_host == "http://env-host:33445"
    assert server.ollama_chat_endpoint == "http://env-host:33445/api/chat"
    assert server.ollama_chat_model == "env-model"
    assert server.ollama_chat_timeout_seconds == 61


def test_enterprise_analyze_memory_dump_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "memory.bin"
    sample.write_bytes(b"\x00\x01\x02")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    import reveng.malware.memory_forensics as memory_module

    monkeypatch.setattr(memory_module, "MemoryForensics", _FakeMemoryForensics)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    monkeypatch.setattr(
        server,
        "_serialize_memory_analysis",
        lambda analysis: {"process_count": 1, "summary": analysis["processes"][0]["name"]},
    )
    monkeypatch.setattr(
        server,
        "_format_memory_analysis_results",
        lambda analysis: f"Memory analysis for {analysis['summary']}",
    )

    result = asyncio.run(server.analyze_memory_dump({"path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "analyze_memory_dump"
    assert result["analysis"]["process_count"] == 1
    assert result["provenance"]["artifacts"][0]["evidence_kind"] == "analysis_report"


def test_enterprise_diff_binaries_returns_contract(monkeypatch, tmp_path: Path):
    binary1 = tmp_path / "left.exe"
    binary2 = tmp_path / "right.exe"
    binary1.write_bytes(b"MZ\x00\x01")
    binary2.write_bytes(b"MZ\x00\x02")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    import reveng.tools.diffing.binary_differ as diff_module

    monkeypatch.setattr(diff_module, "BinaryDiffer", _FakeBinaryDiffer)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    monkeypatch.setattr(
        server,
        "_serialize_diff_result",
        lambda diff: {"changed_function_count": len(diff["changed_functions"])},
    )
    monkeypatch.setattr(
        server,
        "_format_binary_diff_results",
        lambda diff: f"Changed functions: {diff['changed_function_count']}",
    )

    result = asyncio.run(
        server.diff_binaries(
            {"binary1": str(binary1), "binary2": str(binary2), "semantic_diff": True}
        )
    )

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "diff_binaries"
    assert result["semantic_diff"] is True
    assert result["diff"]["changed_function_count"] == 1
    assert result["provenance"]["references"][0]["relationship"] == "compared_with"


def test_enterprise_detect_js_malware_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.js"
    sample.write_text("alert('hi')", encoding="utf-8")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    import reveng.javascript.malware_detector as detector_module

    monkeypatch.setattr(detector_module, "MalwareDetector", _FakeMalwareDetector)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    result = asyncio.run(server.detect_js_malware({"file_path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "detect_js_malware"
    assert result["threat_score"] == 17
    assert result["indicators"] == []
    assert result["provenance"]["tools"] == ["detect_js_malware", "malware_detector"]


def test_enterprise_ask_ai_about_binary_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    async def _fake_decompile(args):
        return {"decompiled_source": "int main() { return 0; }"}

    async def _fake_query_ollama_chat(**kwargs):
        return "The binary prints a greeting."

    monkeypatch.setattr(server, "decompile_binary", _fake_decompile)
    monkeypatch.setattr(
        server,
        "_build_binary_question_context",
        lambda **kwargs: "Binary question context",
    )
    monkeypatch.setattr(server, "_query_ollama_chat", _fake_query_ollama_chat)

    result = asyncio.run(
        server.ask_ai_about_binary(
            {"binary_path": str(sample), "question": "What does this program do?"}
        )
    )

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "ask_ai_about_binary"
    assert result["answer"] == "The binary prints a greeting."
    assert result["provenance"]["artifacts"][0]["evidence_kind"] == "generated_answer"
    assert (
        result["provenance"]["artifacts"][0]["metadata"]["prompt_sha256"]
        == hashlib.sha256("Binary question context".encode("utf-8")).hexdigest()
    )
    assert (
        result["provenance"]["artifacts"][0]["metadata"]["model_host"]
        == reveng_enterprise_server.OLLAMA_CHAT_HOST
    )


def test_enterprise_get_prompt_returns_versioned_prompt_message(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    messages = asyncio.run(server.get_prompt("analyze_malware", {"binary_path": "specimen.exe"}))

    assert len(messages) == 1
    content = messages[0]["content"]
    assert content["schema_version"] == "1.0"
    assert content["result_type"] == "mcp_prompt_message"
    assert content["prompt_name"] == "analyze_malware"
    assert content["prompt_arguments"] == {"binary_path": "specimen.exe"}
    assert "specimen.exe" in content["text"]


def test_enterprise_ask_ai_about_binary_timeout_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    async def _fake_decompile(args):
        return {"decompiled_source": "int main() { return 0; }"}

    async def _fake_query_ollama_chat(**kwargs):
        raise TimeoutError("timed out waiting for Ollama")

    monkeypatch.setattr(server, "decompile_binary", _fake_decompile)
    monkeypatch.setattr(
        server,
        "_build_binary_question_context",
        lambda **kwargs: "Binary question context",
    )
    monkeypatch.setattr(server, "_query_ollama_chat", _fake_query_ollama_chat)
    monkeypatch.setattr(
        server,
        "_build_timeout_question_fallback",
        lambda **kwargs: "Fallback binary answer",
    )

    result = asyncio.run(
        server.ask_ai_about_binary(
            {"binary_path": str(sample), "question": "What does this program do?"}
        )
    )

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "ask_ai_about_binary"
    assert result["status"] == "error"
    assert result["fallback_used"] is True
    assert result["answer"] == "Fallback binary answer"
    assert result["error"] == "timed out waiting for Ollama"


def test_enterprise_ai_code_reconstruction_timeout_returns_contract(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    async def _fake_decompile(args):
        return {
            "decompiled_source": "int main() { return 0; }",
            "decompiled_functions": [{"name": "main", "decompiled": "int main() { return 0; }"}],
        }

    async def _fake_cfg(binary_path):
        return {
            "context_text": "CFG summary",
            "function_count": 1,
            "node_count": 2,
            "edge_count": 1,
        }

    async def _fake_query_ollama_chat(**kwargs):
        raise TimeoutError("reconstruction timeout")

    monkeypatch.setattr(server, "decompile_binary", _fake_decompile)
    monkeypatch.setattr(server, "_extract_cfg_context", _fake_cfg)
    monkeypatch.setattr(server, "_query_ollama_chat", _fake_query_ollama_chat)
    monkeypatch.setattr(
        server,
        "_build_timeout_reconstruction_fallback",
        lambda decompile_result: "int main() { return 0; }",
    )
    monkeypatch.setattr(
        server,
        "_build_timeout_reconstruction_notes",
        lambda cfg_context: "Fallback notes",
    )

    result = asyncio.run(server.ai_code_reconstruction({"binary_path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "ai_code_reconstruction"
    assert result["status"] == "error"
    assert result["fallback_used"] is True
    assert result["reconstructed_code"] == "int main() { return 0; }"
    assert result["improvement_notes"] == "Fallback notes"
    assert result["error"] == "reconstruction timeout"


def test_enterprise_get_analysis_report_returns_contract(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    server.results_cache = {"abc123": {"summary": "cached result"}}
    monkeypatch.setattr(
        server,
        "_format_analysis_results",
        lambda result, path, analysis_id: f"Report for {analysis_id}: {result['summary']}",
    )

    result = asyncio.run(server.get_analysis_report({"analysis_id": "abc123", "format": "json"}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "get_analysis_report"
    assert result["analysis_id"] == "abc123"
    assert result["format"] == "json"
    assert result["provenance"]["references"][0]["relationship"] == "loaded_from_cache"


def test_enterprise_get_analysis_report_missing_returns_contract(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    result = asyncio.run(server.get_analysis_report({"analysis_id": "missing"}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "get_analysis_report"
    assert result["status"] == "error"
    assert result["status_code"] == 404
    assert result["error"] == "not_found"


def test_enterprise_list_recent_analyses_returns_contract(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    server.results_cache = {"abc123": {}, "def456": {}, "ghi789": {}}

    result = asyncio.run(server.list_recent_analyses({"limit": 2}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "list_recent_analyses"
    assert result["limit"] == 2
    assert result["analyses"] == ["abc123", "def456"]
    assert result["provenance"]["tools"] == ["list_recent_analyses", "results_cache"]


def test_enterprise_execute_with_audit_rate_limit_returns_contract(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    server.rate_limiter = _DenyRateLimiter()

    async def _unused_handler(args):
        return {"ok": True}

    result = asyncio.run(server._execute_with_audit("analyze_binary", {}, _unused_handler))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "analyze_binary"
    assert result["status"] == "error"
    assert result["error"] == "rate_limit_exceeded"


def test_enterprise_execute_with_audit_rate_limit_logs_audit_event(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    server.rate_limiter = _DenyRateLimiter()
    server.audit_logger = _AuditRecorder()

    async def _unused_handler(args):
        return {"ok": True}

    result = asyncio.run(server._execute_with_audit("analyze_binary", {}, _unused_handler))

    assert result["status"] == "error"
    assert len(server.audit_logger.events) == 1
    event = server.audit_logger.events[0]
    assert event["tool_name"] == "analyze_binary"
    assert event["result"] == "error"
    assert event["error"] == "rate_limit_exceeded"


def test_enterprise_tools_list_exposes_risk_annotations(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    response = asyncio.run(
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    )

    tools = {tool["name"]: tool for tool in response["result"]["tools"]}

    assert tools["generate_exploit"]["annotations"]["risk_level"] == "high"
    assert tools["generate_exploit"]["annotations"]["requires_policy_acknowledgement"] is True
    assert tools["ai_code_reconstruction"]["annotations"]["risk_level"] == "high"
    assert (
        tools["ai_code_reconstruction"]["annotations"]["requires_policy_acknowledgement"] is False
    )
    assert tools["analyze_binary"]["annotations"]["risk_level"] == "moderate"


def test_enterprise_execute_with_audit_denies_unacknowledged_high_risk_tools(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    async def _unused_handler(args):
        return {"ok": True}

    result = asyncio.run(
        server._execute_with_audit(
            "generate_exploit", {"binary_path": "sample.exe"}, _unused_handler
        )
    )

    assert result["status"] == "error"
    assert result["error"] == "policy_acknowledgement_required"
    assert result["provenance"]["references"][0]["relationship"] == "blocked_by_policy"


def test_enterprise_execute_with_audit_logs_policy_denial(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    server.audit_logger = _AuditRecorder()

    async def _unused_handler(args):
        return {"ok": True}

    result = asyncio.run(
        server._execute_with_audit(
            "generate_exploit", {"binary_path": "sample.exe"}, _unused_handler
        )
    )

    assert result["status"] == "error"
    assert len(server.audit_logger.events) == 1
    event = server.audit_logger.events[0]
    assert event["tool_name"] == "generate_exploit"
    assert event["error"] == "policy_acknowledgement_required"


def test_enterprise_execute_with_audit_allows_acknowledged_high_risk_tools(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    async def _used_handler(args):
        return {"ok": True}

    result = asyncio.run(
        server._execute_with_audit(
            "generate_exploit",
            {"binary_path": "sample.exe", "policy_acknowledged": True},
            _used_handler,
        )
    )

    assert result["ok"] is True


def test_enterprise_coerce_optional_int_invalid_values_return_none(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )
    warnings = []
    monkeypatch.setattr(
        reveng_enterprise_server.logger,
        "warning",
        lambda message, *args: warnings.append(message % args if args else message),
    )

    assert server._coerce_optional_int("abc") is None
    assert server._coerce_optional_int("12.5") is None
    assert server._coerce_optional_int("") is None
    assert server._coerce_optional_int(-1) == -1
    assert len(warnings) == 2
    assert "Invalid integer value" in warnings[0]


def test_enterprise_require_existing_file_rejects_directories(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    result = asyncio.run(server.decompile_binary({"binary_path": str(tmp_path)}))

    assert result["status"] == "error"
    assert "Expected file but received directory" in result["error"]


def test_enterprise_scan_yara_error_returns_contract(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    def _raise_missing(args, field_name):
        raise FileNotFoundError(f"Path not found: {field_name}")

    monkeypatch.setattr(server, "_require_existing_file", _raise_missing)

    result = asyncio.run(server.scan_yara({"path": "missing.exe", "rules_path": "missing.yar"}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "scan_yara"
    assert result["status"] == "error"
    assert result["match_count"] == 0
    assert "Path not found" in result["error"]


def test_enterprise_scan_yara_rejects_non_rule_files(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")
    invalid_rules = tmp_path / "rules.txt"
    invalid_rules.write_text("not yara", encoding="utf-8")

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    result = asyncio.run(server.scan_yara({"path": str(sample), "rules_path": str(invalid_rules)}))

    assert result["status"] == "error"
    assert "YARA rules path must be a .yar/.yara file or directory containing rule files" in (
        result["error"]
    )


def test_enterprise_recompile_binary_error_returns_contract(monkeypatch):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    def _raise_missing(args, field_name="binary_path"):
        raise FileNotFoundError("Path not found: missing.exe")

    monkeypatch.setattr(server, "_resolve_binary_argument", _raise_missing)

    result = asyncio.run(server.recompile_binary({"binary_path": "missing.exe"}))

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "mcp_tool_result"
    assert result["tool_name"] == "recompile_binary"
    assert result["status"] == "error"
    assert result["success"] is False
    assert result["status_code"] == 500
    assert result["compilation_errors"] == ["Path not found: missing.exe"]


def test_enterprise_recompile_binary_routes_bun_to_node_sea(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    fake_build_output = tmp_path / "bun-sea.exe"
    fake_build_output.write_bytes(b"MZ\x00\x01")
    fake_report = tmp_path / "bun_sea_build.json"
    fake_report.write_text('{"route":"bun_node_sea"}', encoding="utf-8")

    normalization = SimpleNamespace(
        entrypoint_path=str(tmp_path / "normalized_project" / "sample.mjs"),
        output_dir=str(tmp_path / "normalized_project"),
    )
    build_result = SimpleNamespace(
        output_path=str(fake_build_output),
        sea_blob_path=str(tmp_path / "sea-prep.blob"),
        installed_dependencies=["ws", "postject"],
        commands_run=["npm install ws postject --silent"],
        verification={"status": "pass", "checks": [{"check": "output_binary_generated"}]},
    )
    bun_result = SimpleNamespace(
        info=SimpleNamespace(is_bun_executable=True),
        status="success",
        reason=None,
        message=None,
        canonical_input=str(tmp_path / "sample_bundle_bunfs" / "root" / "sample.exe"),
        canonical_reason="Recovered Bun virtual file excludes appended bundle metadata",
        normalization=normalization,
        build_result=build_result,
        report_path=str(fake_report),
        report_data={
            "route": "bun_node_sea",
            "report_severity": {"dimension": "reconstruction_risk", "level": "low"},
            "differential_validation": {"status": "pass"},
            "runtime_escalation": {"dimension": "runtime_escalation", "recommended": False},
            "equivalence_validation": {
                "dimension": "equivalence_validation",
                "equivalence_level": "semantic_candidate",
            },
        },
    )

    monkeypatch.setattr(
        reveng_enterprise_server, "run_bun_sea_workflow", lambda **kwargs: bun_result
    )

    result = asyncio.run(server.recompile_binary({"binary_path": str(sample)}))

    assert result["schema_version"] == "1.0"
    assert result["tool_name"] == "recompile_binary"
    assert result["success"] is True
    assert result["recompilation_strategy"] == "bun_node_sea"
    assert result["output_path"] == str(fake_build_output)
    assert result["bun_report_path"] == str(fake_report)
    assert result["bun_build_report"]["route"] == "bun_node_sea"
    assert result["bun_report_severity"]["dimension"] == "reconstruction_risk"
    assert result["bun_differential_validation"]["status"] == "pass"
    assert result["bun_build_verification"]["status"] == "pass"
    assert result["bun_runtime_escalation"]["dimension"] == "runtime_escalation"
    assert result["bun_equivalence_validation"]["dimension"] == "equivalence_validation"
    assert result["provenance"]["artifacts"][1]["kind"] == "bun_rebuild_report"
    assert "node_sea_packaging" in result["provenance"]["stages"]


def test_enterprise_deobfuscate_javascript_non_utf8_file_returns_contract(
    monkeypatch, tmp_path: Path
):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    sample = tmp_path / "sample.js"
    sample.write_bytes(b"\xff\xfe\x00\x00")

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    result = asyncio.run(server.deobfuscate_javascript({"file_path": str(sample)}))

    assert result["status"] == "error"
    assert "Could not decode JavaScript file as UTF-8" in result["error"]


def test_enterprise_detect_js_malware_non_utf8_file_returns_contract(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    sample = tmp_path / "sample.js"
    sample.write_bytes(b"\xff\xfe\x00\x00")

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    result = asyncio.run(server.detect_js_malware({"file_path": str(sample)}))

    assert result["status"] == "error"
    assert "Could not decode JavaScript file as UTF-8" in result["error"]


def test_enterprise_ask_ai_about_binary_timeout_without_context_returns_safe_fallback(
    monkeypatch, tmp_path: Path
):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(reveng_enterprise_server, "GhidraEngine", _FakeGhidraEngine)

    server = reveng_enterprise_server.REVENGEnterpriseServer(
        enable_rate_limiting=False, enable_audit_log=False
    )

    async def _fake_decompile(args):
        return {}

    async def _fake_query_ollama_chat(**kwargs):
        raise TimeoutError("timed out waiting for Ollama")

    monkeypatch.setattr(server, "decompile_binary", _fake_decompile)
    monkeypatch.setattr(
        server,
        "_build_binary_question_context",
        lambda **kwargs: "Binary question context",
    )
    monkeypatch.setattr(server, "_query_ollama_chat", _fake_query_ollama_chat)
    monkeypatch.setattr(
        server,
        "_build_timeout_question_fallback",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("unexpected context fallback")),
    )

    result = asyncio.run(
        server.ask_ai_about_binary(
            {"binary_path": str(sample), "question": "What does this program do?"}
        )
    )

    assert result["status"] == "error"
    assert result["fallback_used"] is True
    assert "timed out before it could produce an answer" in result["answer"]
