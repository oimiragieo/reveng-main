from pathlib import Path

from reveng import ai_api, api
from reveng.analysis import analyzer
from reveng.app_reverse_engineering.models import AppReverseEngineeringResult


class _FakeREVENGAnalyzer:
    def __init__(self, binary_path=None, **kwargs):
        self.binary_path = binary_path

    def analyze_binary(self, binary_path=None):
        return {
            "status": "success",
            "analysis_folder": "analysis_sample",
            "binary": {"file_type": {"language": "c", "confidence": 0.8}},
            "ghidra_analysis": {
                "imports": ["CreateFileA"],
                "exports": ["main"],
                "strings": ["hello"],
                "functions": ["main"],
                "decompiled_code": {"main": "int main() { return 0; }"},
            },
            "results": {
                "metadata": {"duration_seconds": 3.5},
                "resources": ["icon.ico"],
                "errors": [],
            },
        }


class _FakeMLIntegration:
    def analyze_binary(self, path, ghidra_data=None):
        return {"confidence": 0.6, "summary": "ml"}

    def reconstruct_code(self, path, output_format="c"):
        return {
            "source_files": ["main.c"],
            "main_file": "main.c",
            "dependencies": ["stdio.h"],
            "build_instructions": ["make"],
            "completeness": 0.8,
            "readability": 0.9,
            "compilability": 0.7,
            "errors": [],
            "warnings": [],
        }

    def detect_threats(self, path):
        return {
            "is_malware": True,
            "threat_level": "high",
            "malware_family": "test-family",
            "confidence": 0.75,
            "suspicious_apis": ["CreateRemoteThread"],
            "network_indicators": [],
            "file_indicators": [],
            "behavioral_indicators": ["persistence"],
            "mitre_attacks": ["T1055"],
            "recommendations": ["sandbox"],
            "errors": [],
            "warnings": [],
        }


class _FakeInstantTriageEngine:
    def triage(self, binary_path):
        return {
            "threat_level": "medium",
            "threat_score": 45,
            "capabilities": ["network"],
            "indicators": ["indicator-1"],
            "file_type": "PE32",
            "architecture": "x86-64",
            "reasoning": "test reasoning",
        }


class _FakeNaturalLanguageInterface:
    def __init__(self, *args, **kwargs):
        pass

    def query(self, *args, **kwargs):
        raise AssertionError("query should not be called in this test")


class _FakeAppFramework:
    def __init__(self, result: AppReverseEngineeringResult):
        self._result = result

    async def reverse_engineer(self, *args, **kwargs):
        return self._result


def _fake_corpus_report(tmp_path: Path) -> dict:
    return {
        "schema_version": "1.0",
        "result_type": "app_reverse_engineering_corpus_report",
        "output_dir": str(tmp_path / "corpus_out"),
        "summary": {
            "total_entries": 1,
            "completed_entries": 1,
            "failed_entries": 0,
            "required_failed_entries": 0,
            "matrix_status": "pass",
        },
        "rows": [
            {
                "name": "python-sample-app",
                "language": "python",
                "status": "completed",
            }
        ],
    }


def test_reveng_api_analysis_result_is_versioned(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(api, "REVENGAnalyzer", _FakeREVENGAnalyzer)
    monkeypatch.setattr(api, "MLIntegration", _FakeMLIntegration)

    reveng_api = api.REVENGAPI()
    result = reveng_api.analyze_binary(sample, enhanced=True)

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "analysis_result"
    assert result["binary"]["path"] == str(sample)
    assert result["classification"]["language"] == "c"
    assert result["analysis"]["decompiled_functions"] == 1
    assert result["provenance"]["inputs"][0]["path"] == str(sample)
    assert result["provenance"]["inputs"][0]["trace_id"] == f"binary:{sample.name}"
    assert result["provenance"]["inputs"][0]["evidence_kind"] == "input_binary"
    assert any(
        ref["metadata"]["kind"] == "analysis_report" for ref in result["provenance"]["references"]
    )


def test_reveng_api_reconstruction_and_malware_results_are_versioned(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(api, "REVENGAnalyzer", _FakeREVENGAnalyzer)
    monkeypatch.setattr(api, "MLIntegration", _FakeMLIntegration)

    reveng_api = api.REVENGAPI()
    reconstruction = reveng_api.reconstruct_binary(sample)
    malware = reveng_api.detect_malware(sample)

    assert reconstruction["schema_version"] == "1.0"
    assert reconstruction["result_type"] == "reconstruction_result"
    assert reconstruction["provenance"]["artifacts"][0]["path"] == "main.c"
    assert reconstruction["provenance"]["artifacts"][0]["evidence_kind"] == "generated_source"
    assert malware["schema_version"] == "1.0"
    assert malware["result_type"] == "malware_detection_result"
    assert malware["threat_assessment"]["is_malware"] is True
    assert malware["provenance"]["tools"] == ["ml_integration"]


def test_reveng_api_app_reverse_engineering_result_is_versioned(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.py"
    sample.write_text("def main():\n    return 1\n", encoding="utf-8")
    output_dir = tmp_path / "analysis_out"
    analysis_file = output_dir / "analysis.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_payload = {
        "schema_version": "1.0",
        "result_type": "app_reverse_engineering_result",
        "language": "python",
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
            "inputs": [{"path": str(sample)}],
            "artifacts": [{"path": str(analysis_file)}],
            "stages": ["reverse_engineer_app"],
            "references": [],
            "tools": ["python_app_workflow"],
        },
    }
    result_obj = AppReverseEngineeringResult(
        language="python",
        adapter_name="python_app_workflow",
        input_path=sample,
        input_root=sample.parent,
        output_dir=output_dir,
        specs_dir=output_dir / "SPECS",
        domains_dir=output_dir / "SPECS" / "domains",
        artifacts_dir=output_dir / "artifacts",
        analysis_file=analysis_file,
        topic_files={},
        domain_files={},
        warnings=[],
        metadata=analysis_payload,
        primary_artifacts={},
        source_count=1,
        source_language="python",
        validation_grade="evidence_backed",
        validation_summary="Recovered source and evidence.",
        evidence=analysis_payload["evidence"],
        provenance=analysis_payload["provenance"],
    )

    monkeypatch.setattr(
        api,
        "create_default_framework",
        lambda: _FakeAppFramework(result_obj),
        raising=False,
    )

    reveng_api = api.REVENGAPI()
    result = reveng_api.reverse_engineer_app(sample, language="python", output_dir=output_dir)

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "app_reverse_engineering_result"
    assert result["language"] == "python"
    assert result["validation"]["grade"] == "evidence_backed"
    assert result["provenance"]["inputs"][0]["path"] == str(sample)


def test_reveng_api_app_corpus_report_is_versioned(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        api,
        "load_app_corpus_config",
        lambda config_path=None: {"entries": []},
        raising=False,
    )
    monkeypatch.setattr(
        api,
        "run_app_corpus_sync",
        lambda entries, output_dir, **kwargs: _fake_corpus_report(tmp_path),
        raising=False,
    )

    reveng_api = api.REVENGAPI()
    result = reveng_api.run_app_reverse_engineering_corpus(output_dir=tmp_path / "corpus_out")

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "app_reverse_engineering_corpus_report"
    assert result["summary"]["matrix_status"] == "pass"
    assert result["rows"][0]["name"] == "python-sample-app"


def test_analyzer_capabilities_are_versioned(monkeypatch):
    monkeypatch.setattr(analyzer.REVENGAnalyzer, "_check_ghidra_available", lambda self: False)
    monkeypatch.setattr(analyzer.REVENGAnalyzer, "_validate_environment", lambda self: None)
    monkeypatch.setattr(analyzer.REVENGAnalyzer, "_detect_file_type", lambda self: None)
    monkeypatch.setattr(analyzer.REVENGAnalyzer, "_check_ollama_availability", lambda self: None)

    class _FakeDependencyManager:
        def check_all_dependencies(self):
            return {"ghidra": True}

    import reveng.core.dependency_manager as dependency_manager

    monkeypatch.setattr(dependency_manager, "DependencyManager", _FakeDependencyManager)

    result = analyzer.REVENGAnalyzer(binary_path=None, check_ollama=False).get_capabilities()

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "analyzer_capabilities"
    assert "core_features" in result
    assert result["provenance"]["stages"] == [
        "capability_enumeration",
        "result_contract_serialization",
    ]
    assert result["provenance"]["references"][0]["relationship"] == "describes"


def test_ai_api_analysis_result_is_versioned(monkeypatch, tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x00\x01")

    monkeypatch.setattr(ai_api, "InstantTriageEngine", _FakeInstantTriageEngine)
    monkeypatch.setattr(ai_api, "NaturalLanguageInterface", _FakeNaturalLanguageInterface)

    api_instance = ai_api.REVENG_AI_API(use_ollama=False)

    import reveng.analysis.analyzer as analyzer_module

    monkeypatch.setattr(analyzer_module, "REVENGAnalyzer", _FakeREVENGAnalyzer)

    result = api_instance.analyze_binary(
        str(sample), mode=ai_api.AnalysisMode.QUICK, save_results=False
    )

    assert result["schema_version"] == "1.0"
    assert result["result_type"] == "ai_binary_analysis"
    assert result["mode"] == "quick"
    assert result["triage"]["threat_score"] == 45
    assert result["provenance"]["inputs"][0]["path"] == str(sample)
    assert result["provenance"]["inputs"][0]["trace_id"] == f"binary:{sample.name}"
    assert result["provenance"]["stages"][0] == "triage"
