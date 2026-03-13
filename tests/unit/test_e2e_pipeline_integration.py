"""Focused tests for the end-to-end CLI pipeline integration flow."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from reveng import cli
from reveng.pipeline.pipeline_engine import (
    AnalysisPipeline,
    PipelineStatus,
    PipelineStage,
    StageType,
)


def _make_stage(
    name: str,
    stage_type: StageType,
    *,
    dependencies: list[str] | None = None,
    **config,
) -> PipelineStage:
    return PipelineStage(
        name=name,
        stage_type=stage_type,
        tool="test",
        config=config,
        dependencies=dependencies or [],
        timeout=5,
        retry_count=0,
        required=True,
    )


def test_analysis_pipeline_generates_unified_report(monkeypatch, tmp_path: Path):
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)
    output_dir = tmp_path / "analysis_sample"

    engine = AnalysisPipeline()
    pipeline = engine.create_pipeline("cli_e2e")
    engine.add_stage(
        pipeline,
        _make_stage(
            "ghidra_analysis",
            StageType.GHIDRA_ANALYSIS,
            mode="e2e_disassembly",
            output_dir=str(output_dir),
        ),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "recompilation",
            StageType.RECOMPILATION,
            dependencies=["ghidra_analysis"],
            output_dir=str(output_dir),
        ),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "behavioral_forensics",
            StageType.MALWARE_ANALYSIS,
            dependencies=["recompilation"],
            mode="behavioral_forensics",
            output_dir=str(output_dir),
        ),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "memory_forensics",
            StageType.ML_ANALYSIS,
            dependencies=["recompilation"],
            mode="memory_forensics",
            output_dir=str(output_dir),
        ),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "unified_report",
            StageType.REPORT_GENERATION,
            dependencies=[
                "ghidra_analysis",
                "recompilation",
                "behavioral_forensics",
                "memory_forensics",
            ],
            mode="unified_e2e_report",
            output_dir=str(output_dir),
        ),
    )

    def fake_ghidra(self: AnalysisPipeline, stage: PipelineStage, binary: str):
        return {
            "status": "success",
            "backend": "mock_ghidra",
            "analysis_data": {
                "functions": [{"name": "main", "address": "0x401000"}],
                "imports": ["kernel32!CreateFileA"],
                "decompiled_code": {"0x401000": "int main(void) { return 0; }"},
                "cfg_summary": {"function_count": 1, "node_count": 4, "edge_count": 3},
            },
            "summary": {"functions": 1, "imports": 1},
        }

    def fake_recompilation(self: AnalysisPipeline, stage: PipelineStage, binary: str):
        stage_context = self._get_stage_context()
        assert "ghidra_analysis" in stage_context["dependencies"]
        return {
            "status": "success",
            "source_files": {"c": str(output_dir / "reconstructed.c")},
            "compiled_binaries": {"c_gcc": str(output_dir / "reconstructed.exe")},
            "compilation_reports": {
                "c_gcc": {"status": "success", "total_attempts": 1}
            },
            "cfg_summary": stage_context["dependencies"]["ghidra_analysis"]["analysis_data"][
                "cfg_summary"
            ],
        }

    def fake_behavioral(self: AnalysisPipeline, stage: PipelineStage, binary: str):
        stage_context = self._get_stage_context()
        assert "recompilation" in stage_context["dependencies"]
        return {
            "status": "success",
            "analyzed_binary": stage_context["dependencies"]["recompilation"][
                "compiled_binaries"
            ]["c_gcc"],
            "risk_score": 82.0,
            "threat_level": "high",
            "anomaly_score": 0.82,
            "anomaly_flags": ["remote thread injection"],
            "report_path": str(output_dir / "behavioral_profile.json"),
        }

    def fake_memory(self: AnalysisPipeline, stage: PipelineStage, binary: str):
        stage_context = self._get_stage_context()
        assert "recompilation" in stage_context["dependencies"]
        return {
            "status": "success",
            "analyzed_binary": stage_context["dependencies"]["recompilation"][
                "compiled_binaries"
            ]["c_gcc"],
            "risk_score": 91.0,
            "threat_level": "CRITICAL",
            "anomaly_score": 0.91,
            "anomaly_flags": ["memory artifact injection"],
            "report_path": str(output_dir / "memory_analysis.json"),
        }

    monkeypatch.setattr(AnalysisPipeline, "_execute_ghidra_analysis", fake_ghidra)
    monkeypatch.setattr(AnalysisPipeline, "_execute_recompilation", fake_recompilation)
    monkeypatch.setattr(AnalysisPipeline, "_execute_malware_analysis", fake_behavioral)
    monkeypatch.setattr(AnalysisPipeline, "_execute_ml_analysis", fake_memory)

    result = engine.execute_pipeline(pipeline, str(binary_path))

    assert result.status == PipelineStatus.COMPLETED
    report_stage_output = result.output["unified_report"]
    report_path = Path(report_stage_output["report_path"])
    assert report_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["overall_status"] == "success"
    assert report["summary"]["compiled_binaries"] == [str(output_dir / "reconstructed.exe")]
    assert report["summary"]["behavioral_anomaly_score"] == 0.82
    assert report["summary"]["memory_anomaly_score"] == 0.91
    assert report["stages"]["ghidra_analysis"]["backend"] == "mock_ghidra"
    assert report["stages"]["recompilation"]["compiled_binaries"]["c_gcc"].endswith(
        "reconstructed.exe"
    )


def test_handle_analyze_command_reports_unified_pipeline_result(
    monkeypatch,
    tmp_path: Path,
    capsys,
):
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)
    report_path = tmp_path / "analysis_sample" / "unified_analysis_report.json"

    def fake_run_end_to_end_analysis(*, binary_path: str, output_dir: str, enhanced_features):
        return {
            "status": "partial_success",
            "report_path": str(report_path),
            "output_dir": output_dir,
            "summary": {
                "overall_status": "partial_success",
                "compiled_binaries": [],
                "behavioral_anomaly_score": 0.62,
                "memory_anomaly_score": 0.73,
            },
        }

    monkeypatch.setattr(cli, "run_end_to_end_analysis", fake_run_end_to_end_analysis)

    args = SimpleNamespace(
        binary_path=str(binary_path),
        output_dir=str(tmp_path / "analysis_sample"),
        no_ollama_check=True,
        config=None,
        no_enhanced=False,
        no_corporate=False,
        no_vuln=False,
        no_threat=False,
        no_reconstruction=False,
        no_demo=False,
    )

    exit_code = cli.handle_analyze_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "partial_success" in captured.out.lower()
    assert str(report_path) in captured.out
