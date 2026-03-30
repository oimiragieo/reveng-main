"""Focused tests for the end-to-end CLI pipeline integration flow."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from reveng import cli
from reveng.pipeline.e2e_integration import EndToEndPipelineRunner
from reveng.pipeline.pipeline_engine import (
    AnalysisPipeline,
    PipelineResult,
    PipelineStage,
    PipelineStatus,
    StageResult,
    StageStatus,
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


def _make_stage_result(
    stage_name: str,
    *,
    status: StageStatus = StageStatus.COMPLETED,
    output: dict | None = None,
    error: str | None = None,
    retry_count: int = 0,
) -> StageResult:
    return StageResult(
        stage_name=stage_name,
        status=status,
        output=output or {},
        error=error,
        execution_time=0.01,
        retry_count=retry_count,
    )


def _make_pipeline_result(
    *,
    binary_path: str,
    stage_results: list[StageResult],
    output: dict,
    status: PipelineStatus = PipelineStatus.COMPLETED,
) -> PipelineResult:
    return PipelineResult(
        pipeline_name="cli_end_to_end",
        binary_path=binary_path,
        status=status,
        stage_results=stage_results,
        total_execution_time=0.05,
        success_count=sum(1 for result in stage_results if result.status == StageStatus.COMPLETED),
        failure_count=sum(1 for result in stage_results if result.status == StageStatus.FAILED),
        output=output,
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
        recompilation_dir = output_dir / "recompilation"
        recompilation_dir.mkdir(parents=True, exist_ok=True)
        reconstructed_c = recompilation_dir / "reconstructed.c"
        reconstructed_c.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        return {
            "status": "success",
            "source_files": {"c": str(reconstructed_c)},
            "compiled_binaries": {"c_gcc": str(recompilation_dir / "reconstructed.exe")},
            "compilation_reports": {"c_gcc": {"status": "success", "total_attempts": 1}},
            "cfg_summary": stage_context["dependencies"]["ghidra_analysis"]["analysis_data"][
                "cfg_summary"
            ],
        }

    def fake_behavioral(self: AnalysisPipeline, stage: PipelineStage, binary: str):
        stage_context = self._get_stage_context()
        assert "recompilation" in stage_context["dependencies"]
        return {
            "status": "success",
            "analyzed_binary": stage_context["dependencies"]["recompilation"]["compiled_binaries"][
                "c_gcc"
            ],
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
            "analyzed_binary": stage_context["dependencies"]["recompilation"]["compiled_binaries"][
                "c_gcc"
            ],
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
    assert report["summary"]["compiled_binaries"] == [
        str(output_dir / "recompilation" / "reconstructed.exe")
    ]
    assert report["summary"]["behavioral_anomaly_score"] == 0.82
    assert report["summary"]["memory_anomaly_score"] == 0.91
    assert len(report["decompiled_functions"]) == 1
    assert report["decompiled_functions"][0]["source"].startswith("int main")
    assert report["recompilation_result"]["status"] == "success"
    assert Path(report["recompilation_result"]["source_files"]["c"]).exists()
    assert report["summary"]["yara_match_count"] >= 1
    assert report["yara_matches"]
    assert report["vulnerabilities"] == []
    assert report["malware_classification"]["family"]
    assert report["stages"]["ghidra_analysis"]["backend"] == "mock_ghidra"
    assert report["stages"]["recompilation"]["compiled_binaries"]["c_gcc"].endswith(
        "reconstructed.exe"
    )
    assert (output_dir / "source").exists()
    assert list((output_dir / "source").glob("*.c"))


def test_handle_analyze_command_reports_unified_pipeline_result(
    monkeypatch,
    tmp_path: Path,
    capsys,
):
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)
    report_path = tmp_path / "analysis_sample" / "unified_analysis_report.json"

    def fake_run_end_to_end_analysis(
        *,
        binary_path: str,
        output_dir: str,
        enhanced_features,
        ghidra_timeout_seconds: int,
        ghidra_retry_count: int,
    ):
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
        ghidra_timeout=900,
        ghidra_retries=0,
    )

    exit_code = cli.handle_analyze_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "partial_success" in captured.out.lower()
    assert str(report_path) in captured.out


def test_runner_marks_all_stages_failing_as_failed(monkeypatch, tmp_path: Path):
    runner = EndToEndPipelineRunner(output_dir=str(tmp_path / "analysis_sample"))
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    report_path = runner.output_dir / "reports" / "unified_analysis_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    stage_outputs = {
        "ghidra_analysis": {"status": "failed", "error": "disassembly unavailable"},
        "recompilation": {"status": "failed", "error": "no source available"},
        "behavioral_forensics": {"status": "failed", "error": "monitoring failed"},
        "memory_forensics": {"status": "failed", "error": "scan failed"},
    }
    report = {
        "summary": {
            "overall_status": "failed",
            "stage_statuses": {name: output["status"] for name, output in stage_outputs.items()},
            "compiled_binaries": [],
            "behavioral_anomaly_score": None,
            "memory_anomaly_score": None,
        },
        "stages": stage_outputs,
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")

    def fake_execute_pipeline(pipeline: PipelineStage, resolved_binary_path: str):
        return _make_pipeline_result(
            binary_path=resolved_binary_path,
            stage_results=[
                _make_stage_result("ghidra_analysis", output=stage_outputs["ghidra_analysis"]),
                _make_stage_result("recompilation", output=stage_outputs["recompilation"]),
                _make_stage_result(
                    "behavioral_forensics", output=stage_outputs["behavioral_forensics"]
                ),
                _make_stage_result("memory_forensics", output=stage_outputs["memory_forensics"]),
                _make_stage_result(
                    "unified_report",
                    output={
                        "status": "failed",
                        "report_path": str(report_path),
                        "summary": report["summary"],
                    },
                ),
            ],
            output={
                "unified_report": {
                    "status": "failed",
                    "report_path": str(report_path),
                    "summary": report["summary"],
                }
            },
        )

    monkeypatch.setattr(runner.pipeline_engine, "execute_pipeline", fake_execute_pipeline)

    result = runner.run(str(binary_path))

    assert result["status"] == "failed"
    assert result["summary"]["overall_status"] == "failed"
    assert result["unified_report"]["stages"]["recompilation"]["status"] == "failed"
    assert Path(result["pipeline_execution_path"]).exists()


def test_runner_build_pipeline_skips_forensics_when_disabled(tmp_path: Path):
    runner = EndToEndPipelineRunner(
        output_dir=str(tmp_path / "analysis_sample"),
        enable_forensics=False,
    )

    pipeline = runner.build_pipeline()
    stage_names = [stage.name for stage in pipeline.stages]
    unified_report_stage = next(
        stage for stage in pipeline.stages if stage.name == "unified_report"
    )

    assert stage_names == ["ghidra_analysis", "recompilation", "unified_report"]
    assert "behavioral_forensics" not in stage_names
    assert "memory_forensics" not in stage_names
    assert unified_report_stage.dependencies == ["ghidra_analysis", "recompilation"]


def test_runner_build_pipeline_uses_configured_ghidra_timeout_and_retry_count(tmp_path: Path):
    runner = EndToEndPipelineRunner(
        output_dir=str(tmp_path / "analysis_sample"),
        ghidra_timeout_seconds=900,
        ghidra_retry_count=0,
    )

    pipeline = runner.build_pipeline()
    ghidra_stage = next(stage for stage in pipeline.stages if stage.name == "ghidra_analysis")

    assert ghidra_stage.timeout == 900
    assert ghidra_stage.retry_count == 0


def test_runner_resolves_invalid_binary_path_before_execution(
    monkeypatch,
    tmp_path: Path,
):
    runner = EndToEndPipelineRunner(output_dir=str(tmp_path / "analysis_sample"))
    missing_binary = tmp_path / "missing.exe"
    captured: dict[str, str] = {}

    def fake_execute_pipeline(pipeline: PipelineStage, resolved_binary_path: str):
        captured["binary_path"] = resolved_binary_path
        return _make_pipeline_result(
            binary_path=resolved_binary_path,
            stage_results=[
                _make_stage_result(
                    "ghidra_analysis",
                    status=StageStatus.FAILED,
                    error="Binary not found",
                )
            ],
            output={},
            status=PipelineStatus.FAILED,
        )

    monkeypatch.setattr(runner.pipeline_engine, "execute_pipeline", fake_execute_pipeline)

    result = runner.run(str(missing_binary))

    assert captured["binary_path"] == str(missing_binary.resolve())
    assert result["status"] == "failed"
    assert result["report_path"] is None
    assert result["summary"] == {}
    assert result["unified_report"] == {}


def test_handle_analyze_command_passes_ghidra_stage_overrides(
    monkeypatch,
    tmp_path: Path,
    capsys,
):
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)
    captured_call: dict[str, object] = {}

    def fake_run_end_to_end_analysis(
        *,
        binary_path: str,
        output_dir: str,
        enhanced_features,
        ghidra_timeout_seconds: int,
        ghidra_retry_count: int,
    ):
        captured_call.update(
            {
                "binary_path": binary_path,
                "output_dir": output_dir,
                "ghidra_timeout_seconds": ghidra_timeout_seconds,
                "ghidra_retry_count": ghidra_retry_count,
            }
        )
        return {
            "status": "success",
            "report_path": None,
            "output_dir": output_dir,
            "summary": {},
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
        ghidra_timeout=900,
        ghidra_retries=0,
    )

    exit_code = cli.handle_analyze_command(args)
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Ghidra stage timeout: 900s" in captured.out
    assert captured_call["ghidra_timeout_seconds"] == 900
    assert captured_call["ghidra_retry_count"] == 0


def test_runner_preserves_graceful_recompilation_failure(monkeypatch, tmp_path: Path):
    runner = EndToEndPipelineRunner(output_dir=str(tmp_path / "analysis_sample"))
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    report_path = runner.output_dir / "reports" / "unified_analysis_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    stage_outputs = {
        "ghidra_analysis": {"status": "success", "backend": "mock_ghidra"},
        "recompilation": {
            "status": "failed",
            "error": "compiler feedback loop exhausted",
            "compiled_binaries": {},
        },
        "behavioral_forensics": {"status": "success", "anomaly_score": 0.41},
        "memory_forensics": {"status": "success", "anomaly_score": 0.58},
    }
    report = {
        "summary": {
            "overall_status": "partial_success",
            "stage_statuses": {name: output["status"] for name, output in stage_outputs.items()},
            "compiled_binaries": [],
            "behavioral_anomaly_score": 0.41,
            "memory_anomaly_score": 0.58,
        },
        "stages": stage_outputs,
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")

    def fake_execute_pipeline(pipeline: PipelineStage, resolved_binary_path: str):
        return _make_pipeline_result(
            binary_path=resolved_binary_path,
            stage_results=[
                _make_stage_result("ghidra_analysis", output=stage_outputs["ghidra_analysis"]),
                _make_stage_result("recompilation", output=stage_outputs["recompilation"]),
                _make_stage_result(
                    "behavioral_forensics", output=stage_outputs["behavioral_forensics"]
                ),
                _make_stage_result("memory_forensics", output=stage_outputs["memory_forensics"]),
                _make_stage_result(
                    "unified_report",
                    output={
                        "status": "partial_success",
                        "report_path": str(report_path),
                        "summary": report["summary"],
                    },
                ),
            ],
            output={
                "unified_report": {
                    "status": "partial_success",
                    "report_path": str(report_path),
                    "summary": report["summary"],
                }
            },
        )

    monkeypatch.setattr(runner.pipeline_engine, "execute_pipeline", fake_execute_pipeline)

    result = runner.run(str(binary_path))

    assert result["status"] == "partial_success"
    assert result["summary"]["stage_statuses"]["recompilation"] == "failed"
    assert result["summary"]["compiled_binaries"] == []
    assert result["unified_report"]["stages"]["recompilation"]["error"] == (
        "compiler feedback loop exhausted"
    )
