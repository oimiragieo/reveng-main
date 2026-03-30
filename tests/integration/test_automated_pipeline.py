"""Integration tests for the current automated analysis pipeline API."""

import sys
from pathlib import Path

import pytest

import reveng.pipelines.automated_analysis as automated_analysis_module
from reveng.core.errors import AnalysisFailureError
from reveng.pipelines.automated_analysis import (
    AnalysisTool,
    AutomatedAnalysisPipeline,
    PipelineStage,
    PipelineStep,
)


def _make_python_step(
    name: str,
    stage: PipelineStage,
    code: str,
    *,
    required: bool = True,
    timeout: int = 30,
) -> PipelineStep:
    """Create a PipelineStep backed by the current Python interpreter."""
    return PipelineStep(
        name=name,
        tool=AnalysisTool.DIE,
        stage=stage,
        command=sys.executable,
        parameters=["-c", code],
        timeout=timeout,
        required=required,
    )


@pytest.fixture
def pipeline(monkeypatch: pytest.MonkeyPatch) -> AutomatedAnalysisPipeline:
    monkeypatch.setattr(
        automated_analysis_module,
        "create_error_context",
        lambda **_: None,
    )
    return AutomatedAnalysisPipeline()


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)
    return binary_path


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "pipeline-output"


class TestAutomatedAnalysisPipeline:
    """Integration coverage for the legacy automated analysis pipeline wrapper."""

    def test_init_loads_prebuilt_templates(self, pipeline: AutomatedAnalysisPipeline):
        assert pipeline is not None
        assert set(pipeline.templates) == {
            "deep_analysis",
            "dotnet_analysis",
            "malware_analysis",
            "quick_triage",
        }

    def test_run_pipeline_executes_custom_steps_and_writes_reports(
        self,
        pipeline: AutomatedAnalysisPipeline,
        sample_binary: Path,
        output_dir: Path,
    ):
        steps = [
            _make_python_step(
                "precheck",
                PipelineStage.PREPROCESSING,
                "from pathlib import Path; import sys; print(Path(sys.argv[-1]).name)",
            ),
            _make_python_step(
                "static_summary",
                PipelineStage.STATIC_ANALYSIS,
                "from pathlib import Path; import sys; print(Path(sys.argv[-1]).suffix)",
            ),
        ]

        result = pipeline.run_pipeline(
            "quick_triage",
            str(sample_binary),
            str(output_dir),
            custom_steps=steps,
        )

        assert result.success is True
        assert result.execution_time >= 0
        assert result.stage_results[PipelineStage.PREPROCESSING]["steps_executed"] == 1
        assert result.stage_results[PipelineStage.STATIC_ANALYSIS]["steps_executed"] == 1
        assert (output_dir / "analysis_report.json").exists()
        assert (output_dir / "analysis_report.html").exists()

    def test_unknown_template_raises_analysis_failure(
        self,
        pipeline: AutomatedAnalysisPipeline,
        sample_binary: Path,
        output_dir: Path,
    ):
        with pytest.raises(AnalysisFailureError):
            pipeline.run_pipeline(
                "missing_template",
                str(sample_binary),
                str(output_dir),
            )

    def test_missing_binary_raises_analysis_failure(
        self, pipeline: AutomatedAnalysisPipeline, output_dir: Path
    ):
        with pytest.raises(AnalysisFailureError):
            pipeline.run_pipeline(
                "quick_triage",
                str(output_dir / "missing.exe"),
                str(output_dir),
            )

    def test_required_step_failure_marks_pipeline_unsuccessful(
        self,
        pipeline: AutomatedAnalysisPipeline,
        sample_binary: Path,
        output_dir: Path,
    ):
        failing_step = PipelineStep(
            name="broken_required_step",
            tool=AnalysisTool.DIE,
            stage=PipelineStage.PREPROCESSING,
            command="definitely-not-a-real-command",
            parameters=[],
            required=True,
        )

        result = pipeline.run_pipeline(
            "quick_triage",
            str(sample_binary),
            str(output_dir),
            custom_steps=[failing_step],
        )

        stage_result = result.stage_results[PipelineStage.PREPROCESSING]
        assert result.success is False
        assert stage_result["steps_failed"] == 1
        assert stage_result["critical_errors"]
        assert result.errors

    def test_optional_step_failure_is_recorded_as_warning(
        self,
        pipeline: AutomatedAnalysisPipeline,
        sample_binary: Path,
        output_dir: Path,
    ):
        steps = [
            _make_python_step(
                "healthy_step",
                PipelineStage.PREPROCESSING,
                "print('ok')",
            ),
            PipelineStep(
                name="optional_failure",
                tool=AnalysisTool.DIE,
                stage=PipelineStage.PREPROCESSING,
                command="definitely-not-a-real-command",
                parameters=[],
                required=False,
            ),
        ]

        result = pipeline.run_pipeline(
            "quick_triage",
            str(sample_binary),
            str(output_dir),
            custom_steps=steps,
        )

        stage_result = result.stage_results[PipelineStage.PREPROCESSING]
        assert result.success is True
        assert stage_result["steps_executed"] == 1
        assert stage_result["steps_failed"] == 1
        assert not stage_result["critical_errors"]
        assert any("Optional step failed" in warning for warning in stage_result["warnings"])

    def test_execute_step_returns_timeout_error(
        self,
        pipeline: AutomatedAnalysisPipeline,
        sample_binary: Path,
        output_dir: Path,
    ):
        step = _make_python_step(
            "sleepy_step",
            PipelineStage.PREPROCESSING,
            "import time; time.sleep(2)",
            timeout=1,
        )
        output_dir.mkdir(parents=True, exist_ok=True)

        result = pipeline._execute_step(step, str(sample_binary), output_dir)

        assert result["success"] is False
        assert "Timeout" in result["error"]

    def test_template_definitions_use_expected_stage_layout(
        self, pipeline: AutomatedAnalysisPipeline
    ):
        quick_triage = pipeline.templates["quick_triage"]
        malware = pipeline.templates["malware_analysis"]

        assert quick_triage.stages == [
            PipelineStage.PREPROCESSING,
            PipelineStage.STATIC_ANALYSIS,
        ]
        assert len(quick_triage.steps) == 3
        assert malware.stages == [
            PipelineStage.PREPROCESSING,
            PipelineStage.STATIC_ANALYSIS,
            PipelineStage.DYNAMIC_ANALYSIS,
        ]
        assert len(malware.steps) >= 6


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
