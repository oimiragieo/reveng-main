"""Tests for asynchronous pipeline execution and failure isolation."""

import time
from pathlib import Path

import pytest

from reveng.pipeline.pipeline_engine import (
    AnalysisPipeline,
    PipelineStatus,
    PipelineStage,
    StageStatus,
    StageType,
)


def _make_stage(
    name: str,
    stage_type: StageType,
    dependencies: list[str] | None = None,
) -> PipelineStage:
    return PipelineStage(
        name=name,
        stage_type=stage_type,
        tool="test",
        config={},
        dependencies=dependencies or [],
        timeout=5,
        retry_count=0,
        required=True,
    )


@pytest.fixture
def test_binary(tmp_path: Path) -> str:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"REVENG")
    return str(binary_path)


@pytest.mark.asyncio
async def test_execute_pipeline_async_runs_stages_concurrently(
    monkeypatch: pytest.MonkeyPatch,
    test_binary: str,
):
    engine = AnalysisPipeline()
    pipeline = engine.create_pipeline("async_test")
    engine.add_stage(
        pipeline,
        _make_stage("branch_a", StageType.STATIC_ANALYSIS),
    )
    engine.add_stage(
        pipeline,
        _make_stage("branch_b", StageType.PE_ANALYSIS),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "report",
            StageType.REPORT_GENERATION,
            dependencies=["branch_a", "branch_b"],
        ),
    )

    start_times: dict[str, float] = {}

    def slow_static(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        start_times[stage.name] = time.perf_counter()
        time.sleep(0.75)
        return {"stage": stage.name, "binary": binary_path}

    def slow_pe(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        start_times[stage.name] = time.perf_counter()
        time.sleep(0.75)
        return {"stage": stage.name, "binary": binary_path}

    def fast_report(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        start_times[stage.name] = time.perf_counter()
        time.sleep(0.05)
        return {"report": binary_path}

    monkeypatch.setattr(
        AnalysisPipeline,
        "_execute_static_analysis",
        slow_static,
    )
    monkeypatch.setattr(AnalysisPipeline, "_execute_pe_analysis", slow_pe)
    monkeypatch.setattr(
        AnalysisPipeline,
        "_execute_report_generation",
        fast_report,
    )

    started_at = time.perf_counter()
    result = await engine.execute_pipeline_async(pipeline, test_binary)
    elapsed = time.perf_counter() - started_at
    expected_sequential_duration = 0.75 + 0.75 + 0.05

    assert result.status == PipelineStatus.COMPLETED
    assert result.success_count == 3
    assert elapsed < expected_sequential_duration - 0.1
    assert (
        abs(start_times["branch_a"] - start_times["branch_b"])
        < 0.1
    )
    assert start_times["report"] >= max(
        start_times["branch_a"],
        start_times["branch_b"],
    )


def test_execute_pipeline_isolates_failed_branch(
    monkeypatch: pytest.MonkeyPatch,
    test_binary: str,
):
    engine = AnalysisPipeline()
    pipeline = engine.create_pipeline("failure_isolation")
    engine.add_stage(
        pipeline,
        _make_stage("healthy_branch", StageType.STATIC_ANALYSIS),
    )
    engine.add_stage(
        pipeline,
        _make_stage("failing_branch", StageType.PE_ANALYSIS),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "skipped_branch",
            StageType.HEX_ANALYSIS,
            dependencies=["failing_branch"],
        ),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "summary_report",
            StageType.REPORT_GENERATION,
            dependencies=["healthy_branch"],
        ),
    )

    executed: list[str] = []

    def healthy_stage(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        executed.append(stage.name)
        return {"stage": stage.name, "binary": binary_path}

    def failing_stage(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        executed.append(stage.name)
        raise RuntimeError("synthetic failure")

    def skipped_stage(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        pytest.fail(
            "Dependent stage should have been skipped after upstream failure"
        )

    def summary_stage(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        executed.append(stage.name)
        return {"summary": binary_path}

    monkeypatch.setattr(
        AnalysisPipeline,
        "_execute_static_analysis",
        healthy_stage,
    )
    monkeypatch.setattr(
        AnalysisPipeline,
        "_execute_pe_analysis",
        failing_stage,
    )
    monkeypatch.setattr(
        AnalysisPipeline,
        "_execute_hex_analysis",
        skipped_stage,
    )
    monkeypatch.setattr(
        AnalysisPipeline,
        "_execute_report_generation",
        summary_stage,
    )

    result = engine.execute_pipeline(pipeline, test_binary)
    stage_results = {
        stage.stage_name: stage for stage in result.stage_results
    }

    assert result.status == PipelineStatus.COMPLETED
    assert result.success_count == 2
    assert result.failure_count == 1
    assert stage_results["healthy_branch"].status == StageStatus.COMPLETED
    assert stage_results["failing_branch"].status == StageStatus.FAILED
    assert stage_results["skipped_branch"].status == StageStatus.SKIPPED
    assert stage_results["summary_report"].status == StageStatus.COMPLETED
    assert "synthetic failure" in (stage_results["failing_branch"].error or "")
    assert executed[:-1] in (
        ["healthy_branch", "failing_branch"],
        ["failing_branch", "healthy_branch"],
    )
    assert executed[-1] == "summary_report"
    assert set(result.output) == {"healthy_branch", "summary_report"}
