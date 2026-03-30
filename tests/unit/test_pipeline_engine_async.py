"""Tests for asynchronous pipeline execution and failure isolation."""

import asyncio
import time
from pathlib import Path

import pytest

import reveng.pipeline.pipeline_engine as pipeline_engine_module
from reveng.pipeline.pipeline_engine import (
    AnalysisPipeline,
    PipelineStage,
    PipelineStatus,
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

    execution_windows: dict[str, dict[str, float]] = {}

    def slow_static(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        execution_windows[stage.name] = {"start": time.perf_counter()}
        try:
            time.sleep(0.75)
            return {"stage": stage.name, "binary": binary_path}
        finally:
            execution_windows[stage.name]["end"] = time.perf_counter()

    def slow_pe(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        execution_windows[stage.name] = {"start": time.perf_counter()}
        try:
            time.sleep(0.75)
            return {"stage": stage.name, "binary": binary_path}
        finally:
            execution_windows[stage.name]["end"] = time.perf_counter()

    def fast_report(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ):
        execution_windows[stage.name] = {"start": time.perf_counter()}
        try:
            time.sleep(0.05)
            return {"report": binary_path}
        finally:
            execution_windows[stage.name]["end"] = time.perf_counter()

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

    result = await engine.execute_pipeline_async(pipeline, test_binary)
    branch_a_window = execution_windows["branch_a"]
    branch_b_window = execution_windows["branch_b"]
    report_window = execution_windows["report"]

    assert result.status == PipelineStatus.COMPLETED
    assert result.success_count == 3
    assert branch_a_window["start"] < branch_b_window["end"]
    assert branch_b_window["start"] < branch_a_window["end"]
    assert report_window["start"] >= max(
        branch_a_window["end"],
        branch_b_window["end"],
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
        pytest.fail("Dependent stage should have been skipped after upstream failure")

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
    stage_results = {stage.stage_name: stage for stage in result.stage_results}

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


def test_execute_pipeline_supports_dynamic_analysis_stage(
    test_binary: str,
):
    engine = AnalysisPipeline()
    pipeline = engine.create_pipeline("dynamic_stage")
    engine.add_stage(
        pipeline,
        _make_stage("dynamic_branch", StageType.DYNAMIC_ANALYSIS),
    )

    result = engine.execute_pipeline(pipeline, test_binary)

    assert result.status == PipelineStatus.COMPLETED
    assert result.success_count == 1
    assert result.failure_count == 0
    assert result.stage_results[0].status == StageStatus.COMPLETED
    assert result.stage_results[0].output == {
        "status": "skipped",
        "message": (
            "Dynamic analysis stage is not implemented for this " "pipeline configuration."
        ),
        "binary_path": test_binary,
    }


@pytest.mark.parametrize(
    ("stage_type", "expected_message", "expected_extra_key", "expected_extra_value"),
    [
        (
            StageType.MALWARE_ANALYSIS,
            "Malware analysis stage is not implemented for this pipeline configuration.",
            "mode",
            "default",
        ),
        (
            StageType.ML_ANALYSIS,
            "ML analysis stage is not implemented for this pipeline configuration.",
            "mode",
            "default",
        ),
        (
            StageType.REPORT_GENERATION,
            "Report generation stage is not implemented for this pipeline configuration.",
            "format",
            "json",
        ),
    ],
)
def test_optional_stage_defaults_return_skipped_payloads(
    test_binary: str,
    stage_type: StageType,
    expected_message: str,
    expected_extra_key: str,
    expected_extra_value: str,
):
    engine = AnalysisPipeline()
    pipeline = engine.create_pipeline(f"placeholder_{stage_type.value}")
    engine.add_stage(pipeline, _make_stage(stage_type.value, stage_type))

    result = engine.execute_pipeline(pipeline, test_binary)

    assert result.status == PipelineStatus.COMPLETED
    assert result.success_count == 1
    assert result.failure_count == 0
    assert result.stage_results[0].status == StageStatus.COMPLETED
    assert result.stage_results[0].output == {
        "status": "skipped",
        "message": expected_message,
        "binary_path": test_binary,
        expected_extra_key: expected_extra_value,
    }


def test_run_coroutine_sync_times_out_when_thread_hangs(
    monkeypatch: pytest.MonkeyPatch,
):
    engine = AnalysisPipeline()

    class FakeThread:
        latest_instance = None

        def __init__(self, target=None, daemon=None):
            self.target = target
            self.daemon = daemon
            self.join_timeout = None
            FakeThread.latest_instance = self

        def start(self):
            return None

        def join(self, timeout=None):
            self.join_timeout = timeout

        def is_alive(self):
            return True

    warnings: list[str] = []

    monkeypatch.setattr(
        pipeline_engine_module.asyncio,
        "get_running_loop",
        lambda: object(),
    )
    monkeypatch.setattr(
        pipeline_engine_module.threading,
        "Thread",
        FakeThread,
    )
    monkeypatch.setattr(
        engine.logger,
        "warning",
        lambda message, *args: warnings.append(message % args),
    )

    with pytest.raises(TimeoutError, match="30"):
        engine._run_coroutine_sync(lambda: asyncio.sleep(0))

    assert FakeThread.latest_instance is not None
    assert FakeThread.latest_instance.join_timeout == 30
    assert warnings == [
        "Timed out after 30 seconds waiting for pipeline coroutine thread to finish."
    ]
