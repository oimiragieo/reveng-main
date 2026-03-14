"""Tests for the current async DAG-based AnalysisPipeline API."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest
import yaml

import reveng.pipeline.pipeline_engine as pipeline_engine_module
from reveng.pipeline.pipeline_engine import (
    AnalysisPipeline,
    Pipeline,
    PipelineResult,
    PipelineStage,
    PipelineStatus,
    StageResult,
    StageStatus,
    StageType,
)


def _make_stage(
    name: str,
    stage_type: StageType = StageType.DYNAMIC_ANALYSIS,
    *,
    dependencies: list[str] | None = None,
    timeout: float = 1,
    retry_count: int = 0,
    **config,
) -> PipelineStage:
    return PipelineStage(
        name=name,
        stage_type=stage_type,
        tool="test_tool",
        config=config,
        dependencies=dependencies or [],
        timeout=timeout,
        retry_count=retry_count,
        required=True,
    )


@pytest.fixture
def engine() -> AnalysisPipeline:
    return AnalysisPipeline()


@pytest.fixture
def test_binary(tmp_path: Path) -> str:
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)
    return str(binary_path)


def test_init_loads_templates_dir_and_prebuilt_pipelines(engine: AnalysisPipeline):
    assert engine.logger is not None
    assert engine.templates_dir.exists()
    assert engine.templates_dir.is_dir()
    assert set(engine.pipelines) >= {
        "deep_analysis",
        "dotnet_analysis",
        "malware_analysis",
        "quick_triage",
    }


def test_create_pipeline_registers_pipeline_with_description(engine: AnalysisPipeline):
    pipeline = engine.create_pipeline("custom_pipeline", "Custom DAG pipeline")

    assert isinstance(pipeline, Pipeline)
    assert pipeline.name == "custom_pipeline"
    assert pipeline.description == "Custom DAG pipeline"
    assert pipeline.stages == []
    assert pipeline.created
    assert engine.pipelines["custom_pipeline"] is pipeline


def test_add_stage_appends_pipeline_stage(engine: AnalysisPipeline):
    pipeline = engine.create_pipeline("stage_append")
    stage = _make_stage("dynamic", StageType.DYNAMIC_ANALYSIS, mode="noop")

    updated_pipeline = engine.add_stage(pipeline, stage)

    assert updated_pipeline is pipeline
    assert pipeline.stages == [stage]
    assert pipeline.stages[0].stage_type == StageType.DYNAMIC_ANALYSIS
    assert pipeline.stages[0].config == {"mode": "noop"}


def test_list_pipelines_includes_newly_created_pipeline(engine: AnalysisPipeline):
    engine.create_pipeline("listed_pipeline")

    assert "listed_pipeline" in engine.list_pipelines()


@pytest.mark.parametrize(
    ("pipeline_name", "expected_first_stage", "expected_stage_count"),
    [
        ("malware_analysis", StageType.STATIC_ANALYSIS, 6),
        ("dotnet_analysis", StageType.STATIC_ANALYSIS, 4),
        ("quick_triage", StageType.STATIC_ANALYSIS, 3),
        ("deep_analysis", StageType.STATIC_ANALYSIS, 6),
    ],
)
def test_get_prebuilt_pipeline_returns_expected_templates(
    engine: AnalysisPipeline,
    pipeline_name: str,
    expected_first_stage: StageType,
    expected_stage_count: int,
):
    pipeline = engine.get_prebuilt_pipeline(pipeline_name)

    assert pipeline is not None
    assert pipeline.name == pipeline_name
    assert len(pipeline.stages) == expected_stage_count
    assert pipeline.stages[0].stage_type == expected_first_stage


def test_execute_pipeline_empty_pipeline_returns_completed(
    engine: AnalysisPipeline,
    test_binary: str,
):
    pipeline = engine.create_pipeline("empty_pipeline")

    result = engine.execute_pipeline(pipeline, test_binary)

    assert isinstance(result, PipelineResult)
    assert result.pipeline_name == "empty_pipeline"
    assert result.status == PipelineStatus.COMPLETED
    assert result.stage_results == []
    assert result.success_count == 0
    assert result.failure_count == 0
    assert result.output == {}


def test_execute_pipeline_preserves_pipeline_stage_order(
    monkeypatch: pytest.MonkeyPatch,
    engine: AnalysisPipeline,
    test_binary: str,
):
    pipeline = engine.create_pipeline("ordered_results")
    engine.add_stage(pipeline, _make_stage("slow", StageType.STATIC_ANALYSIS))
    engine.add_stage(pipeline, _make_stage("fast", StageType.PE_ANALYSIS))
    engine.add_stage(
        pipeline,
        _make_stage(
            "report",
            StageType.REPORT_GENERATION,
            dependencies=["slow", "fast"],
        ),
    )

    def slow_stage(self: AnalysisPipeline, stage: PipelineStage, binary_path: str):
        time.sleep(0.05)
        return {"stage": stage.name, "binary_path": binary_path}

    def fast_stage(self: AnalysisPipeline, stage: PipelineStage, binary_path: str):
        return {"stage": stage.name, "binary_path": binary_path}

    monkeypatch.setattr(AnalysisPipeline, "_execute_static_analysis", slow_stage)
    monkeypatch.setattr(AnalysisPipeline, "_execute_pe_analysis", fast_stage)
    monkeypatch.setattr(AnalysisPipeline, "_execute_report_generation", fast_stage)

    result = engine.execute_pipeline(pipeline, test_binary)

    assert [stage.stage_name for stage in result.stage_results] == [
        "slow",
        "fast",
        "report",
    ]


@pytest.mark.asyncio
async def test_execute_pipeline_async_runs_independent_stages_concurrently(
    monkeypatch: pytest.MonkeyPatch,
    engine: AnalysisPipeline,
    test_binary: str,
):
    pipeline = engine.create_pipeline("async_concurrency")
    engine.add_stage(pipeline, _make_stage("branch_a", StageType.STATIC_ANALYSIS))
    engine.add_stage(pipeline, _make_stage("branch_b", StageType.PE_ANALYSIS))
    engine.add_stage(
        pipeline,
        _make_stage(
            "summary",
            StageType.REPORT_GENERATION,
            dependencies=["branch_a", "branch_b"],
        ),
    )

    execution_windows: dict[str, dict[str, float]] = {}

    def slow_static(self: AnalysisPipeline, stage: PipelineStage, binary_path: str):
        execution_windows[stage.name] = {"start": time.perf_counter()}
        try:
            time.sleep(0.2)
            return {"stage": stage.name, "binary_path": binary_path}
        finally:
            execution_windows[stage.name]["end"] = time.perf_counter()

    def slow_pe(self: AnalysisPipeline, stage: PipelineStage, binary_path: str):
        execution_windows[stage.name] = {"start": time.perf_counter()}
        try:
            time.sleep(0.2)
            return {"stage": stage.name, "binary_path": binary_path}
        finally:
            execution_windows[stage.name]["end"] = time.perf_counter()

    def fast_report(self: AnalysisPipeline, stage: PipelineStage, binary_path: str):
        execution_windows[stage.name] = {"start": time.perf_counter()}
        try:
            return {"summary_for": binary_path}
        finally:
            execution_windows[stage.name]["end"] = time.perf_counter()

    monkeypatch.setattr(AnalysisPipeline, "_execute_static_analysis", slow_static)
    monkeypatch.setattr(AnalysisPipeline, "_execute_pe_analysis", slow_pe)
    monkeypatch.setattr(AnalysisPipeline, "_execute_report_generation", fast_report)

    result = await engine.execute_pipeline_async(pipeline, test_binary)

    assert result.status == PipelineStatus.COMPLETED
    assert result.success_count == 3
    assert execution_windows["branch_a"]["start"] < execution_windows["branch_b"]["end"]
    assert execution_windows["branch_b"]["start"] < execution_windows["branch_a"]["end"]
    assert execution_windows["summary"]["start"] >= max(
        execution_windows["branch_a"]["end"],
        execution_windows["branch_b"]["end"],
    )


def test_execute_pipeline_isolates_failed_branch_and_skips_dependents(
    monkeypatch: pytest.MonkeyPatch,
    engine: AnalysisPipeline,
    test_binary: str,
):
    pipeline = engine.create_pipeline("error_isolation")
    engine.add_stage(pipeline, _make_stage("healthy", StageType.STATIC_ANALYSIS))
    engine.add_stage(pipeline, _make_stage("broken", StageType.PE_ANALYSIS))
    engine.add_stage(
        pipeline,
        _make_stage(
            "downstream",
            StageType.HEX_ANALYSIS,
            dependencies=["broken"],
        ),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "summary",
            StageType.REPORT_GENERATION,
            dependencies=["healthy"],
        ),
    )

    def healthy_stage(self: AnalysisPipeline, stage: PipelineStage, binary_path: str):
        return {"stage": stage.name, "binary_path": binary_path}

    def broken_stage(self: AnalysisPipeline, stage: PipelineStage, binary_path: str):
        raise RuntimeError("synthetic branch failure")

    def should_not_run(self: AnalysisPipeline, stage: PipelineStage, binary_path: str):
        pytest.fail("Dependent stage should have been skipped")

    monkeypatch.setattr(AnalysisPipeline, "_execute_static_analysis", healthy_stage)
    monkeypatch.setattr(AnalysisPipeline, "_execute_pe_analysis", broken_stage)
    monkeypatch.setattr(AnalysisPipeline, "_execute_hex_analysis", should_not_run)
    monkeypatch.setattr(AnalysisPipeline, "_execute_report_generation", healthy_stage)

    result = engine.execute_pipeline(pipeline, test_binary)
    stage_results = {stage.stage_name: stage for stage in result.stage_results}

    assert result.status == PipelineStatus.COMPLETED
    assert result.success_count == 2
    assert result.failure_count == 1
    assert stage_results["healthy"].status == StageStatus.COMPLETED
    assert stage_results["broken"].status == StageStatus.FAILED
    assert stage_results["downstream"].status == StageStatus.SKIPPED
    assert stage_results["summary"].status == StageStatus.COMPLETED
    assert "synthetic branch failure" in (stage_results["broken"].error or "")
    assert set(result.output) == {"healthy", "summary"}


def test_execute_pipeline_marks_missing_dependencies_as_failed(
    engine: AnalysisPipeline,
    test_binary: str,
):
    pipeline = engine.create_pipeline("missing_dependency")
    engine.add_stage(
        pipeline,
        _make_stage(
            "blocked_stage",
            StageType.DYNAMIC_ANALYSIS,
            dependencies=["unknown_stage"],
        ),
    )

    result = engine.execute_pipeline(pipeline, test_binary)

    assert result.status == PipelineStatus.FAILED
    assert result.success_count == 0
    assert result.failure_count == 1
    assert result.stage_results[0].status == StageStatus.FAILED
    assert "missing unknown_stage" in (result.stage_results[0].error or "")


def test_execute_pipeline_marks_circular_dependencies_as_failed(
    engine: AnalysisPipeline,
    test_binary: str,
):
    pipeline = engine.create_pipeline("circular_dependency")
    engine.add_stage(
        pipeline,
        _make_stage(
            "stage_a",
            StageType.DYNAMIC_ANALYSIS,
            dependencies=["stage_b"],
        ),
    )
    engine.add_stage(
        pipeline,
        _make_stage(
            "stage_b",
            StageType.DYNAMIC_ANALYSIS,
            dependencies=["stage_a"],
        ),
    )

    result = engine.execute_pipeline(pipeline, test_binary)

    assert result.status == PipelineStatus.FAILED
    assert result.success_count == 0
    assert result.failure_count == 2
    assert all(stage.status == StageStatus.FAILED for stage in result.stage_results)
    assert all(
        "Unresolved dependencies or circular dependency detected" in (stage.error or "")
        for stage in result.stage_results
    )


@pytest.mark.asyncio
async def test_execute_stage_async_retries_until_success(
    monkeypatch: pytest.MonkeyPatch,
    engine: AnalysisPipeline,
    test_binary: str,
):
    stage = _make_stage(
        "retryable",
        StageType.DYNAMIC_ANALYSIS,
        retry_count=2,
    )
    attempts: list[int] = []

    def flaky_dispatch(
        stage: PipelineStage,
        binary_path: str,
        dependency_outputs: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        attempts.append(len(attempts) + 1)
        if len(attempts) < 2:
            raise RuntimeError("try again")
        return {"attempt": len(attempts), "binary_path": binary_path}

    async def immediate_sleep(_seconds: float):
        return None

    monkeypatch.setattr(engine, "_dispatch_stage_execution", flaky_dispatch)
    monkeypatch.setattr(pipeline_engine_module.asyncio, "sleep", immediate_sleep)

    result = await engine._execute_stage_async(stage, test_binary)

    assert result.status == StageStatus.COMPLETED
    assert result.retry_count == 1
    assert result.output == {"attempt": 2, "binary_path": test_binary}
    assert attempts == [1, 2]


@pytest.mark.asyncio
async def test_execute_stage_async_returns_failed_after_timeout(
    monkeypatch: pytest.MonkeyPatch,
    engine: AnalysisPipeline,
    test_binary: str,
):
    stage = _make_stage(
        "timeout_stage",
        StageType.DYNAMIC_ANALYSIS,
        timeout=0.01,
        retry_count=0,
    )

    async def slow_to_thread(*args, **kwargs):
        await asyncio.sleep(0.05)
        return {"unreachable": True}

    monkeypatch.setattr(pipeline_engine_module.asyncio, "to_thread", slow_to_thread)

    result = await engine._execute_stage_async(stage, test_binary)

    assert result.status == StageStatus.FAILED
    assert result.retry_count == 1
    assert result.output == {}
    assert result.error == "Stage timed out after 0.01 seconds"


def test_execute_dynamic_analysis_stage_returns_placeholder_message(
    engine: AnalysisPipeline,
    test_binary: str,
):
    pipeline = engine.create_pipeline("dynamic_placeholder")
    engine.add_stage(pipeline, _make_stage("dynamic", StageType.DYNAMIC_ANALYSIS))

    result = engine.execute_pipeline(pipeline, test_binary)

    assert result.status == PipelineStatus.COMPLETED
    assert result.success_count == 1
    assert result.failure_count == 0
    assert result.stage_results[0].status == StageStatus.COMPLETED
    assert result.stage_results[0].output == {
        "status": "skipped",
        "message": (
            "Dynamic analysis stage is not implemented for this pipeline configuration."
        ),
        "binary_path": test_binary,
    }


def test_dispatch_stage_execution_exposes_dependency_context_and_clears_afterwards(
    monkeypatch: pytest.MonkeyPatch,
    engine: AnalysisPipeline,
    test_binary: str,
):
    stage = _make_stage(
        "context_stage",
        StageType.STATIC_ANALYSIS,
        dependencies=["upstream"],
        option=True,
    )

    def inspect_context(
        self: AnalysisPipeline,
        stage: PipelineStage,
        binary_path: str,
    ) -> dict[str, object]:
        return {"context": dict(self._get_stage_context())}

    monkeypatch.setattr(AnalysisPipeline, "_execute_static_analysis", inspect_context)

    result = engine._dispatch_stage_execution(
        stage,
        test_binary,
        {"upstream": {"status": "success"}},
    )

    assert result["context"] == {
        "binary_path": test_binary,
        "stage_name": "context_stage",
        "stage_type": StageType.STATIC_ANALYSIS.value,
        "stage_config": {"option": True},
        "dependencies": {"upstream": {"status": "success"}},
    }
    assert engine._get_stage_context() == {}


def test_aggregate_stage_outputs_only_includes_completed_results(
    engine: AnalysisPipeline,
):
    stage_results = [
        StageResult(
            stage_name="completed_stage",
            status=StageStatus.COMPLETED,
            output={"value": 1},
            error=None,
            execution_time=0.01,
            retry_count=0,
        ),
        StageResult(
            stage_name="failed_stage",
            status=StageStatus.FAILED,
            output={"value": 2},
            error="boom",
            execution_time=0.02,
            retry_count=1,
        ),
        StageResult(
            stage_name="skipped_stage",
            status=StageStatus.SKIPPED,
            output={"value": 3},
            error="blocked",
            execution_time=0.0,
            retry_count=0,
        ),
    ]

    assert engine._aggregate_stage_outputs(stage_results) == {
        "completed_stage": {"value": 1}
    }


def test_select_analysis_target_prefers_recompiled_binary(
    engine: AnalysisPipeline,
    test_binary: str,
):
    engine._stage_context_local.current = {
        "dependencies": {
            "recompilation": {
                "compiled_binaries": {"c_gcc": "recompiled.exe"}
            }
        }
    }

    try:
        assert engine._select_analysis_target(test_binary) == "recompiled.exe"
    finally:
        engine._stage_context_local.current = {}


def test_resolve_output_dir_uses_configured_parent_directory(
    engine: AnalysisPipeline,
    tmp_path: Path,
    test_binary: str,
):
    configured_output = tmp_path / "custom_analysis"
    stage = _make_stage(
        "reporting",
        StageType.REPORT_GENERATION,
        output_dir=str(configured_output),
    )

    output_dir = engine._resolve_output_dir(stage, test_binary, "reports")

    assert output_dir == configured_output / "reports"
    assert output_dir.exists()
    assert output_dir.is_dir()


def test_build_stage_report_writes_utf8_json(
    engine: AnalysisPipeline,
    tmp_path: Path,
):
    report_path = tmp_path / "report.json"
    report = {
        "summary": {"overall_status": "success", "title": "Résumé"},
        "details": {"message": "pipeline complete"},
    }

    payload = engine._build_stage_report(report, report_path)

    assert payload == {
        "status": "success",
        "report_path": str(report_path),
        "summary": report["summary"],
    }
    assert json.loads(report_path.read_text(encoding="utf-8")) == report


def test_save_and_load_pipeline_roundtrip_preserves_stage_fields(
    engine: AnalysisPipeline,
    tmp_path: Path,
):
    pipeline_path = tmp_path / "pipeline.yaml"
    original_pipeline = Pipeline(
        name="yaml_round_trip",
        description="Verify YAML stage enum serialization",
        stages=[
            PipelineStage(
                name="static_stage",
                stage_type=StageType.STATIC_ANALYSIS,
                tool="reveng",
                config={"enabled": True, "threshold": 3},
                dependencies=[],
                timeout=123,
                retry_count=2,
                required=True,
            ),
            PipelineStage(
                name="report_stage",
                stage_type=StageType.REPORT_GENERATION,
                tool="reporter",
                config={"formats": ["json", "html"]},
                dependencies=["static_stage"],
                timeout=45,
                retry_count=1,
                required=False,
            ),
        ],
        created="2026-03-14 00:00:00",
        version="2.0",
    )

    engine.save_pipeline(original_pipeline, str(pipeline_path))

    serialized_pipeline = yaml.safe_load(
        pipeline_path.read_text(encoding="utf-8")
    )
    assert serialized_pipeline["stages"][0]["stage_type"] == StageType.STATIC_ANALYSIS.value
    assert serialized_pipeline["stages"][1]["stage_type"] == StageType.REPORT_GENERATION.value

    loaded_pipeline = engine.load_pipeline(str(pipeline_path))

    assert loaded_pipeline == original_pipeline
