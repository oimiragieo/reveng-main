"""REVENG automated analysis pipeline engine.

Automated analysis pipeline with tool chaining, error handling,
and result aggregation.
"""

import asyncio
import threading
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

import yaml

from ..core.errors import (
    PipelineExecutionError,
    create_error_context,
)
from ..core.logger import get_logger


class PipelineStatus(Enum):
    """Pipeline execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StageStatus(Enum):
    """Pipeline stage status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StageType(Enum):
    """Pipeline stage types"""

    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    PE_ANALYSIS = "pe_analysis"
    GHIDRA_ANALYSIS = "ghidra_analysis"
    HEX_ANALYSIS = "hex_analysis"
    MALWARE_ANALYSIS = "malware_analysis"
    ML_ANALYSIS = "ml_analysis"
    REPORT_GENERATION = "report_generation"


@dataclass
class PipelineStage:
    """Pipeline stage definition"""

    name: str
    stage_type: StageType
    tool: str
    config: Dict[str, Any]
    dependencies: List[str]
    timeout: int = 300
    retry_count: int = 3
    required: bool = True


@dataclass
class StageResult:
    """Pipeline stage execution result"""

    stage_name: str
    status: StageStatus
    output: Dict[str, Any]
    error: Optional[str]
    execution_time: float
    retry_count: int


@dataclass
class Pipeline:
    """Pipeline definition"""

    name: str
    description: str
    stages: List[PipelineStage]
    created: str
    version: str = "1.0"


@dataclass
class PipelineResult:
    """Pipeline execution result"""

    pipeline_name: str
    binary_path: str
    status: PipelineStatus
    stage_results: List[StageResult]
    total_execution_time: float
    success_count: int
    failure_count: int
    output: Dict[str, Any]


class AnalysisPipeline:
    """Automated analysis pipeline with tool chaining"""

    def __init__(self):
        self.logger = get_logger("pipeline_engine")
        self.templates_dir = Path(__file__).parent / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        self.pipelines = {}
        self._load_prebuilt_pipelines()

    def create_pipeline(self, name: str, description: str = "") -> Pipeline:
        """Create new analysis pipeline"""
        try:
            pipeline = Pipeline(
                name=name,
                description=description,
                stages=[],
                created=time.strftime("%Y-%m-%d %H:%M:%S"),
            )

            self.pipelines[name] = pipeline
            self.logger.info(f"Created pipeline: {name}")
            return pipeline

        except Exception as e:
            self.logger.error(f"Failed to create pipeline: {e}")
            raise

    def add_stage(self, pipeline: Pipeline, stage: PipelineStage) -> Pipeline:
        """Add analysis stage to pipeline"""
        try:
            pipeline.stages.append(stage)
            self.logger.info(f"Added stage {stage.name} to pipeline {pipeline.name}")
            return pipeline

        except Exception as e:
            self.logger.error(f"Failed to add stage: {e}")
            raise

    def execute_pipeline(self, pipeline: Pipeline, binary_path: str) -> PipelineResult:
        """Execute complete pipeline synchronously."""
        return self._run_coroutine_sync(
            lambda: self.execute_pipeline_async(pipeline, binary_path)
        )

    async def execute_pipeline_async(
        self, pipeline: Pipeline, binary_path: str
    ) -> PipelineResult:
        """Execute complete pipeline asynchronously."""
        try:
            self.logger.info(
                f"Starting pipeline execution: {pipeline.name} on {binary_path}"
            )

            start_time = time.time()
            self._validate_stage_names(pipeline)

            stage_results_by_name: Dict[str, StageResult] = {}
            pending_stages: Dict[str, PipelineStage] = {
                stage.name: stage for stage in pipeline.stages
            }

            while pending_stages:
                ready_stages = self._get_ready_stages(
                    pending_stages, stage_results_by_name
                )

                if not ready_stages:
                    self._mark_unresolved_stages(
                        pending_stages,
                        stage_results_by_name,
                    )
                    break

                executable_stages: List[PipelineStage] = []
                for stage in ready_stages:
                    pending_stages.pop(stage.name, None)
                    blocked_dependencies = self._get_blocked_dependencies(
                        stage,
                        stage_results_by_name,
                    )
                    if blocked_dependencies:
                        error_message = (
                            "Skipped because dependencies did not complete successfully: "
                            + ", ".join(blocked_dependencies)
                        )
                        self.logger.warning(
                            f"Skipping stage {stage.name}: {error_message}"
                        )
                        stage_results_by_name[stage.name] = StageResult(
                            stage_name=stage.name,
                            status=StageStatus.SKIPPED,
                            output={},
                            error=error_message,
                            execution_time=0.0,
                            retry_count=0,
                        )
                        continue

                    executable_stages.append(stage)

                if executable_stages:
                    self.logger.info(
                        "Executing %d ready stage(s) concurrently: %s"
                        % (
                            len(executable_stages),
                            ", ".join(stage.name for stage in executable_stages),
                        )
                    )
                    stage_results = await asyncio.gather(
                        *(
                            self._execute_stage_async(stage, binary_path)
                            for stage in executable_stages
                        ),
                        return_exceptions=True,
                    )

                    for stage, stage_result in zip(executable_stages, stage_results):
                        if isinstance(stage_result, Exception):
                            self.logger.error(
                                "Stage %s raised an unexpected exception but the pipeline will continue: %s"
                                % (stage.name, stage_result)
                            )
                            stage_results_by_name[stage.name] = StageResult(
                                stage_name=stage.name,
                                status=StageStatus.FAILED,
                                output={},
                                error=str(stage_result),
                                execution_time=0.0,
                                retry_count=0,
                            )
                            continue

                        stage_results_by_name[stage.name] = stage_result

            stage_results = [
                stage_results_by_name[stage.name]
                for stage in pipeline.stages
                if stage.name in stage_results_by_name
            ]

            success_count = sum(
                1
                for result in stage_results
                if result.status == StageStatus.COMPLETED
            )
            failure_count = sum(
                1 for result in stage_results if result.status == StageStatus.FAILED
            )

            total_execution_time = time.time() - start_time

            # Determine overall status
            if failure_count == 0:
                status = PipelineStatus.COMPLETED
            elif success_count > 0:
                status = PipelineStatus.COMPLETED  # Partial success
            else:
                status = PipelineStatus.FAILED

            # Aggregate outputs
            output = self._aggregate_stage_outputs(stage_results)

            result = PipelineResult(
                pipeline_name=pipeline.name,
                binary_path=binary_path,
                status=status,
                stage_results=stage_results,
                total_execution_time=total_execution_time,
                success_count=success_count,
                failure_count=failure_count,
                output=output,
            )

            self.logger.info(
                f"Completed pipeline execution: {pipeline.name} in {total_execution_time:.2f} seconds"
            )
            return result

        except Exception as e:
            context = create_error_context(
                "pipeline_engine", "execute_pipeline", binary_path=binary_path
            )
            raise PipelineExecutionError(
                pipeline.name,
                "pipeline_execution",
                context=context,
                original_exception=e,
            )

    def _run_coroutine_sync(
        self,
        coroutine_factory: Callable[[], Awaitable[PipelineResult]],
    ) -> PipelineResult:
        """Run an async pipeline coroutine from synchronous callers."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coroutine_factory())

        result_holder: Dict[str, PipelineResult] = {}
        error_holder: Dict[str, Exception] = {}

        def _runner():
            try:
                result_holder["result"] = asyncio.run(coroutine_factory())
            except Exception as exc:  # pragma: no cover - defensive path
                error_holder["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()

        if "error" in error_holder:
            raise error_holder["error"]

        return result_holder["result"]

    def _validate_stage_names(self, pipeline: Pipeline):
        """Ensure a pipeline does not contain duplicate stage names."""
        stage_names = [stage.name for stage in pipeline.stages]
        duplicates = sorted(
            {name for name in stage_names if stage_names.count(name) > 1}
        )
        if duplicates:
            duplicate_names = ", ".join(duplicates)
            raise ValueError(
                f"Duplicate stage names found in pipeline: {duplicate_names}"
            )

    def _get_ready_stages(
        self,
        pending_stages: Dict[str, PipelineStage],
        stage_results: Dict[str, StageResult],
    ) -> List[PipelineStage]:
        """Return stages whose dependencies have all reached a terminal state."""
        return [
            stage
            for stage in pending_stages.values()
            if all(dependency in stage_results for dependency in stage.dependencies)
        ]

    def _get_blocked_dependencies(
        self,
        stage: PipelineStage,
        stage_results: Dict[str, StageResult],
    ) -> List[str]:
        """Return dependency names that did not complete successfully."""
        return [
            dependency
            for dependency in stage.dependencies
            if stage_results[dependency].status != StageStatus.COMPLETED
        ]

    def _mark_unresolved_stages(
        self,
        pending_stages: Dict[str, PipelineStage],
        stage_results: Dict[str, StageResult],
    ):
        """Fail remaining stages when the DAG can no longer make progress."""
        unresolved_stage_names = ", ".join(pending_stages.keys())
        self.logger.error(
            "Pipeline DAG stalled because remaining stages could not be resolved: %s"
            % unresolved_stage_names
        )

        for stage_name, stage in list(pending_stages.items()):
            missing_dependencies = [
                dependency
                for dependency in stage.dependencies
                if dependency not in stage_results
            ]
            error_message = "Unresolved dependencies or circular dependency detected"
            if missing_dependencies:
                error_message = (
                    f"{error_message}: missing {', '.join(missing_dependencies)}"
                )

            stage_results[stage_name] = StageResult(
                stage_name=stage_name,
                status=StageStatus.FAILED,
                output={},
                error=error_message,
                execution_time=0.0,
                retry_count=0,
            )
            pending_stages.pop(stage_name, None)

    def save_pipeline(self, pipeline: Pipeline, path: str):
        """Save pipeline definition for reuse"""
        try:
            pipeline_data = asdict(pipeline)

            with open(path, "w") as f:
                yaml.dump(pipeline_data, f, default_flow_style=False)

            self.logger.info(f"Saved pipeline to {path}")

        except Exception as e:
            self.logger.error(f"Failed to save pipeline: {e}")
            raise

    def load_pipeline(self, path: str) -> Pipeline:
        """Load saved pipeline"""
        try:
            with open(path, "r") as f:
                pipeline_data = yaml.safe_load(f)

            # Convert dict back to Pipeline object
            pipeline = Pipeline(
                name=pipeline_data["name"],
                description=pipeline_data["description"],
                stages=[PipelineStage(**stage) for stage in pipeline_data["stages"]],
                created=pipeline_data["created"],
                version=pipeline_data.get("version", "1.0"),
            )

            self.logger.info(f"Loaded pipeline from {path}")
            return pipeline

        except Exception as e:
            self.logger.error(f"Failed to load pipeline: {e}")
            raise

    def get_prebuilt_pipeline(self, name: str) -> Optional[Pipeline]:
        """Get prebuilt pipeline by name"""
        return self.pipelines.get(name)

    def list_pipelines(self) -> List[str]:
        """List available pipelines"""
        return list(self.pipelines.keys())

    def _execute_stage(self, stage: PipelineStage, binary_path: str) -> StageResult:
        """Execute a single pipeline stage synchronously."""
        return self._run_coroutine_sync(
            lambda: self._execute_stage_async(stage, binary_path)
        )

    async def _execute_stage_async(
        self, stage: PipelineStage, binary_path: str
    ) -> StageResult:
        """Execute a single pipeline stage asynchronously with retry support."""
        try:
            self.logger.info(f"Executing stage: {stage.name}")

            start_time = time.time()
            retry_count = 0

            while retry_count <= stage.retry_count:
                try:
                    output = await asyncio.wait_for(
                        asyncio.to_thread(
                            self._dispatch_stage_execution,
                            stage,
                            binary_path,
                        ),
                        timeout=stage.timeout,
                    )

                    execution_time = time.time() - start_time
                    return StageResult(
                        stage_name=stage.name,
                        status=StageStatus.COMPLETED,
                        output=output,
                        error=None,
                        execution_time=execution_time,
                        retry_count=retry_count,
                    )

                except Exception as exc:
                    retry_count += 1
                    error_message = (
                        f"Stage timed out after {stage.timeout} seconds"
                        if isinstance(exc, asyncio.TimeoutError)
                        else str(exc)
                    )

                    if retry_count <= stage.retry_count:
                        self.logger.warning(
                            "Stage %s failed, retrying (%s/%s): %s"
                            % (
                                stage.name,
                                retry_count,
                                stage.retry_count,
                                error_message,
                            )
                        )
                        await asyncio.sleep(1)
                    else:
                        self.logger.error(
                            "Stage %s failed after %s attempt(s), isolating "
                            "error and continuing pipeline: %s"
                            % (
                                stage.name,
                                retry_count,
                                error_message,
                            )
                        )
                        execution_time = time.time() - start_time
                        return StageResult(
                            stage_name=stage.name,
                            status=StageStatus.FAILED,
                            output={},
                            error=error_message,
                            execution_time=execution_time,
                            retry_count=retry_count,
                        )

        except Exception as exc:
            self.logger.error(f"Stage execution failed: {exc}")
            return StageResult(
                stage_name=stage.name,
                status=StageStatus.FAILED,
                output={},
                error=str(exc),
                execution_time=0.0,
                retry_count=0,
            )

    def _dispatch_stage_execution(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Dispatch stage execution to the appropriate synchronous executor."""
        if stage.stage_type == StageType.STATIC_ANALYSIS:
            return self._execute_static_analysis(stage, binary_path)
        if stage.stage_type == StageType.PE_ANALYSIS:
            return self._execute_pe_analysis(stage, binary_path)
        if stage.stage_type == StageType.GHIDRA_ANALYSIS:
            return self._execute_ghidra_analysis(stage, binary_path)
        if stage.stage_type == StageType.HEX_ANALYSIS:
            return self._execute_hex_analysis(stage, binary_path)
        if stage.stage_type == StageType.MALWARE_ANALYSIS:
            return self._execute_malware_analysis(stage, binary_path)
        if stage.stage_type == StageType.ML_ANALYSIS:
            return self._execute_ml_analysis(stage, binary_path)
        if stage.stage_type == StageType.REPORT_GENERATION:
            return self._execute_report_generation(stage, binary_path)

        raise ValueError(f"Unknown stage type: {stage.stage_type}")

    def _execute_static_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute static analysis stage"""
        try:
            # Import analyzers
            from ..analyzers.business_logic_extractor import BusinessLogicExtractor
            from ..analyzers.dotnet_analyzer import DotNetAnalyzer

            results = {}

            # .NET analysis
            if stage.config.get("dotnet_analysis", True):
                dotnet_analyzer = DotNetAnalyzer()
                dotnet_result = dotnet_analyzer.analyze_assembly(binary_path)
                results["dotnet_analysis"] = asdict(dotnet_result)

            # Business logic analysis
            if stage.config.get("business_logic_analysis", True):
                business_extractor = BusinessLogicExtractor()
                business_result = business_extractor.analyze_application_domain(
                    binary_path
                )
                results["business_logic"] = asdict(business_result)

            return results

        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}")
            raise

    def _execute_pe_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute PE analysis stage"""
        try:
            # Import PE analyzers
            from ..pe.import_analyzer import ImportAnalyzer
            from ..pe.resource_extractor import PEResourceExtractor

            results = {}

            # Resource extraction
            if stage.config.get("resource_extraction", True):
                resource_extractor = PEResourceExtractor()
                resources = resource_extractor.extract_all_resources(binary_path)
                results["resources"] = asdict(resources)

            # Import analysis
            if stage.config.get("import_analysis", True):
                import_analyzer = ImportAnalyzer()
                imports = import_analyzer.analyze_imports(binary_path)
                results["imports"] = asdict(imports)

            return results

        except Exception as e:
            self.logger.error(f"PE analysis failed: {e}")
            raise

    def _execute_ghidra_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute Ghidra analysis stage"""
        try:
            from ..ghidra.scripting_engine import GhidraScriptingEngine

            ghidra_engine = GhidraScriptingEngine()
            analysis = ghidra_engine.analyze_binary(binary_path)

            return asdict(analysis)

        except Exception as e:
            self.logger.error(f"Ghidra analysis failed: {e}")
            raise

    def _execute_hex_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute hex analysis stage"""
        try:
            from ..tools.hex_editor import HexEditor

            hex_editor = HexEditor()
            analysis = hex_editor.analyze_binary(binary_path)

            return asdict(analysis)

        except Exception as e:
            self.logger.error(f"Hex analysis failed: {e}")
            raise

    def _execute_malware_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute malware analysis stage"""
        try:
            # This would implement malware analysis
            # For now, return placeholder
            return {"malware_analysis": "Not implemented yet", "confidence": 0.0}

        except Exception as e:
            self.logger.error(f"Malware analysis failed: {e}")
            raise

    def _execute_ml_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute ML analysis stage"""
        try:
            # This would implement ML analysis
            # For now, return placeholder
            return {"ml_analysis": "Not implemented yet", "confidence": 0.0}

        except Exception as e:
            self.logger.error(f"ML analysis failed: {e}")
            raise

    def _execute_report_generation(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute report generation stage"""
        try:
            # This would implement report generation
            # For now, return placeholder
            return {
                "report_generation": "Not implemented yet",
                "output_path": "report.html",
            }

        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            raise

    def _aggregate_stage_outputs(
        self, stage_results: List[StageResult]
    ) -> Dict[str, Any]:
        """Aggregate outputs from all stages"""
        try:
            aggregated = {}

            for result in stage_results:
                if result.status == StageStatus.COMPLETED:
                    aggregated[result.stage_name] = result.output

            return aggregated

        except Exception as e:
            self.logger.error(f"Failed to aggregate stage outputs: {e}")
            return {}

    def _load_prebuilt_pipelines(self):
        """Load prebuilt pipeline templates"""
        try:
            # Malware analysis pipeline
            malware_pipeline = Pipeline(
                name="malware_analysis",
                description="Complete malware analysis workflow",
                stages=[
                    PipelineStage(
                        name="static_analysis",
                        stage_type=StageType.STATIC_ANALYSIS,
                        tool="reveng",
                        config={
                            "dotnet_analysis": True,
                            "business_logic_analysis": True,
                        },
                        dependencies=[],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="pe_analysis",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={"resource_extraction": True, "import_analysis": True},
                        dependencies=["static_analysis"],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="hex_analysis",
                        stage_type=StageType.HEX_ANALYSIS,
                        tool="reveng",
                        config={"entropy_analysis": True, "pattern_matching": True},
                        dependencies=["pe_analysis"],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="ghidra_analysis",
                        stage_type=StageType.GHIDRA_ANALYSIS,
                        tool="ghidra",
                        config={"auto_analyze": True, "decompile": True},
                        dependencies=["hex_analysis"],
                        timeout=600,
                    ),
                    PipelineStage(
                        name="malware_analysis",
                        stage_type=StageType.MALWARE_ANALYSIS,
                        tool="reveng",
                        config={"packer_detection": True, "behavioral_analysis": True},
                        dependencies=["ghidra_analysis"],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="report_generation",
                        stage_type=StageType.REPORT_GENERATION,
                        tool="reveng",
                        config={"format": "html", "include_screenshots": True},
                        dependencies=["malware_analysis"],
                        timeout=60,
                    ),
                ],
                created=time.strftime("%Y-%m-%d %H:%M:%S"),
            )

            # .NET analysis pipeline
            dotnet_pipeline = Pipeline(
                name="dotnet_analysis",
                description=".NET application analysis workflow",
                stages=[
                    PipelineStage(
                        name="dotnet_analysis",
                        stage_type=StageType.STATIC_ANALYSIS,
                        tool="reveng",
                        config={"dotnet_analysis": True, "gui_detection": True},
                        dependencies=[],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="pe_resources",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={"resource_extraction": True, "icon_extraction": True},
                        dependencies=["dotnet_analysis"],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="business_logic",
                        stage_type=StageType.STATIC_ANALYSIS,
                        tool="reveng",
                        config={
                            "business_logic_analysis": True,
                            "data_flow_analysis": True,
                        },
                        dependencies=["pe_resources"],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="report_generation",
                        stage_type=StageType.REPORT_GENERATION,
                        tool="reveng",
                        config={"format": "html", "include_resources": True},
                        dependencies=["business_logic"],
                        timeout=60,
                    ),
                ],
                created=time.strftime("%Y-%m-%d %H:%M:%S"),
            )

            # Quick triage pipeline
            triage_pipeline = Pipeline(
                name="quick_triage",
                description="Quick binary triage",
                stages=[
                    PipelineStage(
                        name="static_analysis",
                        stage_type=StageType.STATIC_ANALYSIS,
                        tool="reveng",
                        config={
                            "dotnet_analysis": True,
                            "business_logic_analysis": True,
                        },
                        dependencies=[],
                        timeout=120,
                    ),
                    PipelineStage(
                        name="pe_analysis",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={"import_analysis": True, "resource_extraction": True},
                        dependencies=["static_analysis"],
                        timeout=120,
                    ),
                    PipelineStage(
                        name="hex_analysis",
                        stage_type=StageType.HEX_ANALYSIS,
                        tool="reveng",
                        config={"entropy_analysis": True, "string_extraction": True},
                        dependencies=["pe_analysis"],
                        timeout=120,
                    ),
                ],
                created=time.strftime("%Y-%m-%d %H:%M:%S"),
            )

            # Deep analysis pipeline
            deep_pipeline = Pipeline(
                name="deep_analysis",
                description="Comprehensive deep-dive analysis",
                stages=[
                    PipelineStage(
                        name="static_analysis",
                        stage_type=StageType.STATIC_ANALYSIS,
                        tool="reveng",
                        config={
                            "dotnet_analysis": True,
                            "business_logic_analysis": True,
                        },
                        dependencies=[],
                        timeout=600,
                    ),
                    PipelineStage(
                        name="pe_analysis",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={
                            "resource_extraction": True,
                            "import_analysis": True,
                            "export_analysis": True,
                        },
                        dependencies=["static_analysis"],
                        timeout=600,
                    ),
                    PipelineStage(
                        name="hex_analysis",
                        stage_type=StageType.HEX_ANALYSIS,
                        tool="reveng",
                        config={
                            "entropy_analysis": True,
                            "pattern_matching": True,
                            "embedded_files": True,
                        },
                        dependencies=["pe_analysis"],
                        timeout=600,
                    ),
                    PipelineStage(
                        name="ghidra_analysis",
                        stage_type=StageType.GHIDRA_ANALYSIS,
                        tool="ghidra",
                        config={
                            "auto_analyze": True,
                            "decompile": True,
                            "call_graph": True,
                        },
                        dependencies=["hex_analysis"],
                        timeout=1200,
                    ),
                    PipelineStage(
                        name="ml_analysis",
                        stage_type=StageType.ML_ANALYSIS,
                        tool="reveng",
                        config={"code_reconstruction": True, "anomaly_detection": True},
                        dependencies=["ghidra_analysis"],
                        timeout=600,
                    ),
                    PipelineStage(
                        name="report_generation",
                        stage_type=StageType.REPORT_GENERATION,
                        tool="reveng",
                        config={
                            "format": "html",
                            "include_all": True,
                            "detailed_analysis": True,
                        },
                        dependencies=["ml_analysis"],
                        timeout=120,
                    ),
                ],
                created=time.strftime("%Y-%m-%d %H:%M:%S"),
            )

            # Store pipelines
            self.pipelines = {
                "malware_analysis": malware_pipeline,
                "dotnet_analysis": dotnet_pipeline,
                "quick_triage": triage_pipeline,
                "deep_analysis": deep_pipeline,
            }

            self.logger.info(f"Loaded {len(self.pipelines)} prebuilt pipelines")

        except Exception as e:
            self.logger.error(f"Failed to load prebuilt pipelines: {e}")
            self.pipelines = {}
