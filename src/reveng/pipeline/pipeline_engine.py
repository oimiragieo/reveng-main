"""REVENG automated analysis pipeline engine.

Automated analysis pipeline with tool chaining, error handling,
and result aggregation.
"""

import asyncio
import json
import threading
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, TypeVar, cast

import yaml

from ..core.errors import (
    PipelineExecutionError,
    create_error_context,
)
from ..core.logger import get_logger


TResult = TypeVar("TResult")
SYNC_COROUTINE_THREAD_TIMEOUT_SECONDS = 30


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
    RECOMPILATION = "recompilation"
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
        self.pipelines: Dict[str, Pipeline] = {}
        self._stage_context_local = threading.local()
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
            self.logger.info(
                f"Added stage {stage.name} to pipeline {pipeline.name}"
            )
            return pipeline

        except Exception as e:
            self.logger.error(f"Failed to add stage: {e}")
            raise

    def execute_pipeline(
        self, pipeline: Pipeline, binary_path: str
    ) -> PipelineResult:
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
                (
                    f"Starting pipeline execution: {pipeline.name} "
                    f"on {binary_path}"
                )
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
                            (
                                "Skipped because dependencies did not "
                                "complete successfully: "
                            )
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
                    stage_dependency_outputs = {
                        stage.name: {
                            dependency: stage_results_by_name[dependency].output
                            for dependency in stage.dependencies
                            if dependency in stage_results_by_name
                        }
                        for stage in executable_stages
                    }
                    self.logger.info(
                        "Executing %d ready stage(s) concurrently: %s"
                        % (
                            len(executable_stages),
                            ", ".join(
                                stage.name for stage in executable_stages
                            ),
                        )
                    )
                    raw_stage_results = await asyncio.gather(
                        *(
                            self._execute_stage_async(
                                stage,
                                binary_path,
                                stage_dependency_outputs.get(stage.name, {}),
                            )
                            for stage in executable_stages
                        ),
                        return_exceptions=True,
                    )

                    for stage, stage_result in zip(
                        executable_stages, raw_stage_results
                    ):
                        if isinstance(stage_result, Exception):
                            self.logger.error(
                                (
                                    "Stage %s raised an unexpected "
                                    "exception but the pipeline will "
                                    "continue: %s"
                                )
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

                        stage_results_by_name[stage.name] = cast(StageResult, stage_result)

            stage_results: List[StageResult] = [
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
                1
                for result in stage_results
                if result.status == StageStatus.FAILED
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
                (
                    f"Completed pipeline execution: {pipeline.name} in "
                    f"{total_execution_time:.2f} seconds"
                )
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
        coroutine_factory: Callable[[], Coroutine[Any, Any, TResult]],
    ) -> TResult:
        """Run an async pipeline coroutine from synchronous callers."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coroutine_factory())

        result_holder: Dict[str, TResult] = {}
        error_holder: Dict[str, Exception] = {}

        def _runner():
            try:
                result_holder["result"] = asyncio.run(coroutine_factory())
            except Exception as exc:  # pragma: no cover - defensive path
                error_holder["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join(timeout=SYNC_COROUTINE_THREAD_TIMEOUT_SECONDS)

        if thread.is_alive():
            self.logger.warning(
                "Timed out after %d seconds waiting for pipeline coroutine thread to finish.",
                SYNC_COROUTINE_THREAD_TIMEOUT_SECONDS,
            )
            raise TimeoutError(
                "Timed out after "
                f"{SYNC_COROUTINE_THREAD_TIMEOUT_SECONDS} seconds waiting for pipeline coroutine thread to finish."
            )

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
        """Return stages whose dependencies have reached a terminal state."""
        return [
            stage
            for stage in pending_stages.values()
            if all(
                dependency in stage_results
                for dependency in stage.dependencies
            )
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
            (
                "Pipeline DAG stalled because remaining stages could not "
                "be resolved: %s"
            )
            % unresolved_stage_names
        )

        for stage_name, stage in list(pending_stages.items()):
            missing_dependencies = [
                dependency
                for dependency in stage.dependencies
                if dependency not in stage_results
            ]
            error_message = (
                "Unresolved dependencies or circular dependency detected"
            )
            if missing_dependencies:
                error_message = (
                    f"{error_message}: missing "
                    f"{', '.join(missing_dependencies)}"
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
            pipeline_data = {
                **asdict(pipeline),
                "stages": [
                    {
                        **asdict(stage),
                        "stage_type": stage.stage_type.value,
                    }
                    for stage in pipeline.stages
                ],
            }

            with open(path, "w", encoding="utf-8") as f:
                yaml.safe_dump(
                    pipeline_data,
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                )

            self.logger.info(f"Saved pipeline to {path}")

        except Exception as e:
            self.logger.error(f"Failed to save pipeline: {e}")
            raise

    def load_pipeline(self, path: str) -> Pipeline:
        """Load saved pipeline"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                pipeline_data = yaml.safe_load(f)

            # Convert dict back to Pipeline object
            pipeline = Pipeline(
                name=pipeline_data["name"],
                description=pipeline_data["description"],
                stages=[
                    PipelineStage(
                        **{
                            **stage,
                            "stage_type": StageType(stage["stage_type"]),
                        }
                    )
                    for stage in pipeline_data["stages"]
                ],
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

    def _execute_stage(
        self, stage: PipelineStage, binary_path: str
    ) -> StageResult:
        """Execute a single pipeline stage synchronously."""
        return self._run_coroutine_sync(
            lambda: self._execute_stage_async(stage, binary_path)
        )

    async def _execute_stage_async(
        self,
        stage: PipelineStage,
        binary_path: str,
        dependency_outputs: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> StageResult:
        """Execute one pipeline stage asynchronously with retry support."""
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
                            dependency_outputs or {},
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

        return StageResult(
            stage_name=stage.name,
            status=StageStatus.FAILED,
            output={},
            error="Stage execution exited without a result",
            execution_time=0.0,
            retry_count=0,
        )

    def _dispatch_stage_execution(
        self,
        stage: PipelineStage,
        binary_path: str,
        dependency_outputs: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Dispatch stage execution to the appropriate synchronous executor."""
        stage_context = {
            "binary_path": binary_path,
            "stage_name": stage.name,
            "stage_type": stage.stage_type.value,
            "stage_config": dict(stage.config),
            "dependencies": dependency_outputs or {},
        }
        self._stage_context_local.current = stage_context

        try:
            if stage.stage_type == StageType.STATIC_ANALYSIS:
                return self._execute_static_analysis(stage, binary_path)
            if stage.stage_type == StageType.DYNAMIC_ANALYSIS:
                return self._execute_dynamic_analysis(stage, binary_path)
            if stage.stage_type == StageType.RECOMPILATION:
                return self._execute_recompilation(stage, binary_path)
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
        finally:
            self._stage_context_local.current = {}

    def _get_stage_context(self) -> Dict[str, Any]:
        """Return the current stage execution context."""
        return getattr(self._stage_context_local, "current", {})

    def _resolve_output_dir(
        self,
        stage: PipelineStage,
        binary_path: str,
        default_name: str = "analysis_output",
    ) -> Path:
        """Resolve the output directory for a stage."""
        configured_output = stage.config.get("output_dir")
        if configured_output:
            output_dir = Path(configured_output)
        else:
            output_dir = Path(binary_path).parent / f"analysis_{Path(binary_path).stem}"

        output_dir.mkdir(parents=True, exist_ok=True)
        stage_output_dir = output_dir / default_name
        stage_output_dir.mkdir(parents=True, exist_ok=True)
        return stage_output_dir

    def _candidate_ghidra_urls(self, preferred_url: Optional[str] = None) -> List[str]:
        """Return candidate Ghidra server URLs in priority order."""
        candidates = [
            preferred_url,
            "http://127.0.0.1:5000",
            "http://127.0.0.1:13370",
        ]
        ordered_candidates: List[str] = []
        for candidate in candidates:
            if candidate and candidate not in ordered_candidates:
                ordered_candidates.append(candidate)
        return ordered_candidates

    def _select_analysis_target(self, binary_path: str) -> str:
        """Select the most useful artifact for downstream forensics stages."""
        stage_context = self._get_stage_context()
        recompilation_output = stage_context.get("dependencies", {}).get("recompilation", {})
        compiled_binaries = recompilation_output.get("compiled_binaries", {})

        if isinstance(compiled_binaries, dict):
            for compiled_binary in compiled_binaries.values():
                if compiled_binary:
                    return str(compiled_binary)

        return binary_path

    def _build_stage_report(self, report: Dict[str, Any], report_path: Path) -> Dict[str, Any]:
        """Persist a report and return a standard report payload."""
        with open(report_path, "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2, default=str)

        return {
            "status": report["summary"]["overall_status"],
            "report_path": str(report_path),
            "summary": report["summary"],
        }

    def _execute_dynamic_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute dynamic analysis stage."""
        return {
            "status": "skipped",
            "message": "Dynamic analysis stage is not implemented for this pipeline configuration.",
            "binary_path": binary_path,
        }

    def _execute_recompilation(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute the binary recompilation engine for end-to-end CLI flows."""
        output_dir = self._resolve_output_dir(stage, binary_path, "recompilation")
        stage_context = self._get_stage_context()
        ghidra_output = stage_context.get("dependencies", {}).get("ghidra_analysis", {})
        cached_analysis = ghidra_output.get("analysis_data")

        class _CachedGhidraEngine:
            def __init__(self, analysis_data: Dict[str, Any]):
                self.analysis_data = analysis_data

            def analyze_binary(self, target_binary_path: str) -> Dict[str, Any]:
                return self.analysis_data

        try:
            from ..ai.recompilation_engine import BinaryRecompilationEngine
        except ImportError as exc:
            return {
                "status": "failed",
                "error": str(exc),
                "output_dir": str(output_dir),
                "compiled_binaries": {},
                "compilation_reports": {},
                "source_files": {},
            }

        ghidra_engine = _CachedGhidraEngine(cached_analysis) if cached_analysis else None

        gemini_engine = None
        if stage.config.get("use_gemini", False):
            try:
                from ..ai.gemini_engine import GeminiEngine

                gemini_engine = GeminiEngine()
            except Exception as exc:  # pragma: no cover - defensive path
                self.logger.warning("Gemini engine unavailable for recompilation stage: %s", exc)

        try:
            recompilation_engine = BinaryRecompilationEngine(
                ghidra_engine=ghidra_engine,
                gemini_engine=gemini_engine,
                work_dir=output_dir,
                max_compilation_retries=int(stage.config.get("max_compilation_retries", 2)),
            )
            recompilation_result = asyncio.run(
                recompilation_engine.full_reconstruction_pipeline(
                    binary_path,
                    output_dir=output_dir,
                )
            )
        except Exception as exc:
            return {
                "status": "failed",
                "error": str(exc),
                "output_dir": str(output_dir),
                "compiled_binaries": {},
                "compilation_reports": {},
                "source_files": {},
                "cfg_summary": (cached_analysis or {}).get("cfg_summary", {}),
            }

        return {
            "status": recompilation_result.get("status", "failed"),
            "output_dir": str(output_dir),
            "source_files": recompilation_result.get("source_files", {}),
            "compiled_binaries": recompilation_result.get("compiled_binaries", {}),
            "compilation_reports": recompilation_result.get("compilation_reports", {}),
            "cfg_summary": recompilation_result.get(
                "cfg_summary", (cached_analysis or {}).get("cfg_summary", {})
            ),
            "validation_results": recompilation_result.get("validation_results", {}),
            "vulnerabilities": recompilation_result.get("vulnerabilities", []),
            "exploits": recompilation_result.get("exploits", []),
            "error": recompilation_result.get("error"),
        }

    def _execute_static_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute static analysis stage"""
        try:
            # Import analyzers
            from ..analyzers.business_logic_extractor import (
                BusinessLogicExtractor,
            )
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
                business_result = (
                    business_extractor.analyze_application_domain(
                        binary_path
                    )
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
                resources = resource_extractor.extract_all_resources(
                    binary_path
                )
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
        if stage.config.get("mode") == "e2e_disassembly":
            output_dir = self._resolve_output_dir(stage, binary_path, "ghidra_analysis")
            analysis_path = output_dir / "ghidra_analysis.json"

            try:
                from ..integrations.ghidra.ghidra_engine import GhidraEngine
            except ImportError:
                GhidraEngine = None  # type: ignore[assignment]

            ghidra_errors: List[str] = []
            if GhidraEngine is not None:
                for ghidra_url in self._candidate_ghidra_urls(stage.config.get("ghidra_url")):
                    try:
                        ghidra_engine = GhidraEngine(
                            server_url=ghidra_url,
                            timeout=stage.timeout,
                            fail_fast=True,
                        )
                        analysis_data = ghidra_engine.analyze_binary(binary_path)
                        with open(analysis_path, "w", encoding="utf-8") as analysis_file:
                            json.dump(analysis_data, analysis_file, indent=2, default=str)

                        return {
                            "status": "success",
                            "backend": "ghidra_server",
                            "ghidra_url": ghidra_url,
                            "analysis_data": analysis_data,
                            "summary": {
                                "functions": len(analysis_data.get("functions", [])),
                                "imports": len(analysis_data.get("imports", [])),
                                "strings": len(analysis_data.get("strings", [])),
                            },
                            "report_path": str(analysis_path),
                        }
                    except Exception as exc:
                        ghidra_errors.append(f"{ghidra_url}: {exc}")

            try:
                from ..integrations.local_disassembler import get_local_disassembler

                local_disassembler = get_local_disassembler()
                if local_disassembler is not None:
                    local_result = local_disassembler.analyze_binary(binary_path)
                    if local_result.success:
                        analysis_data = local_disassembler.to_ghidra_format(local_result)
                        with open(analysis_path, "w", encoding="utf-8") as analysis_file:
                            json.dump(analysis_data, analysis_file, indent=2, default=str)

                        return {
                            "status": "partial_success",
                            "backend": "local_capstone",
                            "analysis_data": analysis_data,
                            "summary": {
                                "functions": len(analysis_data.get("functions", [])),
                                "imports": len(analysis_data.get("imports", [])),
                                "strings": len(analysis_data.get("strings", [])),
                            },
                            "warning": analysis_data.get("warning"),
                            "report_path": str(analysis_path),
                            "errors": ghidra_errors,
                        }
            except Exception as exc:
                ghidra_errors.append(f"local_disassembler: {exc}")

            return {
                "status": "failed",
                "backend": "unavailable",
                "analysis_data": {},
                "summary": {"functions": 0, "imports": 0, "strings": 0},
                "report_path": str(analysis_path),
                "errors": ghidra_errors,
            }

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
        if stage.config.get("mode") == "behavioral_forensics":
            output_dir = self._resolve_output_dir(stage, binary_path, "behavioral_forensics")
            report_path = output_dir / "behavioral_profile.json"
            analysis_target = self._select_analysis_target(binary_path)

            try:
                from ..malware.behavioral_monitor import BehavioralMonitor

                behavioral_monitor = BehavioralMonitor()
                monitor_duration = max(1, int(stage.config.get("duration_seconds", 1)))

                if not behavioral_monitor.start_monitoring(analysis_target, duration=monitor_duration):
                    return {
                        "status": "failed",
                        "analyzed_binary": analysis_target,
                        "report_path": str(report_path),
                        "error": "Behavioral monitoring could not be started.",
                    }

                time.sleep(max(1.1, float(monitor_duration)))
                profile = behavioral_monitor.stop_monitoring()
                if profile is None:
                    return {
                        "status": "failed",
                        "analyzed_binary": analysis_target,
                        "report_path": str(report_path),
                        "error": "Behavioral monitoring did not produce a profile.",
                    }

                profile.binary_path = analysis_target
                behavioral_monitor.save_behavioral_profile(profile, str(report_path))

                return {
                    "status": "success",
                    "analyzed_binary": analysis_target,
                    "risk_score": profile.risk_score,
                    "threat_level": profile.threat_level.value,
                    "anomaly_score": profile.anomaly_score,
                    "anomaly_threshold": profile.anomaly_threshold,
                    "anomaly_flags": profile.anomaly_flags,
                    "sandbox_available": profile.sandbox_available,
                    "analysis_mode": profile.analysis_mode,
                    "report_path": str(report_path),
                }
            except Exception as exc:
                return {
                    "status": "failed",
                    "analyzed_binary": analysis_target,
                    "report_path": str(report_path),
                    "error": str(exc),
                }

        try:
            # This would implement malware analysis
            # For now, return placeholder
            return {
                "malware_analysis": "Not implemented yet",
                "confidence": 0.0,
            }

        except Exception as e:
            self.logger.error(f"Malware analysis failed: {e}")
            raise

    def _execute_ml_analysis(
        self, stage: PipelineStage, binary_path: str
    ) -> Dict[str, Any]:
        """Execute ML analysis stage"""
        if stage.config.get("mode") == "memory_forensics":
            output_dir = self._resolve_output_dir(stage, binary_path, "memory_forensics")
            report_path = output_dir / "memory_analysis.json"
            analysis_target = self._select_analysis_target(binary_path)

            try:
                from ..malware.memory_forensics import MemoryForensics

                memory_forensics = MemoryForensics()
                analysis = memory_forensics.analyze_memory(analysis_target, str(output_dir))

                return {
                    "status": "success",
                    "analyzed_binary": analysis_target,
                    "total_processes": analysis.total_processes,
                    "total_memory_regions": analysis.total_memory_regions,
                    "total_artifacts": analysis.total_artifacts,
                    "risk_score": analysis.risk_score,
                    "threat_level": analysis.threat_level,
                    "anomaly_score": analysis.anomaly_score,
                    "anomaly_threshold": analysis.anomaly_threshold,
                    "anomaly_flags": analysis.anomaly_flags,
                    "report_path": str(report_path),
                }
            except Exception as exc:
                return {
                    "status": "failed",
                    "analyzed_binary": analysis_target,
                    "report_path": str(report_path),
                    "error": str(exc),
                }

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
        if stage.config.get("mode") == "unified_e2e_report":
            output_dir = self._resolve_output_dir(stage, binary_path, "reports")
            report_path = output_dir / "unified_analysis_report.json"
            stage_context = self._get_stage_context()
            dependency_outputs = stage_context.get("dependencies", {})

            ghidra_output = dependency_outputs.get("ghidra_analysis", {})
            recompilation_output = dependency_outputs.get("recompilation", {})
            behavioral_output = dependency_outputs.get("behavioral_forensics", {})
            memory_output = dependency_outputs.get("memory_forensics", {})

            compiled_binaries = list((recompilation_output.get("compiled_binaries") or {}).values())
            stage_statuses = {
                stage_name: stage_output.get("status", "unknown")
                for stage_name, stage_output in dependency_outputs.items()
            }
            overall_status = (
                "success"
                if all(status == "success" for status in stage_statuses.values())
                else "partial_success"
            )
            if not dependency_outputs:
                overall_status = "failed"

            yara_matches = []
            malware_classification = {}
            try:
                from reveng.security.yara_scanner import YARAScanner

                yara_enrichment = YARAScanner().enrich_analysis({}, file_path=binary_path)
                yara_matches = yara_enrichment.get("yara_matches", [])
                malware_classification = yara_enrichment.get("malware_classification", {})
            except Exception as exc:
                yara_matches = []
                malware_classification = {
                    "family": "YARA unavailable",
                    "confidence": 0.0,
                    "matched_rules": [],
                    "indicators": [str(exc)],
                }

            report = {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "binary_path": binary_path,
                "analysis_folder": str(output_dir.parent),
                "summary": {
                    "overall_status": overall_status,
                    "stage_statuses": stage_statuses,
                    "ghidra_backend": ghidra_output.get("backend"),
                    "functions_detected": len(
                        (ghidra_output.get("analysis_data") or {}).get("functions", [])
                    ),
                    "compiled_binaries": compiled_binaries,
                    "behavioral_anomaly_score": behavioral_output.get("anomaly_score"),
                    "behavioral_threat_level": behavioral_output.get("threat_level"),
                    "memory_anomaly_score": memory_output.get("anomaly_score"),
                    "memory_threat_level": memory_output.get("threat_level"),
                    "yara_match_count": len(yara_matches),
                    "malware_family": malware_classification.get("family"),
                    "malware_confidence": malware_classification.get("confidence"),
                },
                "yara_matches": yara_matches,
                "malware_classification": malware_classification,
                "stages": dependency_outputs,
            }

            return self._build_stage_report(report, report_path)

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
                        config={
                            "resource_extraction": True,
                            "import_analysis": True,
                        },
                        dependencies=["static_analysis"],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="hex_analysis",
                        stage_type=StageType.HEX_ANALYSIS,
                        tool="reveng",
                        config={
                            "entropy_analysis": True,
                            "pattern_matching": True,
                        },
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
                        config={
                            "packer_detection": True,
                            "behavioral_analysis": True,
                        },
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
                        config={
                            "dotnet_analysis": True,
                            "gui_detection": True,
                        },
                        dependencies=[],
                        timeout=300,
                    ),
                    PipelineStage(
                        name="pe_resources",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={
                            "resource_extraction": True,
                            "icon_extraction": True,
                        },
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
                        config={
                            "import_analysis": True,
                            "resource_extraction": True,
                        },
                        dependencies=["static_analysis"],
                        timeout=120,
                    ),
                    PipelineStage(
                        name="hex_analysis",
                        stage_type=StageType.HEX_ANALYSIS,
                        tool="reveng",
                        config={
                            "entropy_analysis": True,
                            "string_extraction": True,
                        },
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
                        config={
                            "code_reconstruction": True,
                            "anomaly_detection": True,
                        },
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

            self.logger.info(
                f"Loaded {len(self.pipelines)} prebuilt pipelines"
            )

        except Exception as e:
            self.logger.error(f"Failed to load prebuilt pipelines: {e}")
            self.pipelines = {}
