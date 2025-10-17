"""
REVENG Automated Analysis Pipeline Engine

Automated analysis pipeline with tool chaining, error handling, and result aggregation.
"""

import os
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.errors import AnalysisFailureError, PipelineExecutionError, create_error_context
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
                created=time.strftime("%Y-%m-%d %H:%M:%S")
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
        """Execute complete pipeline"""
        try:
            self.logger.info(f"Starting pipeline execution: {pipeline.name} on {binary_path}")

            start_time = time.time()
            stage_results = []
            success_count = 0
            failure_count = 0

            # Execute stages in order
            for stage in pipeline.stages:
                try:
                    stage_result = self._execute_stage(stage, binary_path)
                    stage_results.append(stage_result)

                    if stage_result.status == StageStatus.COMPLETED:
                        success_count += 1
                    else:
                        failure_count += 1

                        # Skip dependent stages if required stage failed
                        if stage.required:
                            self.logger.warning(f"Required stage {stage.name} failed, skipping dependent stages")
                            break

                except Exception as e:
                    self.logger.error(f"Stage {stage.name} execution failed: {e}")
                    stage_result = StageResult(
                        stage_name=stage.name,
                        status=StageStatus.FAILED,
                        output={},
                        error=str(e),
                        execution_time=0.0,
                        retry_count=0
                    )
                    stage_results.append(stage_result)
                    failure_count += 1

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
                output=output
            )

            self.logger.info(f"Completed pipeline execution: {pipeline.name} in {total_execution_time:.2f} seconds")
            return result

        except Exception as e:
            context = create_error_context(
                "pipeline_engine",
                "execute_pipeline",
                binary_path=binary_path
            )
            raise PipelineExecutionError(
                pipeline.name,
                "pipeline_execution",
                context=context,
                original_exception=e
            )

    def save_pipeline(self, pipeline: Pipeline, path: str):
        """Save pipeline definition for reuse"""
        try:
            pipeline_data = asdict(pipeline)

            with open(path, 'w') as f:
                yaml.dump(pipeline_data, f, default_flow_style=False)

            self.logger.info(f"Saved pipeline to {path}")

        except Exception as e:
            self.logger.error(f"Failed to save pipeline: {e}")
            raise

    def load_pipeline(self, path: str) -> Pipeline:
        """Load saved pipeline"""
        try:
            with open(path, 'r') as f:
                pipeline_data = yaml.safe_load(f)

            # Convert dict back to Pipeline object
            pipeline = Pipeline(
                name=pipeline_data['name'],
                description=pipeline_data['description'],
                stages=[PipelineStage(**stage) for stage in pipeline_data['stages']],
                created=pipeline_data['created'],
                version=pipeline_data.get('version', '1.0')
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
        """Execute a single pipeline stage"""
        try:
            self.logger.info(f"Executing stage: {stage.name}")

            start_time = time.time()
            retry_count = 0

            while retry_count <= stage.retry_count:
                try:
                    # Execute stage based on type
                    if stage.stage_type == StageType.STATIC_ANALYSIS:
                        output = self._execute_static_analysis(stage, binary_path)
                    elif stage.stage_type == StageType.PE_ANALYSIS:
                        output = self._execute_pe_analysis(stage, binary_path)
                    elif stage.stage_type == StageType.GHIDRA_ANALYSIS:
                        output = self._execute_ghidra_analysis(stage, binary_path)
                    elif stage.stage_type == StageType.HEX_ANALYSIS:
                        output = self._execute_hex_analysis(stage, binary_path)
                    elif stage.stage_type == StageType.MALWARE_ANALYSIS:
                        output = self._execute_malware_analysis(stage, binary_path)
                    elif stage.stage_type == StageType.ML_ANALYSIS:
                        output = self._execute_ml_analysis(stage, binary_path)
                    elif stage.stage_type == StageType.REPORT_GENERATION:
                        output = self._execute_report_generation(stage, binary_path)
                    else:
                        raise ValueError(f"Unknown stage type: {stage.stage_type}")

                    execution_time = time.time() - start_time

                    return StageResult(
                        stage_name=stage.name,
                        status=StageStatus.COMPLETED,
                        output=output,
                        error=None,
                        execution_time=execution_time,
                        retry_count=retry_count
                    )

                except Exception as e:
                    retry_count += 1
                    if retry_count <= stage.retry_count:
                        self.logger.warning(f"Stage {stage.name} failed, retrying ({retry_count}/{stage.retry_count}): {e}")
                        time.sleep(1)  # Wait before retry
                    else:
                        execution_time = time.time() - start_time
                        return StageResult(
                            stage_name=stage.name,
                            status=StageStatus.FAILED,
                            output={},
                            error=str(e),
                            execution_time=execution_time,
                            retry_count=retry_count
                        )

        except Exception as e:
            self.logger.error(f"Stage execution failed: {e}")
            return StageResult(
                stage_name=stage.name,
                status=StageStatus.FAILED,
                output={},
                error=str(e),
                execution_time=0.0,
                retry_count=0
            )

    def _execute_static_analysis(self, stage: PipelineStage, binary_path: str) -> Dict[str, Any]:
        """Execute static analysis stage"""
        try:
            # Import analyzers
            from ..analyzers.dotnet_analyzer import DotNetAnalyzer
            from ..analyzers.business_logic_extractor import BusinessLogicExtractor

            results = {}

            # .NET analysis
            if stage.config.get('dotnet_analysis', True):
                dotnet_analyzer = DotNetAnalyzer()
                dotnet_result = dotnet_analyzer.analyze_assembly(binary_path)
                results['dotnet_analysis'] = asdict(dotnet_result)

            # Business logic analysis
            if stage.config.get('business_logic_analysis', True):
                business_extractor = BusinessLogicExtractor()
                business_result = business_extractor.analyze_application_domain(binary_path)
                results['business_logic'] = asdict(business_result)

            return results

        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}")
            return {}

    def _execute_pe_analysis(self, stage: PipelineStage, binary_path: str) -> Dict[str, Any]:
        """Execute PE analysis stage"""
        try:
            # Import PE analyzers
            from ..pe.resource_extractor import PEResourceExtractor
            from ..pe.import_analyzer import ImportAnalyzer

            results = {}

            # Resource extraction
            if stage.config.get('resource_extraction', True):
                resource_extractor = PEResourceExtractor()
                resources = resource_extractor.extract_all_resources(binary_path)
                results['resources'] = asdict(resources)

            # Import analysis
            if stage.config.get('import_analysis', True):
                import_analyzer = ImportAnalyzer()
                imports = import_analyzer.analyze_imports(binary_path)
                results['imports'] = asdict(imports)

            return results

        except Exception as e:
            self.logger.error(f"PE analysis failed: {e}")
            return {}

    def _execute_ghidra_analysis(self, stage: PipelineStage, binary_path: str) -> Dict[str, Any]:
        """Execute Ghidra analysis stage"""
        try:
            from ..ghidra.scripting_engine import GhidraScriptingEngine

            ghidra_engine = GhidraScriptingEngine()
            analysis = ghidra_engine.analyze_binary(binary_path)

            return asdict(analysis)

        except Exception as e:
            self.logger.error(f"Ghidra analysis failed: {e}")
            return {}

    def _execute_hex_analysis(self, stage: PipelineStage, binary_path: str) -> Dict[str, Any]:
        """Execute hex analysis stage"""
        try:
            from ..tools.hex_editor import HexEditor

            hex_editor = HexEditor()
            analysis = hex_editor.analyze_binary(binary_path)

            return asdict(analysis)

        except Exception as e:
            self.logger.error(f"Hex analysis failed: {e}")
            return {}

    def _execute_malware_analysis(self, stage: PipelineStage, binary_path: str) -> Dict[str, Any]:
        """Execute malware analysis stage"""
        try:
            # This would implement malware analysis
            # For now, return placeholder
            return {
                'malware_analysis': 'Not implemented yet',
                'confidence': 0.0
            }

        except Exception as e:
            self.logger.error(f"Malware analysis failed: {e}")
            return {}

    def _execute_ml_analysis(self, stage: PipelineStage, binary_path: str) -> Dict[str, Any]:
        """Execute ML analysis stage"""
        try:
            # This would implement ML analysis
            # For now, return placeholder
            return {
                'ml_analysis': 'Not implemented yet',
                'confidence': 0.0
            }

        except Exception as e:
            self.logger.error(f"ML analysis failed: {e}")
            return {}

    def _execute_report_generation(self, stage: PipelineStage, binary_path: str) -> Dict[str, Any]:
        """Execute report generation stage"""
        try:
            # This would implement report generation
            # For now, return placeholder
            return {
                'report_generation': 'Not implemented yet',
                'output_path': 'report.html'
            }

        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {}

    def _aggregate_stage_outputs(self, stage_results: List[StageResult]) -> Dict[str, Any]:
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
                        config={'dotnet_analysis': True, 'business_logic_analysis': True},
                        dependencies=[],
                        timeout=300
                    ),
                    PipelineStage(
                        name="pe_analysis",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={'resource_extraction': True, 'import_analysis': True},
                        dependencies=['static_analysis'],
                        timeout=300
                    ),
                    PipelineStage(
                        name="hex_analysis",
                        stage_type=StageType.HEX_ANALYSIS,
                        tool="reveng",
                        config={'entropy_analysis': True, 'pattern_matching': True},
                        dependencies=['pe_analysis'],
                        timeout=300
                    ),
                    PipelineStage(
                        name="ghidra_analysis",
                        stage_type=StageType.GHIDRA_ANALYSIS,
                        tool="ghidra",
                        config={'auto_analyze': True, 'decompile': True},
                        dependencies=['hex_analysis'],
                        timeout=600
                    ),
                    PipelineStage(
                        name="malware_analysis",
                        stage_type=StageType.MALWARE_ANALYSIS,
                        tool="reveng",
                        config={'packer_detection': True, 'behavioral_analysis': True},
                        dependencies=['ghidra_analysis'],
                        timeout=300
                    ),
                    PipelineStage(
                        name="report_generation",
                        stage_type=StageType.REPORT_GENERATION,
                        tool="reveng",
                        config={'format': 'html', 'include_screenshots': True},
                        dependencies=['malware_analysis'],
                        timeout=60
                    )
                ],
                created=time.strftime("%Y-%m-%d %H:%M:%S")
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
                        config={'dotnet_analysis': True, 'gui_detection': True},
                        dependencies=[],
                        timeout=300
                    ),
                    PipelineStage(
                        name="pe_resources",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={'resource_extraction': True, 'icon_extraction': True},
                        dependencies=['dotnet_analysis'],
                        timeout=300
                    ),
                    PipelineStage(
                        name="business_logic",
                        stage_type=StageType.STATIC_ANALYSIS,
                        tool="reveng",
                        config={'business_logic_analysis': True, 'data_flow_analysis': True},
                        dependencies=['pe_resources'],
                        timeout=300
                    ),
                    PipelineStage(
                        name="report_generation",
                        stage_type=StageType.REPORT_GENERATION,
                        tool="reveng",
                        config={'format': 'html', 'include_resources': True},
                        dependencies=['business_logic'],
                        timeout=60
                    )
                ],
                created=time.strftime("%Y-%m-%d %H:%M:%S")
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
                        config={'dotnet_analysis': True, 'business_logic_analysis': True},
                        dependencies=[],
                        timeout=120
                    ),
                    PipelineStage(
                        name="pe_analysis",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={'import_analysis': True, 'resource_extraction': True},
                        dependencies=['static_analysis'],
                        timeout=120
                    ),
                    PipelineStage(
                        name="hex_analysis",
                        stage_type=StageType.HEX_ANALYSIS,
                        tool="reveng",
                        config={'entropy_analysis': True, 'string_extraction': True},
                        dependencies=['pe_analysis'],
                        timeout=120
                    )
                ],
                created=time.strftime("%Y-%m-%d %H:%M:%S")
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
                        config={'dotnet_analysis': True, 'business_logic_analysis': True},
                        dependencies=[],
                        timeout=600
                    ),
                    PipelineStage(
                        name="pe_analysis",
                        stage_type=StageType.PE_ANALYSIS,
                        tool="reveng",
                        config={'resource_extraction': True, 'import_analysis': True, 'export_analysis': True},
                        dependencies=['static_analysis'],
                        timeout=600
                    ),
                    PipelineStage(
                        name="hex_analysis",
                        stage_type=StageType.HEX_ANALYSIS,
                        tool="reveng",
                        config={'entropy_analysis': True, 'pattern_matching': True, 'embedded_files': True},
                        dependencies=['pe_analysis'],
                        timeout=600
                    ),
                    PipelineStage(
                        name="ghidra_analysis",
                        stage_type=StageType.GHIDRA_ANALYSIS,
                        tool="ghidra",
                        config={'auto_analyze': True, 'decompile': True, 'call_graph': True},
                        dependencies=['hex_analysis'],
                        timeout=1200
                    ),
                    PipelineStage(
                        name="ml_analysis",
                        stage_type=StageType.ML_ANALYSIS,
                        tool="reveng",
                        config={'code_reconstruction': True, 'anomaly_detection': True},
                        dependencies=['ghidra_analysis'],
                        timeout=600
                    ),
                    PipelineStage(
                        name="report_generation",
                        stage_type=StageType.REPORT_GENERATION,
                        tool="reveng",
                        config={'format': 'html', 'include_all': True, 'detailed_analysis': True},
                        dependencies=['ml_analysis'],
                        timeout=120
                    )
                ],
                created=time.strftime("%Y-%m-%d %H:%M:%S")
            )

            # Store pipelines
            self.pipelines = {
                "malware_analysis": malware_pipeline,
                "dotnet_analysis": dotnet_pipeline,
                "quick_triage": triage_pipeline,
                "deep_analysis": deep_pipeline
            }

            self.logger.info(f"Loaded {len(self.pipelines)} prebuilt pipelines")

        except Exception as e:
            self.logger.error(f"Failed to load prebuilt pipelines: {e}")
            self.pipelines = {}
