"""
Automated Analysis Pipeline for REVENG

Chaining multiple analysis tools into workflows with pre-built templates
for malware analysis, .NET analysis, quick triage, and deep analysis.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, BinaryIO
from dataclasses import dataclass
from enum import Enum

from ..core.errors import REVENGError, AnalysisFailureError, create_error_context
from ..core.logger import get_logger

logger = get_logger()

class PipelineStage(Enum):
    """Pipeline stages"""
    PREPROCESSING = "preprocessing"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    POSTPROCESSING = "postprocessing"
    REPORTING = "reporting"

class AnalysisTool(Enum):
    """Analysis tools"""
    GHIDRA = "ghidra"
    IDA = "ida"
    ILSPY = "ilspy"
    CFR = "cfr"
    UNCOMPYLE6 = "uncompyle6"
    DIE = "die"
    EXEINFO = "exeinfo"
    SCYLLA = "scylla"
    X64DBG = "x64dbg"
    HXD = "hxd"
    IMHEX = "imhex"
    RESOURCE_HACKER = "resource_hacker"
    LORDPE = "lordpe"

@dataclass
class PipelineStep:
    """Pipeline step definition"""
    name: str
    tool: AnalysisTool
    stage: PipelineStage
    command: str
    parameters: List[str] = None
    timeout: int = 300
    required: bool = True
    output_format: str = "json"

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []

@dataclass
class PipelineResult:
    """Pipeline execution result"""
    pipeline_name: str
    binary_path: str
    execution_time: float
    success: bool
    results: Dict[str, Any] = None
    errors: List[str] = None
    warnings: List[str] = None
    stage_results: Dict[PipelineStage, Dict[str, Any]] = None

    def __post_init__(self):
        if self.results is None:
            self.results = {}
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.stage_results is None:
            self.stage_results = {}

@dataclass
class AnalysisTemplate:
    """Analysis template definition"""
    name: str
    description: str
    stages: List[PipelineStage]
    steps: List[PipelineStep]
    output_formats: List[str] = None
    estimated_time: int = 0  # in minutes

    def __post_init__(self):
        if self.output_formats is None:
            self.output_formats = ["json", "html", "pdf"]

class AutomatedAnalysisPipeline:
    """Automated analysis pipeline engine"""

    def __init__(self):
        self.logger = get_logger()

        # Pre-built analysis templates
        self.templates = {
            "malware_analysis": self._create_malware_analysis_template(),
            "dotnet_analysis": self._create_dotnet_analysis_template(),
            "quick_triage": self._create_quick_triage_template(),
            "deep_analysis": self._create_deep_analysis_template()
        }

    def run_pipeline(self, template_name: str, binary_path: str, output_dir: str, custom_steps: Optional[List[PipelineStep]] = None) -> PipelineResult:
        """Run analysis pipeline with specified template"""

        context = create_error_context(
            tool_name="automated_analysis_pipeline",
            binary_path=binary_path,
            analysis_stage="pipeline_execution"
        )

        try:
            if template_name not in self.templates:
                raise AnalysisFailureError(
                    "pipeline_execution",
                    binary_path,
                    context=context,
                    details=f"Unknown template: {template_name}"
                )

            if not Path(binary_path).exists():
                raise AnalysisFailureError(
                    "pipeline_execution",
                    binary_path,
                    context=context,
                    details="Binary file not found"
                )

            self.logger.info(f"Running analysis pipeline: {template_name} on {binary_path}")

            # Get template
            template = self.templates[template_name]

            # Use custom steps if provided
            steps = custom_steps if custom_steps else template.steps

            # Create output directory
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Initialize result
            result = PipelineResult(
                pipeline_name=template_name,
                binary_path=binary_path,
                execution_time=0.0,
                success=False
            )

            start_time = time.time()

            # Execute pipeline stages
            for stage in template.stages:
                stage_results = self._execute_stage(stage, steps, binary_path, output_path)
                result.stage_results[stage] = stage_results

                # Check for critical errors
                if stage_results.get('critical_errors'):
                    result.errors.extend(stage_results['critical_errors'])
                    if any(step.required for step in steps if step.stage == stage):
                        result.success = False
                        break

            # Calculate execution time
            result.execution_time = time.time() - start_time

            # Determine overall success
            if not result.success:
                result.success = all(
                    not stage_results.get('critical_errors', [])
                    for stage_results in result.stage_results.values()
                )

            # Generate final report
            self._generate_final_report(result, output_path)

            self.logger.info(f"Pipeline execution completed: {template_name} in {result.execution_time:.2f}s")
            return result

        except Exception as e:
            self.logger.error(f"Failed to run analysis pipeline: {e}")
            raise AnalysisFailureError(
                "pipeline_execution",
                binary_path,
                context=context,
                original_error=e
            )

    def _execute_stage(self, stage: PipelineStage, steps: List[PipelineStep], binary_path: str, output_path: Path) -> Dict[str, Any]:
        """Execute a pipeline stage"""

        try:
            self.logger.info(f"Executing pipeline stage: {stage.value}")

            stage_results = {
                'stage': stage.value,
                'start_time': time.time(),
                'steps_executed': 0,
                'steps_failed': 0,
                'critical_errors': [],
                'warnings': [],
                'outputs': {}
            }

            # Get steps for this stage
            stage_steps = [step for step in steps if step.stage == stage]

            for step in stage_steps:
                try:
                    self.logger.info(f"Executing step: {step.name}")

                    # Execute step
                    step_result = self._execute_step(step, binary_path, output_path)

                    if step_result['success']:
                        stage_results['steps_executed'] += 1
                        stage_results['outputs'][step.name] = step_result
                    else:
                        stage_results['steps_failed'] += 1
                        if step.required:
                            stage_results['critical_errors'].append(f"Required step failed: {step.name}")
                        else:
                            stage_results['warnings'].append(f"Optional step failed: {step.name}")

                except Exception as e:
                    self.logger.error(f"Step execution failed: {step.name} - {e}")
                    stage_results['steps_failed'] += 1
                    if step.required:
                        stage_results['critical_errors'].append(f"Required step failed: {step.name} - {e}")
                    else:
                        stage_results['warnings'].append(f"Optional step failed: {step.name} - {e}")

            stage_results['end_time'] = time.time()
            stage_results['duration'] = stage_results['end_time'] - stage_results['start_time']

            self.logger.info(f"Stage {stage.value} completed: {stage_results['steps_executed']} successful, {stage_results['steps_failed']} failed")
            return stage_results

        except Exception as e:
            self.logger.error(f"Failed to execute stage {stage.value}: {e}")
            return {
                'stage': stage.value,
                'critical_errors': [f"Stage execution failed: {e}"],
                'steps_executed': 0,
                'steps_failed': 0
            }

    def _execute_step(self, step: PipelineStep, binary_path: str, output_path: Path) -> Dict[str, Any]:
        """Execute a single pipeline step"""

        try:
            # Build command
            command = [step.command] + step.parameters + [binary_path]

            # Set output file
            output_file = output_path / f"{step.name}_output.{step.output_format}"

            # Execute command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=step.timeout,
                cwd=str(output_path)
            )

            # Save output
            if result.stdout:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)

            # Parse results
            step_result = {
                'step_name': step.name,
                'tool': step.tool.value,
                'command': ' '.join(command),
                'return_code': result.returncode,
                'success': result.returncode == 0,
                'output_file': str(output_file),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'execution_time': 0.0  # Would be calculated in real implementation
            }

            return step_result

        except subprocess.TimeoutExpired:
            self.logger.error(f"Step {step.name} timed out after {step.timeout} seconds")
            return {
                'step_name': step.name,
                'success': False,
                'error': f"Timeout after {step.timeout} seconds"
            }
        except Exception as e:
            self.logger.error(f"Step {step.name} execution failed: {e}")
            return {
                'step_name': step.name,
                'success': False,
                'error': str(e)
            }

    def _generate_final_report(self, result: PipelineResult, output_path: Path):
        """Generate final analysis report"""

        try:
            # Create comprehensive report
            report = {
                'pipeline_name': result.pipeline_name,
                'binary_path': result.binary_path,
                'execution_time': result.execution_time,
                'success': result.success,
                'errors': result.errors,
                'warnings': result.warnings,
                'stage_results': result.stage_results,
                'summary': self._generate_summary(result)
            }

            # Save JSON report
            json_report_path = output_path / "analysis_report.json"
            with open(json_report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            # Generate HTML report
            html_report_path = output_path / "analysis_report.html"
            self._generate_html_report(report, html_report_path)

            self.logger.info(f"Final report generated: {json_report_path}")

        except Exception as e:
            self.logger.error(f"Failed to generate final report: {e}")

    def _generate_summary(self, result: PipelineResult) -> Dict[str, Any]:
        """Generate analysis summary"""

        try:
            summary = {
                'total_stages': len(result.stage_results),
                'successful_stages': sum(1 for stage_result in result.stage_results.values() if not stage_result.get('critical_errors')),
                'failed_stages': sum(1 for stage_result in result.stage_results.values() if stage_result.get('critical_errors')),
                'total_steps': sum(stage_result.get('steps_executed', 0) + stage_result.get('steps_failed', 0) for stage_result in result.stage_results.values()),
                'successful_steps': sum(stage_result.get('steps_executed', 0) for stage_result in result.stage_results.values()),
                'failed_steps': sum(stage_result.get('steps_failed', 0) for stage_result in result.stage_results.values()),
                'execution_time': result.execution_time,
                'success_rate': 0.0
            }

            if summary['total_steps'] > 0:
                summary['success_rate'] = summary['successful_steps'] / summary['total_steps']

            return summary

        except Exception as e:
            self.logger.error(f"Failed to generate summary: {e}")
            return {}

    def _generate_html_report(self, report: Dict[str, Any], output_path: Path):
        """Generate HTML report"""

        try:
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>REVENG Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
        .warning {{ color: orange; }}
        .summary {{ background-color: #e8f4f8; padding: 15px; border-radius: 5px; }}
        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>REVENG Analysis Report</h1>
        <p><strong>Pipeline:</strong> {report['pipeline_name']}</p>
        <p><strong>Binary:</strong> {report['binary_path']}</p>
        <p><strong>Execution Time:</strong> {report['execution_time']:.2f} seconds</p>
        <p><strong>Status:</strong> <span class="{'success' if report['success'] else 'error'}">{'SUCCESS' if report['success'] else 'FAILED'}</span></p>
    </div>

    <div class="section">
        <h2>Summary</h2>
        <div class="summary">
            <p><strong>Total Stages:</strong> {report['summary']['total_stages']}</p>
            <p><strong>Successful Stages:</strong> {report['summary']['successful_stages']}</p>
            <p><strong>Failed Stages:</strong> {report['summary']['failed_stages']}</p>
            <p><strong>Total Steps:</strong> {report['summary']['total_steps']}</p>
            <p><strong>Successful Steps:</strong> {report['summary']['successful_steps']}</p>
            <p><strong>Failed Steps:</strong> {report['summary']['failed_steps']}</p>
            <p><strong>Success Rate:</strong> {report['summary']['success_rate']:.2%}</p>
        </div>
    </div>

    <div class="section">
        <h2>Stage Results</h2>
        {self._generate_stage_html(report['stage_results'])}
    </div>

    <div class="section">
        <h2>Errors</h2>
        {self._generate_errors_html(report['errors'])}
    </div>

    <div class="section">
        <h2>Warnings</h2>
        {self._generate_warnings_html(report['warnings'])}
    </div>
</body>
</html>
"""

            with open(output_path, 'w') as f:
                f.write(html_content)

        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")

    def _generate_stage_html(self, stage_results: Dict[PipelineStage, Dict[str, Any]]) -> str:
        """Generate HTML for stage results"""

        html = ""
        for stage, results in stage_results.items():
            html += f"""
            <div class="section">
                <h3>{stage.value}</h3>
                <p><strong>Steps Executed:</strong> {results.get('steps_executed', 0)}</p>
                <p><strong>Steps Failed:</strong> {results.get('steps_failed', 0)}</p>
                <p><strong>Duration:</strong> {results.get('duration', 0):.2f} seconds</p>
            </div>
            """
        return html

    def _generate_errors_html(self, errors: List[str]) -> str:
        """Generate HTML for errors"""

        if not errors:
            return "<p>No errors.</p>"

        html = "<ul>"
        for error in errors:
            html += f"<li class='error'>{error}</li>"
        html += "</ul>"
        return html

    def _generate_warnings_html(self, warnings: List[str]) -> str:
        """Generate HTML for warnings"""

        if not warnings:
            return "<p>No warnings.</p>"

        html = "<ul>"
        for warning in warnings:
            html += f"<li class='warning'>{warning}</li>"
        html += "</ul>"
        return html

    def _create_malware_analysis_template(self) -> AnalysisTemplate:
        """Create malware analysis template"""

        steps = [
            PipelineStep(
                name="file_type_detection",
                tool=AnalysisTool.DIE,
                stage=PipelineStage.PREPROCESSING,
                command="die",
                parameters=["-c", "-j"],
                timeout=60
            ),
            PipelineStep(
                name="entropy_analysis",
                tool=AnalysisTool.HXD,
                stage=PipelineStage.PREPROCESSING,
                command="hxd",
                parameters=["-e"],
                timeout=120
            ),
            PipelineStep(
                name="static_analysis",
                tool=AnalysisTool.GHIDRA,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="ghidra",
                parameters=["-headless", "-import", "-postScript", "malware_analysis.py"],
                timeout=600
            ),
            PipelineStep(
                name="import_analysis",
                tool=AnalysisTool.LORDPE,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="lordpe",
                parameters=["-i"],
                timeout=300
            ),
            PipelineStep(
                name="resource_extraction",
                tool=AnalysisTool.RESOURCE_HACKER,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="resource_hacker",
                parameters=["-extract"],
                timeout=300
            ),
            PipelineStep(
                name="dynamic_analysis",
                tool=AnalysisTool.X64DBG,
                stage=PipelineStage.DYNAMIC_ANALYSIS,
                command="x64dbg",
                parameters=["-a"],
                timeout=900
            ),
            PipelineStep(
                name="unpacking",
                tool=AnalysisTool.SCYLLA,
                stage=PipelineStage.DYNAMIC_ANALYSIS,
                command="scylla",
                parameters=["-u"],
                timeout=600
            )
        ]

        return AnalysisTemplate(
            name="malware_analysis",
            description="Comprehensive malware analysis pipeline",
            stages=[PipelineStage.PREPROCESSING, PipelineStage.STATIC_ANALYSIS, PipelineStage.DYNAMIC_ANALYSIS],
            steps=steps,
            estimated_time=45
        )

    def _create_dotnet_analysis_template(self) -> AnalysisTemplate:
        """Create .NET analysis template"""

        steps = [
            PipelineStep(
                name="dotnet_detection",
                tool=AnalysisTool.DIE,
                stage=PipelineStage.PREPROCESSING,
                command="die",
                parameters=["-c", "-j"],
                timeout=60
            ),
            PipelineStep(
                name="decompilation",
                tool=AnalysisTool.ILSPY,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="ilspy",
                parameters=["-o"],
                timeout=600
            ),
            PipelineStep(
                name="ghidra_analysis",
                tool=AnalysisTool.GHIDRA,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="ghidra",
                parameters=["-headless", "-import", "-postScript", "dotnet_analysis.py"],
                timeout=600
            ),
            PipelineStep(
                name="resource_extraction",
                tool=AnalysisTool.RESOURCE_HACKER,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="resource_hacker",
                parameters=["-extract"],
                timeout=300
            )
        ]

        return AnalysisTemplate(
            name="dotnet_analysis",
            description=".NET-specific analysis pipeline",
            stages=[PipelineStage.PREPROCESSING, PipelineStage.STATIC_ANALYSIS],
            steps=steps,
            estimated_time=25
        )

    def _create_quick_triage_template(self) -> AnalysisTemplate:
        """Create quick triage template"""

        steps = [
            PipelineStep(
                name="file_type_detection",
                tool=AnalysisTool.DIE,
                stage=PipelineStage.PREPROCESSING,
                command="die",
                parameters=["-c", "-j"],
                timeout=30
            ),
            PipelineStep(
                name="quick_analysis",
                tool=AnalysisTool.GHIDRA,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="ghidra",
                parameters=["-headless", "-import", "-postScript", "quick_triage.py"],
                timeout=300
            ),
            PipelineStep(
                name="import_analysis",
                tool=AnalysisTool.LORDPE,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="lordpe",
                parameters=["-i"],
                timeout=120
            )
        ]

        return AnalysisTemplate(
            name="quick_triage",
            description="Quick triage analysis pipeline",
            stages=[PipelineStage.PREPROCESSING, PipelineStage.STATIC_ANALYSIS],
            steps=steps,
            estimated_time=10
        )

    def _create_deep_analysis_template(self) -> AnalysisTemplate:
        """Create deep analysis template"""

        steps = [
            PipelineStep(
                name="file_type_detection",
                tool=AnalysisTool.DIE,
                stage=PipelineStage.PREPROCESSING,
                command="die",
                parameters=["-c", "-j"],
                timeout=60
            ),
            PipelineStep(
                name="entropy_analysis",
                tool=AnalysisTool.HXD,
                stage=PipelineStage.PREPROCESSING,
                command="hxd",
                parameters=["-e"],
                timeout=120
            ),
            PipelineStep(
                name="deep_static_analysis",
                tool=AnalysisTool.GHIDRA,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="ghidra",
                parameters=["-headless", "-import", "-postScript", "deep_analysis.py"],
                timeout=1200
            ),
            PipelineStep(
                name="import_analysis",
                tool=AnalysisTool.LORDPE,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="lordpe",
                parameters=["-i"],
                timeout=300
            ),
            PipelineStep(
                name="resource_extraction",
                tool=AnalysisTool.RESOURCE_HACKER,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="resource_hacker",
                parameters=["-extract"],
                timeout=300
            ),
            PipelineStep(
                name="hex_analysis",
                tool=AnalysisTool.IMHEX,
                stage=PipelineStage.STATIC_ANALYSIS,
                command="imhex",
                parameters=["-a"],
                timeout=600
            )
        ]

        return AnalysisTemplate(
            name="deep_analysis",
            description="Comprehensive deep analysis pipeline",
            stages=[PipelineStage.PREPROCESSING, PipelineStage.STATIC_ANALYSIS],
            steps=steps,
            estimated_time=60
        )
