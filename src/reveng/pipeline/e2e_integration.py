"""End-to-end CLI pipeline orchestration for async analysis integration."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

from .pipeline_engine import (
    AnalysisPipeline,
    Pipeline,
    PipelineResult,
    PipelineStage,
    PipelineStatus,
    StageType,
)


class EndToEndPipelineRunner:
    """Run the CLI's end-to-end async analysis lifecycle."""

    def __init__(
        self,
        *,
        output_dir: str,
        use_gemini: bool = False,
        enable_recompilation: bool = True,
        enable_forensics: bool = True,
        ghidra_url: str | None = None,
        max_compilation_retries: int = 2,
        behavioral_duration_seconds: int = 1,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_gemini = use_gemini
        self.enable_recompilation = enable_recompilation
        self.enable_forensics = enable_forensics
        self.ghidra_url = ghidra_url
        self.max_compilation_retries = max(0, max_compilation_retries)
        self.behavioral_duration_seconds = max(1, behavioral_duration_seconds)
        self.pipeline_engine = AnalysisPipeline()

    def build_pipeline(self) -> Pipeline:
        """Build the configured end-to-end pipeline."""
        pipeline = self.pipeline_engine.create_pipeline(
            "cli_end_to_end",
            "CLI end-to-end async disassembly, recompilation, and ML forensics flow",
        )

        self.pipeline_engine.add_stage(
            pipeline,
            PipelineStage(
                name="ghidra_analysis",
                stage_type=StageType.GHIDRA_ANALYSIS,
                tool="reveng",
                config={
                    "mode": "e2e_disassembly",
                    "output_dir": str(self.output_dir),
                    "ghidra_url": self.ghidra_url,
                },
                dependencies=[],
                timeout=300,
            ),
        )

        report_dependencies = ["ghidra_analysis"]
        downstream_dependency = "ghidra_analysis"

        if self.enable_recompilation:
            self.pipeline_engine.add_stage(
                pipeline,
                PipelineStage(
                    name="recompilation",
                    stage_type=StageType.RECOMPILATION,
                    tool="reveng",
                    config={
                        "output_dir": str(self.output_dir),
                        "use_gemini": self.use_gemini,
                        "max_compilation_retries": self.max_compilation_retries,
                    },
                    dependencies=["ghidra_analysis"],
                    timeout=600,
                ),
            )
            report_dependencies.append("recompilation")
            downstream_dependency = "recompilation"

        if self.enable_forensics:
            self.pipeline_engine.add_stage(
                pipeline,
                PipelineStage(
                    name="behavioral_forensics",
                    stage_type=StageType.MALWARE_ANALYSIS,
                    tool="reveng",
                    config={
                        "mode": "behavioral_forensics",
                        "output_dir": str(self.output_dir),
                        "duration_seconds": self.behavioral_duration_seconds,
                    },
                    dependencies=[downstream_dependency],
                    timeout=120,
                ),
            )
            self.pipeline_engine.add_stage(
                pipeline,
                PipelineStage(
                    name="memory_forensics",
                    stage_type=StageType.ML_ANALYSIS,
                    tool="reveng",
                    config={
                        "mode": "memory_forensics",
                        "output_dir": str(self.output_dir),
                    },
                    dependencies=[downstream_dependency],
                    timeout=120,
                ),
            )
            report_dependencies.extend(["behavioral_forensics", "memory_forensics"])

        self.pipeline_engine.add_stage(
            pipeline,
            PipelineStage(
                name="unified_report",
                stage_type=StageType.REPORT_GENERATION,
                tool="reveng",
                config={
                    "mode": "unified_e2e_report",
                    "output_dir": str(self.output_dir),
                },
                dependencies=report_dependencies,
                timeout=60,
            ),
        )

        return pipeline

    def run(self, binary_path: str) -> Dict[str, Any]:
        """Run the end-to-end pipeline and load the unified report."""
        resolved_binary_path = str(Path(binary_path).resolve())
        pipeline = self.build_pipeline()
        pipeline_result = self.pipeline_engine.execute_pipeline(pipeline, resolved_binary_path)
        report_output = pipeline_result.output.get("unified_report", {})
        report_path = report_output.get("report_path")
        unified_report = self._load_unified_report(report_path)

        pipeline_execution_path = self.output_dir / "e2e_pipeline_execution.json"
        self._save_pipeline_execution(pipeline_result, pipeline_execution_path)

        status = report_output.get("status") or (
            "success" if pipeline_result.status == PipelineStatus.COMPLETED else "failed"
        )

        return {
            "status": status,
            "report_path": report_path,
            "output_dir": str(self.output_dir),
            "summary": report_output.get("summary", {}),
            "pipeline_execution_path": str(pipeline_execution_path),
            "unified_report": unified_report,
        }

    def _load_unified_report(self, report_path: str | None) -> Dict[str, Any]:
        if not report_path:
            return {}

        report_file = Path(report_path)
        if not report_file.exists():
            return {}

        loaded_report = json.loads(report_file.read_text(encoding="utf-8"))
        return loaded_report if isinstance(loaded_report, dict) else {}

    def _save_pipeline_execution(
        self, pipeline_result: PipelineResult, output_path: Path
    ) -> None:
        serialized_result = {
            "pipeline_name": pipeline_result.pipeline_name,
            "binary_path": pipeline_result.binary_path,
            "status": pipeline_result.status.value,
            "total_execution_time": pipeline_result.total_execution_time,
            "success_count": pipeline_result.success_count,
            "failure_count": pipeline_result.failure_count,
            "stage_results": [
                {
                    **asdict(stage_result),
                    "status": stage_result.status.value,
                }
                for stage_result in pipeline_result.stage_results
            ],
            "output": pipeline_result.output,
        }
        output_path.write_text(json.dumps(serialized_result, indent=2, default=str), encoding="utf-8")
