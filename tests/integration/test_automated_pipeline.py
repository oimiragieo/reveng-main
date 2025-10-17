"""
Integration tests for REVENG Automated Analysis Pipeline

Tests the automated analysis pipeline with tool chaining and workflow automation.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from reveng.pipelines.automated_analysis import AutomatedAnalysisPipeline, PipelineStep, PipelineResult
from reveng.analyzers.dotnet_analyzer import DotNetAnalyzer
from reveng.pe.resource_extractor import PEResourceExtractor
from reveng.pe.import_analyzer import ImportAnalyzer
from reveng.analyzers.business_logic_extractor import BusinessLogicExtractor
from reveng.ghidra.scripting_engine import GhidraScriptingEngine
from reveng.tools.hex_editor import HexEditor
from reveng.core.errors import AnalysisFailureError, ConfigurationError

class TestAutomatedAnalysisPipeline:
    """Test cases for AutomatedAnalysisPipeline"""

    def test_init(self):
        """Test AutomatedAnalysisPipeline initialization"""
        pipeline = AutomatedAnalysisPipeline()
        assert pipeline is not None
        assert hasattr(pipeline, 'analyzers')
        assert hasattr(pipeline, 'results')

    def test_run_pipeline_success(self, mock_automated_pipeline, sample_binaries_dir):
        """Test successful pipeline execution"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Create pipeline steps
        steps = [
            PipelineStep(
                name="dotnet_analysis",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": str(binary_path)}
            ),
            PipelineStep(
                name="pe_resource_extraction",
                function=pipeline.analyzers["pe_resource"].extract_all_resources,
                args={"binary_path": str(binary_path), "output_dir": str(sample_binaries_dir / "output")}
            ),
            PipelineStep(
                name="pe_import_analysis",
                function=pipeline.analyzers["pe_import"].analyze_imports,
                args={"binary_path": str(binary_path)}
            ),
            PipelineStep(
                name="business_logic_extraction",
                function=pipeline.analyzers["business_logic"].extract_logic,
                args={"binary_path": str(binary_path)},
                depends_on=["dotnet_analysis", "pe_import_analysis"]
            )
        ]

        # Mock analyzer results
        with patch.object(pipeline.analyzers["dotnet"], 'analyze_assembly', return_value={'framework': '4.8'}):
            with patch.object(pipeline.analyzers["pe_resource"], 'extract_all_resources', return_value={'icons': ['app.ico']}):
                with patch.object(pipeline.analyzers["pe_import"], 'analyze_imports', return_value={'dlls': ['kernel32.dll']}):
                    with patch.object(pipeline.analyzers["business_logic"], 'extract_logic', return_value={'domain': 'Security Reporting'}):
                        result = pipeline.run_pipeline(str(binary_path), steps)

                        assert isinstance(result, PipelineResult)
                        assert result.binary_path == str(binary_path)
                        assert result.dotnet_analysis is not None
                        assert result.pe_resources is not None
                        assert result.pe_imports is not None
                        assert result.business_logic is not None

    def test_run_pipeline_file_not_found(self):
        """Test pipeline execution with non-existent file"""
        pipeline = AutomatedAnalysisPipeline()

        steps = [
            PipelineStep(
                name="dotnet_analysis",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": "nonexistent.exe"}
            )
        ]

        with pytest.raises(FileNotFoundError):
            pipeline.run_pipeline("nonexistent.exe", steps)

    def test_run_pipeline_with_dependencies(self, sample_binaries_dir):
        """Test pipeline execution with step dependencies"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Create pipeline steps with dependencies
        steps = [
            PipelineStep(
                name="dotnet_analysis",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": str(binary_path)}
            ),
            PipelineStep(
                name="pe_import_analysis",
                function=pipeline.analyzers["pe_import"].analyze_imports,
                args={"binary_path": str(binary_path)}
            ),
            PipelineStep(
                name="business_logic_extraction",
                function=pipeline.analyzers["business_logic"].extract_logic,
                args={"binary_path": str(binary_path)},
                depends_on=["dotnet_analysis", "pe_import_analysis"]
            )
        ]

        # Mock analyzer results
        with patch.object(pipeline.analyzers["dotnet"], 'analyze_assembly', return_value={'framework': '4.8'}):
            with patch.object(pipeline.analyzers["pe_import"], 'analyze_imports', return_value={'dlls': ['kernel32.dll']}):
                with patch.object(pipeline.analyzers["business_logic"], 'extract_logic', return_value={'domain': 'Security Reporting'}):
                    result = pipeline.run_pipeline(str(binary_path), steps)

                    assert isinstance(result, PipelineResult)
                    assert result.business_logic is not None

    def test_run_pipeline_with_disabled_step(self, sample_binaries_dir):
        """Test pipeline execution with disabled steps"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Create pipeline steps with one disabled
        steps = [
            PipelineStep(
                name="dotnet_analysis",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": str(binary_path)},
                enabled=True
            ),
            PipelineStep(
                name="pe_resource_extraction",
                function=pipeline.analyzers["pe_resource"].extract_all_resources,
                args={"binary_path": str(binary_path)},
                enabled=False  # Disabled step
            )
        ]

        # Mock analyzer results
        with patch.object(pipeline.analyzers["dotnet"], 'analyze_assembly', return_value={'framework': '4.8'}):
            result = pipeline.run_pipeline(str(binary_path), steps)

            assert isinstance(result, PipelineResult)
            assert result.dotnet_analysis is not None
            assert result.pe_resources is None  # Should be None for disabled step

    def test_run_pipeline_with_step_failure(self, sample_binaries_dir):
        """Test pipeline execution with step failure"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Create pipeline steps
        steps = [
            PipelineStep(
                name="dotnet_analysis",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": str(binary_path)}
            ),
            PipelineStep(
                name="pe_resource_extraction",
                function=pipeline.analyzers["pe_resource"].extract_all_resources,
                args={"binary_path": str(binary_path)}
            )
        ]

        # Mock analyzer results with one failure
        with patch.object(pipeline.analyzers["dotnet"], 'analyze_assembly', return_value={'framework': '4.8'}):
            with patch.object(pipeline.analyzers["pe_resource"], 'extract_all_resources', side_effect=Exception("Resource extraction failed")):
                with pytest.raises(AnalysisFailureError):
                    pipeline.run_pipeline(str(binary_path), steps)

    def test_run_pipeline_with_circular_dependency(self, sample_binaries_dir):
        """Test pipeline execution with circular dependency"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Create pipeline steps with circular dependency
        steps = [
            PipelineStep(
                name="step1",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": str(binary_path)},
                depends_on=["step2"]
            ),
            PipelineStep(
                name="step2",
                function=pipeline.analyzers["pe_resource"].extract_all_resources,
                args={"binary_path": str(binary_path)},
                depends_on=["step1"]
            )
        ]

        with pytest.raises(ConfigurationError):
            pipeline.run_pipeline(str(binary_path), steps)

    def test_create_template_pipeline_malware(self, sample_binaries_dir):
        """Test creating malware analysis template pipeline"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "malware_sample.exe"
        output_dir = sample_binaries_dir / "output"

        steps = pipeline.create_template_pipeline("malware_triage", str(binary_path), str(output_dir))

        assert isinstance(steps, list)
        assert len(steps) > 0

        # Check that required steps are present
        step_names = [step.name for step in steps]
        assert "pe_resource_extraction" in step_names
        assert "pe_import_analysis" in step_names
        assert "hex_editor_scan" in step_names

    def test_create_template_pipeline_dotnet(self, sample_binaries_dir):
        """Test creating .NET analysis template pipeline"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"
        output_dir = sample_binaries_dir / "output"

        steps = pipeline.create_template_pipeline(".net_deep_analysis", str(binary_path), str(output_dir))

        assert isinstance(steps, list)
        assert len(steps) > 0

        # Check that required steps are present
        step_names = [step.name for step in steps]
        assert "dotnet_analysis" in step_names
        assert "business_logic_extraction" in step_names

    def test_create_template_pipeline_quick(self, sample_binaries_dir):
        """Test creating quick triage template pipeline"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "native_app.exe"
        output_dir = sample_binaries_dir / "output"

        steps = pipeline.create_template_pipeline("quick_triage", str(binary_path), str(output_dir))

        assert isinstance(steps, list)
        assert len(steps) > 0

        # Check that required steps are present
        step_names = [step.name for step in steps]
        assert "pe_resource_extraction" in step_names
        assert "pe_import_analysis" in step_names

    def test_create_template_pipeline_unknown(self, sample_binaries_dir):
        """Test creating unknown template pipeline"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "test.exe"
        output_dir = sample_binaries_dir / "output"

        with pytest.raises(ValueError):
            pipeline.create_template_pipeline("unknown_template", str(binary_path), str(output_dir))

    def test_execute_step_success(self, sample_binaries_dir):
        """Test successful step execution"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        step = PipelineStep(
            name="dotnet_analysis",
            function=pipeline.analyzers["dotnet"].analyze_assembly,
            args={"binary_path": str(binary_path)}
        )

        # Mock analyzer result
        with patch.object(pipeline.analyzers["dotnet"], 'analyze_assembly', return_value={'framework': '4.8'}):
            result = pipeline._execute_step(step, str(binary_path))

            assert result is not None
            assert result['framework'] == '4.8'

    def test_execute_step_disabled(self, sample_binaries_dir):
        """Test disabled step execution"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        step = PipelineStep(
            name="dotnet_analysis",
            function=pipeline.analyzers["dotnet"].analyze_assembly,
            args={"binary_path": str(binary_path)},
            enabled=False
        )

        result = pipeline._execute_step(step, str(binary_path))

        assert result is None

    def test_execute_step_with_dependency(self, sample_binaries_dir):
        """Test step execution with dependency resolution"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Set up dependency result
        pipeline.results["dotnet_analysis"] = {'framework': '4.8'}

        step = PipelineStep(
            name="business_logic_extraction",
            function=pipeline.analyzers["business_logic"].extract_logic,
            args={"decompiled_code": "$$dotnet_analysis"},
            depends_on=["dotnet_analysis"]
        )

        # Mock analyzer result
        with patch.object(pipeline.analyzers["business_logic"], 'extract_logic', return_value={'domain': 'Security Reporting'}):
            result = pipeline._execute_step(step, str(binary_path))

            assert result is not None
            assert result['domain'] == 'Security Reporting'

    def test_execute_step_with_missing_dependency(self, sample_binaries_dir):
        """Test step execution with missing dependency"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        step = PipelineStep(
            name="business_logic_extraction",
            function=pipeline.analyzers["business_logic"].extract_logic,
            args={"decompiled_code": "$$missing_dependency"},
            depends_on=["missing_dependency"]
        )

        # Mock analyzer result
        with patch.object(pipeline.analyzers["business_logic"], 'extract_logic', return_value={'domain': 'Security Reporting'}):
            result = pipeline._execute_step(step, str(binary_path))

            assert result is not None
            assert result['domain'] == 'Security Reporting'

    def test_execute_step_with_exception(self, sample_binaries_dir):
        """Test step execution with exception"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        step = PipelineStep(
            name="dotnet_analysis",
            function=pipeline.analyzers["dotnet"].analyze_assembly,
            args={"binary_path": str(binary_path)}
        )

        # Mock analyzer exception
        with patch.object(pipeline.analyzers["dotnet"], 'analyze_assembly', side_effect=Exception("Analysis failed")):
            with pytest.raises(AnalysisFailureError):
                pipeline._execute_step(step, str(binary_path))

    def test_get_pipeline_summary(self, sample_binaries_dir):
        """Test getting pipeline summary"""
        pipeline = AutomatedAnalysisPipeline()
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Create pipeline steps
        steps = [
            PipelineStep(
                name="dotnet_analysis",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": str(binary_path)}
            ),
            PipelineStep(
                name="pe_resource_extraction",
                function=pipeline.analyzers["pe_resource"].extract_all_resources,
                args={"binary_path": str(binary_path)}
            )
        ]

        # Mock analyzer results
        with patch.object(pipeline.analyzers["dotnet"], 'analyze_assembly', return_value={'framework': '4.8'}):
            with patch.object(pipeline.analyzers["pe_resource"], 'extract_all_resources', return_value={'icons': ['app.ico']}):
                result = pipeline.run_pipeline(str(binary_path), steps)

                summary = pipeline.get_pipeline_summary(result)

                assert isinstance(summary, dict)
                assert 'total_steps' in summary
                assert 'successful_steps' in summary
                assert 'failed_steps' in summary
                assert 'execution_time' in summary
                assert summary['total_steps'] == 2
                assert summary['successful_steps'] == 2
                assert summary['failed_steps'] == 0

    def test_validate_pipeline_steps(self):
        """Test pipeline step validation"""
        pipeline = AutomatedAnalysisPipeline()

        # Valid steps
        valid_steps = [
            PipelineStep(
                name="step1",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": "test.exe"}
            ),
            PipelineStep(
                name="step2",
                function=pipeline.analyzers["pe_resource"].extract_all_resources,
                args={"binary_path": "test.exe"}
            )
        ]

        assert pipeline.validate_pipeline_steps(valid_steps) is True

        # Invalid steps (duplicate names)
        invalid_steps = [
            PipelineStep(
                name="step1",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": "test.exe"}
            ),
            PipelineStep(
                name="step1",  # Duplicate name
                function=pipeline.analyzers["pe_resource"].extract_all_resources,
                args={"binary_path": "test.exe"}
            )
        ]

        assert pipeline.validate_pipeline_steps(invalid_steps) is False

    def test_save_pipeline_definition(self, temp_dir):
        """Test saving pipeline definition"""
        pipeline = AutomatedAnalysisPipeline()

        # Create pipeline steps
        steps = [
            PipelineStep(
                name="dotnet_analysis",
                function=pipeline.analyzers["dotnet"].analyze_assembly,
                args={"binary_path": "test.exe"}
            )
        ]

        pipeline_file = Path(temp_dir) / "test_pipeline.yaml"

        success = pipeline.save_pipeline_definition(steps, str(pipeline_file))

        assert success is True
        assert pipeline_file.exists()

    def test_load_pipeline_definition(self, temp_dir):
        """Test loading pipeline definition"""
        pipeline = AutomatedAnalysisPipeline()

        # Create pipeline file
        pipeline_file = Path(temp_dir) / "test_pipeline.yaml"
        with open(pipeline_file, 'w') as f:
            f.write("""
steps:
  - name: dotnet_analysis
    function: analyze_assembly
    args:
      binary_path: test.exe
""")

        steps = pipeline.load_pipeline_definition(str(pipeline_file))

        assert isinstance(steps, list)
        assert len(steps) > 0
        assert steps[0].name == "dotnet_analysis"
