"""
Unit tests for AutomatedAnalysisPipeline
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.pipeline.pipeline_engine import (
    AnalysisPipeline, PipelineStage, Pipeline, PipelineResult
)


class TestAutomatedAnalysisPipeline:
    """Test cases for AutomatedAnalysisPipeline"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.pipeline_engine = AnalysisPipeline()

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test AnalysisPipeline initialization"""
        assert self.pipeline_engine is not None
        assert hasattr(self.pipeline_engine, 'logger')
        assert hasattr(self.pipeline_engine, 'stage_executors')
        assert hasattr(self.pipeline_engine, 'pipeline_templates')

    def test_create_pipeline_success(self):
        """Test creating pipeline successfully"""
        pipeline_name = 'test_pipeline'

        # Create pipeline
        pipeline = self.pipeline_engine.create_pipeline(pipeline_name)

        assert isinstance(pipeline, Pipeline)
        assert pipeline.name == pipeline_name
        assert pipeline.stages == []
        assert pipeline.status == 'created'

    def test_create_pipeline_with_stages(self):
        """Test creating pipeline with initial stages"""
        pipeline_name = 'test_pipeline'
        stages = [
            PipelineStage('stage1', 'tool1', {'param1': 'value1'}),
            PipelineStage('stage2', 'tool2', {'param2': 'value2'})
        ]

        # Create pipeline
        pipeline = self.pipeline_engine.create_pipeline(pipeline_name, stages)

        assert isinstance(pipeline, Pipeline)
        assert pipeline.name == pipeline_name
        assert len(pipeline.stages) == 2
        assert pipeline.stages[0].name == 'stage1'
        assert pipeline.stages[1].name == 'stage2'
        assert pipeline.status == 'created'

    def test_add_stage_success(self):
        """Test adding stage to pipeline successfully"""
        # Create pipeline
        pipeline = self.pipeline_engine.create_pipeline('test_pipeline')

        # Add stage
        updated_pipeline = self.pipeline_engine.add_stage(
            pipeline, 'test_stage', 'test_tool', {'param': 'value'}
        )

        assert updated_pipeline is pipeline  # Should return same object
        assert len(pipeline.stages) == 1
        assert pipeline.stages[0].name == 'test_stage'
        assert pipeline.stages[0].tool == 'test_tool'
        assert pipeline.stages[0].config == {'param': 'value'}
        assert pipeline.stages[0].status == 'pending'

    def test_add_stage_multiple(self):
        """Test adding multiple stages to pipeline"""
        # Create pipeline
        pipeline = self.pipeline_engine.create_pipeline('test_pipeline')

        # Add multiple stages
        for i in range(3):
            self.pipeline_engine.add_stage(
                pipeline, f'stage_{i}', f'tool_{i}', {f'param_{i}': f'value_{i}'}
            )

        assert len(pipeline.stages) == 3
        for i in range(3):
            assert pipeline.stages[i].name == f'stage_{i}'
            assert pipeline.stages[i].tool == f'tool_{i}'
            assert pipeline.stages[i].config == {f'param_{i}': f'value_{i}'}
            assert pipeline.stages[i].status == 'pending'

    def test_execute_pipeline_success(self):
        """Test executing pipeline successfully"""
        # Create pipeline with stages
        pipeline = self.pipeline_engine.create_pipeline('test_pipeline')
        self.pipeline_engine.add_stage(pipeline, 'stage1', 'tool1', {'param1': 'value1'})
        self.pipeline_engine.add_stage(pipeline, 'stage2', 'tool2', {'param2': 'value2'})

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute pipeline
        result = self.pipeline_engine.execute_pipeline(pipeline, test_binary)

        assert isinstance(result, PipelineResult)
        assert result.pipeline_name == 'test_pipeline'
        assert result.status == 'completed'
        assert len(result.stage_results) == 2
        assert 'stage1' in result.stage_results
        assert 'stage2' in result.stage_results
        assert all(stage.status == 'completed' for stage in pipeline.stages)

    def test_execute_pipeline_failure(self):
        """Test executing pipeline with failure"""
        # Create pipeline with failing stage
        pipeline = self.pipeline_engine.create_pipeline('test_pipeline')
        self.pipeline_engine.add_stage(pipeline, 'stage1', 'tool1', {'param1': 'value1'})
        self.pipeline_engine.add_stage(pipeline, 'failing_stage', 'failing_tool', {'param': 'value'})

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute pipeline
        result = self.pipeline_engine.execute_pipeline(pipeline, test_binary)

        assert isinstance(result, PipelineResult)
        assert result.pipeline_name == 'test_pipeline'
        assert result.status == 'failed'
        assert len(result.stage_results) == 2
        assert 'stage1' in result.stage_results
        assert 'failing_stage' in result.stage_results
        assert pipeline.stages[0].status == 'completed'
        assert pipeline.stages[1].status == 'failed'

    def test_execute_pipeline_empty(self):
        """Test executing empty pipeline"""
        # Create empty pipeline
        pipeline = self.pipeline_engine.create_pipeline('empty_pipeline')

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute pipeline
        result = self.pipeline_engine.execute_pipeline(pipeline, test_binary)

        assert isinstance(result, PipelineResult)
        assert result.pipeline_name == 'empty_pipeline'
        assert result.status == 'completed'
        assert len(result.stage_results) == 0

    def test_save_pipeline_success(self):
        """Test saving pipeline successfully"""
        # Create pipeline
        pipeline = self.pipeline_engine.create_pipeline('test_pipeline')
        self.pipeline_engine.add_stage(pipeline, 'stage1', 'tool1', {'param1': 'value1'})

        # Save pipeline
        save_path = self.temp_dir / 'test_pipeline.yaml'
        self.pipeline_engine.save_pipeline(pipeline, save_path)

        assert save_path.exists()
        assert save_path.is_file()

    def test_save_pipeline_nonexistent_directory(self):
        """Test saving pipeline to nonexistent directory"""
        # Create pipeline
        pipeline = self.pipeline_engine.create_pipeline('test_pipeline')
        self.pipeline_engine.add_stage(pipeline, 'stage1', 'tool1', {'param1': 'value1'})

        # Save pipeline to nonexistent directory
        save_path = self.temp_dir / 'nonexistent' / 'test_pipeline.yaml'
        self.pipeline_engine.save_pipeline(pipeline, save_path)

        assert save_path.exists()
        assert save_path.is_file()

    def test_load_pipeline_success(self):
        """Test loading pipeline successfully"""
        # Create and save pipeline
        pipeline = self.pipeline_engine.create_pipeline('test_pipeline')
        self.pipeline_engine.add_stage(pipeline, 'stage1', 'tool1', {'param1': 'value1'})

        save_path = self.temp_dir / 'test_pipeline.yaml'
        self.pipeline_engine.save_pipeline(pipeline, save_path)

        # Load pipeline
        loaded_pipeline = self.pipeline_engine.load_pipeline(save_path)

        assert isinstance(loaded_pipeline, Pipeline)
        assert loaded_pipeline.name == 'test_pipeline'
        assert len(loaded_pipeline.stages) == 1
        assert loaded_pipeline.stages[0].name == 'stage1'
        assert loaded_pipeline.stages[0].tool == 'tool1'
        assert loaded_pipeline.stages[0].config == {'param1': 'value1'}

    def test_load_pipeline_nonexistent(self):
        """Test loading nonexistent pipeline"""
        nonexistent_path = self.temp_dir / 'nonexistent_pipeline.yaml'

        # Load pipeline
        loaded_pipeline = self.pipeline_engine.load_pipeline(nonexistent_path)

        assert isinstance(loaded_pipeline, Pipeline)
        assert loaded_pipeline.name == 'nonexistent_pipeline'
        assert loaded_pipeline.stages == []

    def test_pipeline_stage_properties(self):
        """Test PipelineStage properties"""
        stage = PipelineStage('test_stage', 'test_tool', {'param': 'value'})

        assert stage.name == 'test_stage'
        assert stage.tool == 'test_tool'
        assert stage.config == {'param': 'value'}
        assert stage.result is None
        assert stage.status == 'pending'

    def test_pipeline_properties(self):
        """Test Pipeline properties"""
        pipeline = Pipeline('test_pipeline')

        assert pipeline.name == 'test_pipeline'
        assert pipeline.stages == []
        assert pipeline.status == 'created'

    def test_pipeline_result_properties(self):
        """Test PipelineResult properties"""
        result = PipelineResult('test_pipeline', 'completed', {'stage1': 'result1'})

        assert result.pipeline_name == 'test_pipeline'
        assert result.status == 'completed'
        assert result.stage_results == {'stage1': 'result1'}

    def test_pipeline_engine_with_large_binary(self):
        """Test pipeline engine with large binary"""
        # Create large test binary
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        # Create pipeline
        pipeline = self.pipeline_engine.create_pipeline('large_pipeline')
        self.pipeline_engine.add_stage(pipeline, 'stage1', 'tool1', {'param1': 'value1'})

        # Execute pipeline
        result = self.pipeline_engine.execute_pipeline(pipeline, test_binary)

        assert isinstance(result, PipelineResult)
        assert result.pipeline_name == 'large_pipeline'
        assert result.status == 'completed'
        assert len(result.stage_results) == 1

    def test_pipeline_engine_with_multiple_binaries(self):
        """Test pipeline engine with multiple binaries"""
        # Create multiple test binaries
        test_binaries = []
        for i in range(3):
            binary_path = self.temp_dir / f'test_{i}.exe'
            binary_path.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)
            test_binaries.append(binary_path)

        # Create pipeline
        pipeline = self.pipeline_engine.create_pipeline('multi_pipeline')
        self.pipeline_engine.add_stage(pipeline, 'stage1', 'tool1', {'param1': 'value1'})

        # Execute pipeline for each binary
        results = []
        for binary in test_binaries:
            result = self.pipeline_engine.execute_pipeline(pipeline, binary)
            results.append(result)

        assert len(results) == 3
        assert all(isinstance(result, PipelineResult) for result in results)
        assert all(result.pipeline_name == 'multi_pipeline' for result in results)
        assert all(result.status == 'completed' for result in results)

    def test_pipeline_engine_with_complex_pipeline(self):
        """Test pipeline engine with complex pipeline"""
        # Create complex pipeline
        pipeline = self.pipeline_engine.create_pipeline('complex_pipeline')

        # Add multiple stages
        stages = [
            ('stage1', 'tool1', {'param1': 'value1'}),
            ('stage2', 'tool2', {'param2': 'value2'}),
            ('stage3', 'tool3', {'param3': 'value3'}),
            ('stage4', 'tool4', {'param4': 'value4'})
        ]

        for name, tool, config in stages:
            self.pipeline_engine.add_stage(pipeline, name, tool, config)

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute pipeline
        result = self.pipeline_engine.execute_pipeline(pipeline, test_binary)

        assert isinstance(result, PipelineResult)
        assert result.pipeline_name == 'complex_pipeline'
        assert result.status == 'completed'
        assert len(result.stage_results) == 4
        assert all(stage.status == 'completed' for stage in pipeline.stages)
