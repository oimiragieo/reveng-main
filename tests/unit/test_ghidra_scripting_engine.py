"""
Unit tests for GhidraScriptEngine
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.ghidra.scripting_engine import (
    GhidraScriptEngine, ScriptResult, GhidraProject, ExportResult
)


class TestGhidraScriptEngine:
    """Test cases for GhidraScriptEngine"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.ghidra_headless_path = self.temp_dir / 'ghidra_headless'
        self.ghidra_scripts_path = self.temp_dir / 'ghidra_scripts'

        # Create mock Ghidra headless executable
        self.ghidra_headless_path.write_text('#!/bin/bash\necho "Ghidra headless"')
        self.ghidra_headless_path.chmod(0o755)

        # Create mock scripts directory
        self.ghidra_scripts_path.mkdir(parents=True, exist_ok=True)

        # Initialize script engine
        self.script_engine = GhidraScriptEngine(
            self.ghidra_headless_path,
            self.ghidra_scripts_path
        )

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test GhidraScriptEngine initialization"""
        assert self.script_engine is not None
        assert self.script_engine.ghidra_headless_path == self.ghidra_headless_path
        assert self.script_engine.ghidra_scripts_path == self.ghidra_scripts_path
        assert hasattr(self.script_engine, 'logger')

    def test_run_ghidra_command_success(self):
        """Test running Ghidra command successfully"""
        # Create mock script
        script_path = self.ghidra_scripts_path / 'test_script.py'
        script_path.write_text('print("Hello from Ghidra script")')

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Run command
        result = self.script_engine._run_ghidra_command([
            str(self.temp_dir),
            'test_project',
            '-import', str(test_binary),
            '-postscript', str(script_path)
        ])

        assert result.returncode == 0
        assert 'Hello from Ghidra script' in result.stdout

    def test_run_ghidra_command_failure(self):
        """Test running Ghidra command with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Run command with invalid arguments
        result = self.script_engine._run_ghidra_command([
            str(self.temp_dir),
            'test_project',
            '-import', str(test_binary),
            '-invalid-argument'
        ])

        assert result.returncode != 0
        assert result.stderr is not None

    def test_execute_python_script_success(self):
        """Test executing Python script successfully"""
        # Create mock Python script
        script_path = self.ghidra_scripts_path / 'test_script.py'
        script_path.write_text('print("Python script executed")')

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute script
        result = self.script_engine.execute_python_script(
            script_path, test_binary, 'test_project'
        )

        assert isinstance(result, ScriptResult)
        assert result.success is True
        assert 'Python script executed' in result.stdout
        assert result.stderr == ''
        assert result.output_path is None

    def test_execute_python_script_failure(self):
        """Test executing Python script with failure"""
        # Create mock Python script that will fail
        script_path = self.ghidra_scripts_path / 'failing_script.py'
        script_path.write_text('import nonexistent_module')

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute script
        result = self.script_engine.execute_python_script(
            script_path, test_binary, 'test_project'
        )

        assert isinstance(result, ScriptResult)
        assert result.success is False
        assert result.stderr is not None
        assert result.output_path is None

    def test_execute_java_script_success(self):
        """Test executing Java script successfully"""
        # Create mock Java script
        script_path = self.ghidra_scripts_path / 'test_script.java'
        script_path.write_text('public class TestScript { public static void main(String[] args) { System.out.println("Java script executed"); } }')

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute script
        result = self.script_engine.execute_java_script(
            script_path, test_binary, 'test_project'
        )

        assert isinstance(result, ScriptResult)
        assert result.success is True
        assert 'Java script executed' in result.stdout
        assert result.stderr == ''
        assert result.output_path is None

    def test_execute_java_script_failure(self):
        """Test executing Java script with failure"""
        # Create mock Java script that will fail
        script_path = self.ghidra_scripts_path / 'failing_script.java'
        script_path.write_text('public class FailingScript { public static void main(String[] args) { System.out.println(nonexistent_variable); } }')

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute script
        result = self.script_engine.execute_java_script(
            script_path, test_binary, 'test_project'
        )

        assert isinstance(result, ScriptResult)
        assert result.success is False
        assert result.stderr is not None
        assert result.output_path is None

    def test_batch_analyze_success(self):
        """Test batch analysis successfully"""
        # Create mock script
        script_path = self.ghidra_scripts_path / 'batch_script.py'
        script_path.write_text('print("Batch script executed")')

        # Create test binaries
        test_binaries = []
        for i in range(3):
            binary_path = self.temp_dir / f'test_{i}.exe'
            binary_path.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)
            test_binaries.append(binary_path)

        # Execute batch analysis
        results = self.script_engine.batch_analyze(
            test_binaries, script_path, 'batch_project'
        )

        assert isinstance(results, list)
        assert len(results) == 3
        assert all(isinstance(result, ScriptResult) for result in results)
        assert all(result.success is True for result in results)
        assert all('Batch script executed' in result.stdout for result in results)

    def test_batch_analyze_failure(self):
        """Test batch analysis with failure"""
        # Create mock script that will fail
        script_path = self.ghidra_scripts_path / 'failing_batch_script.py'
        script_path.write_text('import nonexistent_module')

        # Create test binaries
        test_binaries = []
        for i in range(3):
            binary_path = self.temp_dir / f'test_{i}.exe'
            binary_path.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)
            test_binaries.append(binary_path)

        # Execute batch analysis
        results = self.script_engine.batch_analyze(
            test_binaries, script_path, 'batch_project'
        )

        assert isinstance(results, list)
        assert len(results) == 3
        assert all(isinstance(result, ScriptResult) for result in results)
        assert all(result.success is False for result in results)
        assert all(result.stderr is not None for result in results)

    def test_create_ghidra_project_success(self):
        """Test creating Ghidra project successfully"""
        project_name = 'test_project'
        project_location = self.temp_dir / 'ghidra_projects'

        # Create project
        project = self.script_engine.create_ghidra_project(project_name, project_location)

        assert isinstance(project, GhidraProject)
        assert project.name == project_name
        assert project.path == project_location / project_name
        assert project_location.exists()
        assert (project_location / project_name).exists()

    def test_create_ghidra_project_existing(self):
        """Test creating Ghidra project when directory already exists"""
        project_name = 'existing_project'
        project_location = self.temp_dir / 'ghidra_projects'
        project_location.mkdir(parents=True, exist_ok=True)
        (project_location / project_name).mkdir(parents=True, exist_ok=True)

        # Create project
        project = self.script_engine.create_ghidra_project(project_name, project_location)

        assert isinstance(project, GhidraProject)
        assert project.name == project_name
        assert project.path == project_location / project_name

    def test_export_analysis_results_success(self):
        """Test exporting analysis results successfully"""
        project_path = self.temp_dir / 'ghidra_projects'
        project_name = 'test_project'
        binary_name = 'test.exe'
        output_path = self.temp_dir / 'export.xml'

        # Create project directory
        project_path.mkdir(parents=True, exist_ok=True)

        # Export results
        result = self.script_engine.export_analysis_results(
            project_path, project_name, binary_name, 'XML', output_path
        )

        assert isinstance(result, ExportResult)
        assert result.success is True
        assert result.output_path == output_path
        assert result.message is not None

    def test_export_analysis_results_failure(self):
        """Test exporting analysis results with failure"""
        project_path = self.temp_dir / 'nonexistent_projects'
        project_name = 'nonexistent_project'
        binary_name = 'nonexistent.exe'
        output_path = self.temp_dir / 'export.xml'

        # Export results
        result = self.script_engine.export_analysis_results(
            project_path, project_name, binary_name, 'XML', output_path
        )

        assert isinstance(result, ExportResult)
        assert result.success is False
        assert result.output_path == output_path
        assert result.message is not None

    def test_script_result_properties(self):
        """Test ScriptResult properties"""
        result = ScriptResult(
            success=True,
            stdout='test output',
            stderr='test error',
            output_path=Path('test.xml')
        )

        assert result.success is True
        assert result.stdout == 'test output'
        assert result.stderr == 'test error'
        assert result.output_path == Path('test.xml')

    def test_ghidra_project_properties(self):
        """Test GhidraProject properties"""
        project = GhidraProject(name='test_project', path=Path('test_path'))

        assert project.name == 'test_project'
        assert project.path == Path('test_path')

    def test_export_result_properties(self):
        """Test ExportResult properties"""
        result = ExportResult(
            success=True,
            output_path=Path('test.xml'),
            message='test message'
        )

        assert result.success is True
        assert result.output_path == Path('test.xml')
        assert result.message == 'test message'

    def test_script_engine_with_custom_project_location(self):
        """Test script engine with custom project location"""
        custom_location = self.temp_dir / 'custom_ghidra_projects'

        # Create project
        project = self.script_engine.create_ghidra_project('custom_project', custom_location)

        assert isinstance(project, GhidraProject)
        assert project.name == 'custom_project'
        assert project.path == custom_location / 'custom_project'
        assert custom_location.exists()
        assert (custom_location / 'custom_project').exists()

    def test_script_engine_with_multiple_scripts(self):
        """Test script engine with multiple scripts"""
        # Create multiple scripts
        scripts = []
        for i in range(3):
            script_path = self.ghidra_scripts_path / f'script_{i}.py'
            script_path.write_text(f'print("Script {i} executed")')
            scripts.append(script_path)

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Execute each script
        results = []
        for script in scripts:
            result = self.script_engine.execute_python_script(
                script, test_binary, f'project_{script.stem}'
            )
            results.append(result)

        assert len(results) == 3
        assert all(isinstance(result, ScriptResult) for result in results)
        assert all(result.success is True for result in results)

    def test_script_engine_with_large_binary(self):
        """Test script engine with large binary"""
        # Create large test binary
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        # Create mock script
        script_path = self.ghidra_scripts_path / 'large_script.py'
        script_path.write_text('print("Large binary processed")')

        # Execute script
        result = self.script_engine.execute_python_script(
            script_path, test_binary, 'large_project'
        )

        assert isinstance(result, ScriptResult)
        assert result.success is True
        assert 'Large binary processed' in result.stdout
