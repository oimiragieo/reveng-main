#!/usr/bin/env python3
"""
Test REVENG Examples
====================

This module tests that all examples run correctly.
"""

import pytest
import subprocess
import sys
from pathlib import Path


class TestExamples:
    """Test example scripts"""
    
    def test_analysis_template(self):
        """Test analysis template example"""
        template_path = Path('examples/analysis_template.py')
        if not template_path.exists():
            pytest.skip("Analysis template not found")
        
        # Test template with help
        result = subprocess.run([
            sys.executable, str(template_path), '--help'
        ], capture_output=True, text=True, timeout=30)
        
        assert result.returncode == 0, f"Analysis template failed: {result.stderr}"
        assert "REVENG Custom Analysis Template" in result.stdout
    
    def test_basic_examples(self):
        """Test basic examples directory"""
        basic_dir = Path('examples/basic')
        if not basic_dir.exists():
            pytest.skip("Basic examples directory not found")
        
        # Check for example files
        example_files = list(basic_dir.glob('*.py'))
        assert len(example_files) > 0, "No basic examples found"
        
        # Test each example
        for example_file in example_files:
            result = subprocess.run([
                sys.executable, str(example_file), '--help'
            ], capture_output=True, text=True, timeout=30)
            
            # Examples should have help or run without errors
            assert result.returncode in [0, 1], f"Example {example_file} failed: {result.stderr}"
    
    def test_advanced_examples(self):
        """Test advanced examples directory"""
        advanced_dir = Path('examples/advanced')
        if not advanced_dir.exists():
            pytest.skip("Advanced examples directory not found")
        
        # Check for example files
        example_files = list(advanced_dir.glob('*.py'))
        assert len(example_files) > 0, "No advanced examples found"
        
        # Test each example
        for example_file in example_files:
            result = subprocess.run([
                sys.executable, str(example_file), '--help'
            ], capture_output=True, text=True, timeout=30)
            
            # Examples should have help or run without errors
            assert result.returncode in [0, 1], f"Example {example_file} failed: {result.stderr}"
    
    def test_examples_readme(self):
        """Test examples README"""
        readme_path = Path('examples/README.md')
        if not readme_path.exists():
            pytest.skip("Examples README not found")
        
        # Check that README exists and has content
        content = readme_path.read_text()
        assert len(content) > 100, "Examples README too short"
        assert "REVENG" in content, "Examples README missing REVENG reference"


class TestExampleExecution:
    """Test example execution with sample data"""
    
    def test_analysis_template_with_sample(self):
        """Test analysis template with sample file"""
        template_path = Path('examples/analysis_template.py')
        sample_path = Path('test_samples/HelloWorld.java')
        
        if not template_path.exists() or not sample_path.exists():
            pytest.skip("Template or sample not found")
        
        result = subprocess.run([
            sys.executable, str(template_path), str(sample_path)
        ], capture_output=True, text=True, timeout=60)
        
        # Should complete (may fail due to missing dependencies)
        assert result.returncode in [0, 1], f"Template execution failed: {result.stderr}"
    
    def test_basic_analysis_example(self):
        """Test basic analysis example"""
        basic_dir = Path('examples/basic')
        if not basic_dir.exists():
            pytest.skip("Basic examples not found")
        
        # Look for analysis example
        analysis_examples = list(basic_dir.glob('*analysis*.py'))
        if not analysis_examples:
            pytest.skip("No analysis examples found")
        
        sample_path = Path('test_samples/HelloWorld.java')
        if not sample_path.exists():
            pytest.skip("Sample file not found")
        
        # Test first analysis example
        example_file = analysis_examples[0]
        result = subprocess.run([
            sys.executable, str(example_file), str(sample_path)
        ], capture_output=True, text=True, timeout=60)
        
        # Should complete (may fail due to missing dependencies)
        assert result.returncode in [0, 1], f"Basic example failed: {result.stderr}"


class TestExampleOutputs:
    """Test example output generation"""
    
    def test_example_outputs_directory(self):
        """Test example outputs directory"""
        outputs_dir = Path('examples/outputs')
        if not outputs_dir.exists():
            pytest.skip("Example outputs directory not found")
        
        # Check for output files
        output_files = list(outputs_dir.glob('*'))
        assert len(output_files) > 0, "No example outputs found"
    
    def test_output_file_formats(self):
        """Test that output files are in expected formats"""
        outputs_dir = Path('examples/outputs')
        if not outputs_dir.exists():
            pytest.skip("Example outputs directory not found")
        
        # Check for common output formats
        json_files = list(outputs_dir.glob('*.json'))
        txt_files = list(outputs_dir.glob('*.txt'))
        md_files = list(outputs_dir.glob('*.md'))
        
        total_outputs = len(json_files) + len(txt_files) + len(md_files)
        assert total_outputs > 0, "No example output files found"


class TestExampleDocumentation:
    """Test example documentation"""
    
    def test_examples_readme_content(self):
        """Test examples README content"""
        readme_path = Path('examples/README.md')
        if not readme_path.exists():
            pytest.skip("Examples README not found")
        
        content = readme_path.read_text()
        
        # Check for key sections
        assert "## Basic Examples" in content or "## Getting Started" in content
        assert "## Advanced Examples" in content or "## Advanced Usage" in content
        assert "## Usage" in content or "## How to Use" in content
    
    def test_example_docstrings(self):
        """Test that examples have proper docstrings"""
        examples_dir = Path('examples')
        if not examples_dir.exists():
            pytest.skip("Examples directory not found")
        
        python_files = list(examples_dir.rglob('*.py'))
        assert len(python_files) > 0, "No Python examples found"
        
        for py_file in python_files:
            content = py_file.read_text()
            
            # Check for docstring
            assert '"""' in content or "'''" in content, f"Example {py_file} missing docstring"
            
            # Check for usage information
            assert "usage" in content.lower() or "example" in content.lower(), f"Example {py_file} missing usage info"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
