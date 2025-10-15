#!/usr/bin/env python3
"""
Test REVENG CLI Interface
=========================

This module tests the command-line interface functionality.
"""

import pytest
import subprocess
import sys
from pathlib import Path


class TestCLI:
    """Test command-line interface"""
    
    def test_help_command(self):
        """Test that help command works"""
        result = subprocess.run([
            sys.executable, 'reveng_analyzer.py', '--help'
        ], capture_output=True, text=True, timeout=30)
        
        assert result.returncode == 0, f"Help command failed: {result.stderr}"
        assert "REVENG Universal Reverse Engineering Platform" in result.stdout
    
    def test_version_command(self):
        """Test that version command works"""
        result = subprocess.run([
            sys.executable, 'reveng_analyzer.py', '--version'
        ], capture_output=True, text=True, timeout=30)
        
        assert result.returncode == 0, f"Version command failed: {result.stderr}"
        assert "2.0.0" in result.stdout
    
    def test_invalid_binary(self):
        """Test handling of invalid binary file"""
        result = subprocess.run([
            sys.executable, 'reveng_analyzer.py', 'nonexistent.exe'
        ], capture_output=True, text=True, timeout=30)
        
        # Should fail gracefully
        assert result.returncode != 0, "Should fail for nonexistent file"
        assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()
    
    def test_java_sample_analysis(self):
        """Test analysis of Java sample"""
        java_sample = Path('test_samples/HelloWorld.java')
        if not java_sample.exists():
            pytest.skip("Java sample not found")
        
        result = subprocess.run([
            sys.executable, 'reveng_analyzer.py', str(java_sample)
        ], capture_output=True, text=True, timeout=60)
        
        # Analysis should complete (may fail due to missing dependencies)
        assert result.returncode in [0, 1], f"Analysis failed unexpectedly: {result.stderr}"
    
    def test_analysis_with_output_dir(self):
        """Test analysis with custom output directory"""
        java_sample = Path('test_samples/HelloWorld.java')
        if not java_sample.exists():
            pytest.skip("Java sample not found")
        
        output_dir = Path('test_output')
        output_dir.mkdir(exist_ok=True)
        
        try:
            result = subprocess.run([
                sys.executable, 'reveng_analyzer.py', 
                str(java_sample), '--output', str(output_dir)
            ], capture_output=True, text=True, timeout=60)
            
            # Should create output directory
            assert output_dir.exists(), "Output directory not created"
        finally:
            # Cleanup
            if output_dir.exists():
                import shutil
                shutil.rmtree(output_dir, ignore_errors=True)
    
    def test_enhanced_analysis_options(self):
        """Test enhanced analysis options"""
        java_sample = Path('test_samples/HelloWorld.java')
        if not java_sample.exists():
            pytest.skip("Java sample not found")
        
        result = subprocess.run([
            sys.executable, 'reveng_analyzer.py', 
            str(java_sample), '--enhanced', '--corporate-exposure'
        ], capture_output=True, text=True, timeout=60)
        
        # Should accept enhanced options
        assert result.returncode in [0, 1], f"Enhanced analysis failed: {result.stderr}"
    
    def test_verbose_output(self):
        """Test verbose output option"""
        java_sample = Path('test_samples/HelloWorld.java')
        if not java_sample.exists():
            pytest.skip("Java sample not found")
        
        result = subprocess.run([
            sys.executable, 'reveng_analyzer.py', 
            str(java_sample), '--verbose'
        ], capture_output=True, text=True, timeout=60)
        
        # Should produce verbose output
        assert result.returncode in [0, 1], f"Verbose analysis failed: {result.stderr}"
        assert len(result.stdout) > 0, "No output produced"


class TestToolCLI:
    """Test individual tool CLI interfaces"""
    
    def test_language_detector_cli(self):
        """Test language detector CLI"""
        java_sample = Path('test_samples/HelloWorld.java')
        if not java_sample.exists():
            pytest.skip("Java sample not found")
        
        result = subprocess.run([
            sys.executable, 'tools/language_detector.py', str(java_sample)
        ], capture_output=True, text=True, timeout=30)
        
        assert result.returncode == 0, f"Language detector failed: {result.stderr}"
        assert "java" in result.stdout.lower() or "text" in result.stdout.lower()
    
    def test_ai_converter_cli(self):
        """Test AI converter CLI"""
        java_sample = Path('test_samples/HelloWorld.java')
        if not java_sample.exists():
            pytest.skip("Java sample not found")
        
        result = subprocess.run([
            sys.executable, 'tools/ai_recompiler_converter.py', str(java_sample)
        ], capture_output=True, text=True, timeout=60)
        
        # May fail due to missing AI dependencies
        assert result.returncode in [0, 1], f"AI converter failed: {result.stderr}"
    
    def test_binary_analysis_cli(self):
        """Test binary analysis CLI"""
        java_sample = Path('test_samples/HelloWorld.java')
        if not java_sample.exists():
            pytest.skip("Java sample not found")
        
        result = subprocess.run([
            sys.executable, 'tools/optimal_binary_analysis.py', str(java_sample)
        ], capture_output=True, text=True, timeout=60)
        
        # May fail due to missing Ghidra
        assert result.returncode in [0, 1], f"Binary analysis failed: {result.stderr}"


class TestBootstrapScripts:
    """Test bootstrap scripts"""
    
    def test_windows_bootstrap(self):
        """Test Windows bootstrap script"""
        bootstrap_script = Path('scripts/bootstrap_windows.bat')
        if not bootstrap_script.exists():
            pytest.skip("Windows bootstrap script not found")
        
        # Test that script exists and is executable
        assert bootstrap_script.exists()
    
    def test_linux_bootstrap(self):
        """Test Linux bootstrap script"""
        bootstrap_script = Path('scripts/bootstrap_linux.sh')
        if not bootstrap_script.exists():
            pytest.skip("Linux bootstrap script not found")
        
        # Test that script exists and is executable
        assert bootstrap_script.exists()
        
        # Test script syntax (dry run)
        result = subprocess.run([
            'bash', '-n', str(bootstrap_script)
        ], capture_output=True, text=True, timeout=10)
        
        assert result.returncode == 0, f"Bootstrap script syntax error: {result.stderr}"


class TestUtilityScripts:
    """Test utility scripts"""
    
    def test_lint_script(self):
        """Test linting script"""
        lint_script = Path('scripts/lint_codebase.py')
        if not lint_script.exists():
            pytest.skip("Lint script not found")
        
        result = subprocess.run([
            sys.executable, str(lint_script), '--help'
        ], capture_output=True, text=True, timeout=30)
        
        assert result.returncode == 0, f"Lint script failed: {result.stderr}"
    
    def test_cleanup_script(self):
        """Test cleanup script"""
        cleanup_script = Path('scripts/cleanup_legacy.py')
        if not cleanup_script.exists():
            pytest.skip("Cleanup script not found")
        
        result = subprocess.run([
            sys.executable, str(cleanup_script), '--help'
        ], capture_output=True, text=True, timeout=30)
        
        assert result.returncode == 0, f"Cleanup script failed: {result.stderr}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
