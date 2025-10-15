#!/usr/bin/env python3
"""
Test REVENG Installation
========================

This module tests that REVENG is properly installed and all dependencies are available.
"""

import pytest
import sys
import subprocess
from pathlib import Path


class TestInstallation:
    """Test REVENG installation and dependencies"""
    
    def test_python_version(self):
        """Test that Python version is 3.11 or higher"""
        assert sys.version_info >= (3, 11), f"Python 3.11+ required, got {sys.version_info}"
    
    def test_core_imports(self):
        """Test that core modules can be imported"""
        try:
            import requests
            import lief
            import keystone
            import capstone
            import networkx
            import yaml
        except ImportError as e:
            pytest.fail(f"Core dependency import failed: {e}")
    
    def test_reveng_analyzer_import(self):
        """Test that main analyzer can be imported"""
        try:
            from reveng_analyzer import REVENGAnalyzer
        except ImportError as e:
            pytest.fail(f"REVENGAnalyzer import failed: {e}")
    
    def test_tools_import(self):
        """Test that key tools can be imported"""
        try:
            from tools.language_detector import LanguageDetector
            from tools.ai_recompiler_converter import AIRecompilerConverter
            from tools.optimal_binary_analysis import OptimalBinaryAnalysis
        except ImportError as e:
            pytest.fail(f"Tools import failed: {e}")
    
    def test_java_availability(self):
        """Test that Java is available (optional)"""
        try:
            result = subprocess.run(['java', '-version'], 
                                  capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, "Java not available"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("Java not available (optional)")
    
    def test_ghidra_availability(self):
        """Test that Ghidra is available (optional)"""
        ghidra_path = Path.cwd() / "ghidra"
        if not ghidra_path.exists():
            pytest.skip("Ghidra not available (optional)")
    
    def test_compiler_availability(self):
        """Test that compiler toolchain is available"""
        compilers = ['gcc', 'clang']
        available_compilers = []
        
        for compiler in compilers:
            try:
                result = subprocess.run([compiler, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    available_compilers.append(compiler)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        assert len(available_compilers) > 0, f"No compilers available. Tried: {compilers}"
    
    def test_analysis_pipeline(self):
        """Test that analysis pipeline can be initialized"""
        from reveng_analyzer import REVENGAnalyzer
        
        # Test initialization without binary
        analyzer = REVENGAnalyzer()
        assert analyzer is not None
        
        # Test with binary path
        analyzer = REVENGAnalyzer("test_samples/HelloWorld.java")
        assert analyzer.binary_path == "test_samples/HelloWorld.java"
    
    def test_tool_chain_check(self):
        """Test that toolchain check script works"""
        try:
            result = subprocess.run([
                sys.executable, 'tools/check_toolchain.py', '--check-only'
            ], capture_output=True, text=True, timeout=30)
            
            # Toolchain check should not fail completely
            assert result.returncode in [0, 1], f"Toolchain check failed: {result.stderr}"
        except subprocess.TimeoutExpired:
            pytest.skip("Toolchain check timed out")
        except FileNotFoundError:
            pytest.skip("Toolchain check script not found")


class TestDependencies:
    """Test specific dependencies"""
    
    def test_requests_version(self):
        """Test requests version"""
        import requests
        assert requests.__version__ >= "2.28.0"
    
    def test_lief_version(self):
        """Test LIEF version"""
        import lief
        assert lief.__version__ >= "0.13.0"
    
    def test_keystone_version(self):
        """Test Keystone version"""
        import keystone
        assert keystone.__version__ >= "0.9.2"
    
    def test_capstone_version(self):
        """Test Capstone version"""
        import capstone
        assert capstone.__version__ >= "5.0.0"
    
    def test_networkx_version(self):
        """Test NetworkX version"""
        import networkx
        assert networkx.__version__ >= "3.0.0"


class TestFileStructure:
    """Test that required files and directories exist"""
    
    def test_main_files_exist(self):
        """Test that main files exist"""
        required_files = [
            'reveng_analyzer.py',
            'README.md',
            'LICENSE',
            'requirements.txt'
        ]
        
        for file in required_files:
            assert Path(file).exists(), f"Required file missing: {file}"
    
    def test_directories_exist(self):
        """Test that required directories exist"""
        required_dirs = [
            'tools',
            'tests',
            'examples',
            'docs'
        ]
        
        for dir_name in required_dirs:
            assert Path(dir_name).exists(), f"Required directory missing: {dir_name}"
    
    def test_tools_directory(self):
        """Test that tools directory has required files"""
        tools_dir = Path('tools')
        assert tools_dir.exists()
        
        # Check for key tool files
        key_tools = [
            'language_detector.py',
            'ai_recompiler_converter.py',
            'optimal_binary_analysis.py'
        ]
        
        for tool in key_tools:
            tool_path = tools_dir / tool
            if not tool_path.exists():
                pytest.skip(f"Tool not found: {tool}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
