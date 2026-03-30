#!/usr/bin/env python3
"""
Integration tests for the symbolic execution engine.

These checks cover deterministic engine initialization and configuration behavior
without depending on vulnerability discovery results.
"""

import os
import subprocess
import tempfile

import pytest


def _cleanup_if_exists(path: str | None):
    """Best-effort cleanup for temporary compilation artifacts."""
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except PermissionError:
            pass


@pytest.mark.integration
def test_symbolic_execution_basic():
    """Test basic symbolic execution engine initialization."""
    try:
        from reveng.security.symbolic_execution_engine import SymbolicExecutionEngine

        test_code = """
#include <stdio.h>
int main() { return 0; }
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(test_code)
            source = f.name

        binary = source.replace(".c", ".out")
        subprocess.run(["gcc", source, "-o", binary], timeout=10, check=False)

        try:
            engine = SymbolicExecutionEngine(binary, analysis_depth="shallow")

            assert engine.project is not None
            assert engine.max_paths > 0

        finally:
            _cleanup_if_exists(source)
            _cleanup_if_exists(binary)

    except ImportError as e:
        pytest.skip(f"angr not available: {e}")


@pytest.mark.integration
def test_vulnerability_type_coverage():
    """Test that the engine exposes its vulnerability taxonomy and sink coverage."""
    try:
        from reveng.security.symbolic_execution_engine import (
            SymbolicExecutionEngine,
            VulnerabilityType,
        )

        vuln_types = list(VulnerabilityType)

        assert len(vuln_types) >= 10
        assert len(SymbolicExecutionEngine.DANGEROUS_FUNCTIONS) >= 10
        assert "strcpy" in SymbolicExecutionEngine.DANGEROUS_FUNCTIONS
        assert "printf" in SymbolicExecutionEngine.DANGEROUS_FUNCTIONS

    except ImportError as e:
        pytest.skip(f"Dependencies not available: {e}")


@pytest.mark.integration
def test_analysis_depth_configurations():
    """Test different symbolic analysis depth configurations."""
    try:
        from reveng.security.symbolic_execution_engine import SymbolicExecutionEngine

        test_code = "int main() { return 0; }"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(test_code)
            source = f.name

        binary = source.replace(".c", ".out")
        subprocess.run(["gcc", source, "-o", binary], timeout=10, check=False)

        try:
            depths = ["shallow", "medium", "deep"]
            configs = {}

            for depth in depths:
                engine = SymbolicExecutionEngine(binary, analysis_depth=depth)
                configs[depth] = {"max_paths": engine.max_paths, "timeout": engine.timeout}

            assert configs["shallow"]["max_paths"] < configs["medium"]["max_paths"]
            assert configs["medium"]["max_paths"] < configs["deep"]["max_paths"]
            assert configs["shallow"]["timeout"] < configs["medium"]["timeout"]
            assert configs["medium"]["timeout"] < configs["deep"]["timeout"]

        finally:
            _cleanup_if_exists(source)
            _cleanup_if_exists(binary)

    except ImportError as e:
        pytest.skip(f"Dependencies not available: {e}")
