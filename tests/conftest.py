"""
REVENG Test Configuration and Fixtures
=====================================

Pytest configuration and shared fixtures for the REVENG test suite.

Author: REVENG Development Team
Version: 2.1.0
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any
import sys
import os

# Add src to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    """Get the test data directory."""
    return Path(__file__).parent / "fixtures"

@pytest.fixture(scope="session")
def sample_binaries_dir() -> Path:
    """Get the sample binaries directory."""
    return Path(__file__).parent / "fixtures" / "binaries"

@pytest.fixture(scope="session")
def expected_outputs_dir() -> Path:
    """Get the expected outputs directory."""
    return Path(__file__).parent / "fixtures" / "expected_outputs"

@pytest.fixture
def temp_analysis_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for analysis output."""
    temp_dir = tempfile.mkdtemp(prefix="reveng_test_")
    try:
        yield Path(temp_dir)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def mock_binary_file(temp_analysis_dir: Path) -> Path:
    """Create a mock binary file for testing."""
    binary_path = temp_analysis_dir / "test_binary.exe"
    # Create a simple PE file header for testing
    with open(binary_path, "wb") as f:
        f.write(b"MZ\x90\x00" + b"\x00" * 100)  # Minimal PE header
    return binary_path

@pytest.fixture
def mock_java_jar(temp_analysis_dir: Path) -> Path:
    """Create a mock Java JAR file for testing."""
    jar_path = temp_analysis_dir / "test_app.jar"
    # Create a minimal JAR file
    with open(jar_path, "wb") as f:
        f.write(b"PK\x03\x04" + b"\x00" * 50)  # Minimal ZIP/JAR header
    return jar_path

@pytest.fixture
def mock_csharp_dll(temp_analysis_dir: Path) -> Path:
    """Create a mock C# DLL file for testing."""
    dll_path = temp_analysis_dir / "test_library.dll"
    # Create a minimal .NET assembly
    with open(dll_path, "wb") as f:
        f.write(b"MZ\x90\x00" + b"\x00" * 100)  # Minimal PE header
    return dll_path

@pytest.fixture
def mock_python_pyc(temp_analysis_dir: Path) -> Path:
    """Create a mock Python bytecode file for testing."""
    pyc_path = temp_analysis_dir / "test_module.pyc"
    # Create a minimal Python bytecode file
    with open(pyc_path, "wb") as f:
        f.write(b"\x42\x0d\x0d\x0a" + b"\x00" * 20)  # Minimal .pyc header
    return pyc_path

@pytest.fixture
def analysis_config() -> Dict[str, Any]:
    """Get a test analysis configuration."""
    return {
        "ai": {
            "provider": "ollama",
            "model": "llama2",
            "enabled": True,
            "ollama_host": "http://localhost:11434"
        },
        "analysis": {
            "enhanced_features": True,
            "timeout": 300,
            "max_memory": 2048
        },
        "output": {
            "format": "json",
            "directory": "./analysis_results"
        }
    }

@pytest.fixture
def mock_enhanced_features():
    """Create mock enhanced analysis features."""
    from src.reveng.analyzer import EnhancedAnalysisFeatures

    features = EnhancedAnalysisFeatures()
    features.enable_enhanced_analysis = True
    features.enable_corporate_exposure = True
    features.enable_vulnerability_discovery = True
    features.enable_threat_intelligence = True
    features.enable_enhanced_reconstruction = True
    features.enable_demonstration_generation = True

    return features

@pytest.fixture
def mock_analyzer(mock_binary_file: Path, analysis_config: Dict[str, Any]):
    """Create a mock REVENG analyzer for testing."""
    from src.reveng.analyzer import REVENGAnalyzer

    analyzer = REVENGAnalyzer(
        binary_path=str(mock_binary_file),
        check_ollama=False,  # Skip Ollama check in tests
        enhanced_features=None
    )

    return analyzer

@pytest.fixture(scope="session")
def test_environment():
    """Set up test environment variables."""
    original_env = os.environ.copy()

    # Set test environment variables
    os.environ.update({
        "REVENG_ENV": "test",
        "REVENG_LOG_LEVEL": "DEBUG",
        "REVENG_AI_PROVIDER": "mock",
        "REVENG_AI_ENABLED": "false"
    })

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)

@pytest.fixture
def mock_web_server():
    """Mock web server for testing web interface."""
    import threading
    import time
    from http.server import HTTPServer, SimpleHTTPRequestHandler

    class TestHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')

    server = HTTPServer(('localhost', 0), TestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    yield server.server_address[1]

    server.shutdown()
    server_thread.join(timeout=1)

# Performance testing fixtures
@pytest.fixture
def performance_benchmark():
    """Fixture for performance benchmarking."""
    import time

    class PerformanceBenchmark:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.time()

        def stop(self):
            self.end_time = time.time()
            return self.end_time - self.start_time

        @property
        def duration(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

    return PerformanceBenchmark()

# Coverage configuration
def pytest_configure(config):
    """Configure pytest for coverage reporting."""
    config.addinivalue_line(
        "markers", "unit: Unit tests"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests"
    )
    config.addinivalue_line(
        "markers", "e2e: End-to-end tests"
    )
    config.addinivalue_line(
        "markers", "performance: Performance tests"
    )
    config.addinivalue_line(
        "markers", "slow: Slow running tests"
    )

def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on directory."""
    for item in items:
        # Add markers based on test file location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
        elif "performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)

        # Mark slow tests
        if "slow" in item.name or "benchmark" in item.name:
            item.add_marker(pytest.mark.slow)
