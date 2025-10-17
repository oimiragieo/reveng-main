"""
REVENG Test Configuration

Comprehensive test configuration for REVENG with fixtures for all test categories.
"""

import pytest
import tempfile
import shutil
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from unittest.mock import Mock, patch

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from reveng.core.logger import setup_logging
from reveng.core.dependency_manager import DependencyManager
from reveng.analyzers.dotnet_analyzer import DotNetAnalyzer
from reveng.pe.resource_extractor import PEResourceExtractor
from reveng.pe.import_analyzer import ImportAnalyzer
from reveng.analyzers.business_logic_extractor import BusinessLogicExtractor
from reveng.ghidra.scripting_engine import GhidraScriptingEngine
from reveng.tools.hex_editor import HexEditor
from reveng.pipelines.automated_analysis import AutomatedAnalysisPipeline
from reveng.plugins.manager import PluginManager
from reveng.malware.behavioral_monitor import BehavioralMonitor
from reveng.malware.memory_forensics import MemoryForensics
from reveng.ml import MLIntegration, MLIntegrationConfig

@pytest.fixture(scope="session")
def test_logger():
    """Setup test logger"""
    return setup_logging(level="DEBUG")

@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    temp_path = tempfile.mkdtemp(prefix="reveng_test_")
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)

@pytest.fixture
def sample_binaries_dir(temp_dir):
    """Create directory with sample binaries for testing"""
    binaries_dir = Path(temp_dir) / "binaries"
    binaries_dir.mkdir(exist_ok=True)

    # Create sample binary files (mock)
    sample_files = [
        "dotnet_app.exe",
        "java_app.jar",
        "native_app.exe",
        "packed_app.exe",
        "malware_sample.exe"
    ]

    for filename in sample_files:
        file_path = binaries_dir / filename
        with open(file_path, 'wb') as f:
            f.write(b'\x4D\x5A\x90\x00' + b'\x00' * 100)  # Mock PE header

    return binaries_dir

@pytest.fixture
def mock_dependency_manager():
    """Mock dependency manager for testing"""
    manager = Mock(spec=DependencyManager)
    manager.check_all_dependencies.return_value = {
        'ghidra': True,
        'ilspy': True,
        'cfr': True,
        'die': True,
        'scylla': True,
        'x64dbg': True,
        'hxd': True,
        'resource_hacker': True,
        'lordpe': True
    }
    manager.install_missing_tools.return_value = {
        'ghidra': True,
        'ilspy': True,
        'cfr': True
    }
    return manager

@pytest.fixture
def mock_dotnet_analyzer():
    """Mock .NET analyzer for testing"""
    analyzer = Mock(spec=DotNetAnalyzer)
    analyzer.analyze_assembly.return_value = {
        'framework_version': '4.8',
        'gui_framework': 'WinForms',
        'dependencies': ['System.Windows.Forms', 'System.Data'],
        'resources': {
            'icons': ['app.ico'],
            'strings': ['Application Name', 'Version 1.0'],
            'manifests': ['app.manifest']
        },
        'entry_points': ['Main'],
        'business_logic': {
            'domain': 'Security Reporting',
            'key_functionalities': ['Nessus Processing', 'Excel Generation'],
            'data_flows': ['Read .nessus -> Generate .xlsx']
        },
        'is_packed': False,
        'obfuscation_level': 'None',
        'api_calls': ['CreateFile', 'ReadFile', 'WriteFile'],
        'pe_sections': ['.text', '.data', '.resources']
    }
    return analyzer

@pytest.fixture
def mock_pe_resource_extractor():
    """Mock PE resource extractor for testing"""
    extractor = Mock(spec=PEResourceExtractor)
    extractor.extract_all_resources.return_value = {
        'icons': ['app.ico', 'icon1.ico'],
        'bitmaps': ['logo.bmp'],
        'strings': ['Application Name', 'Version 1.0', 'Company Name'],
        'manifests': ['app.manifest'],
        'version_info': {
            'file_version': '1.0.0.0',
            'product_version': '1.0.0.0',
            'company_name': 'Test Company',
            'product_name': 'Test Application'
        },
        'custom_resources': ['config.xml', 'template.html'],
        'embedded_files': ['data.db', 'template.xlsx']
    }
    return extractor

@pytest.fixture
def mock_import_analyzer():
    """Mock import analyzer for testing"""
    analyzer = Mock(spec=ImportAnalyzer)
    analyzer.analyze_imports.return_value = {
        'imported_dlls': ['kernel32.dll', 'user32.dll', 'ole32.dll'],
        'api_calls': [
            {'api': 'CreateFile', 'dll': 'kernel32.dll', 'category': 'File I/O'},
            {'api': 'ReadFile', 'dll': 'kernel32.dll', 'category': 'File I/O'},
            {'api': 'WriteFile', 'dll': 'kernel32.dll', 'category': 'File I/O'},
            {'api': 'MessageBox', 'dll': 'user32.dll', 'category': 'GUI'},
            {'api': 'CoInitialize', 'dll': 'ole32.dll', 'category': 'COM'}
        ],
        'suspicious_apis': [],
        'api_categories': {
            'File I/O': ['CreateFile', 'ReadFile', 'WriteFile'],
            'GUI': ['MessageBox'],
            'COM': ['CoInitialize']
        },
        'behavioral_indicators': ['File operations', 'GUI interaction', 'COM usage']
    }
    return analyzer

@pytest.fixture
def mock_business_logic_extractor():
    """Mock business logic extractor for testing"""
    extractor = Mock(spec=BusinessLogicExtractor)
    extractor.extract_logic.return_value = {
        'application_domain': 'Security Reporting',
        'key_functionalities': [
            'Nessus Report Processing',
            'Excel Report Generation',
            'Vulnerability Analysis'
        ],
        'data_flows': [
            'Reads .nessus files -> Generates Excel reports',
            'Processes vulnerability data -> Creates formatted reports'
        ],
        'file_operations': [
            'Reads .nessus files',
            'Writes .xlsx files',
            'Creates temporary files'
        ],
        'network_interactions': [],
        'registry_interactions': [],
        'identified_apis': ['CreateFile', 'ReadFile', 'WriteFile'],
        'report_generation_details': {
            'Vulnerability Report': 'Detected',
            'IV&V Test Plan': 'Detected',
            'CNET Report': 'Detected',
            'HW/SW Inventory': 'Detected',
            'eMASS HW/SW Inventory': 'Detected'
        },
        'gui_interactions': ['Uses Windows Forms for user interface']
    }
    return extractor

@pytest.fixture
def mock_ghidra_scripting_engine():
    """Mock Ghidra scripting engine for testing"""
    engine = Mock(spec=GhidraScriptingEngine)
    engine.run_script.return_value = "Ghidra script execution completed successfully"
    engine.batch_analyze_directory.return_value = {
        'binary1.exe': 'SUCCESS',
        'binary2.exe': 'SUCCESS'
    }
    return engine

@pytest.fixture
def mock_hex_editor():
    """Mock hex editor for testing"""
    editor = Mock(spec=HexEditor)
    editor.read_bytes.return_value = b'\x4D\x5A\x90\x00'
    editor.search_pattern.return_value = [0, 100, 200]
    editor.calculate_entropy.return_value = 7.2
    editor.detect_embedded_files_heuristic.return_value = [
        (0x1000, 1024, 'ZIP'),
        (0x2000, 2048, 'PDF')
    ]
    return editor

@pytest.fixture
def mock_automated_pipeline():
    """Mock automated analysis pipeline for testing"""
    pipeline = Mock(spec=AutomatedAnalysisPipeline)
    pipeline.run_pipeline.return_value = {
        'binary_path': 'test.exe',
        'dotnet_analysis': {'framework': '4.8'},
        'pe_resources': {'icons': ['app.ico']},
        'pe_imports': {'dlls': ['kernel32.dll']},
        'business_logic': {'domain': 'Security Reporting'},
        'ghidra_script_output': {'script1.py': 'SUCCESS'},
        'hex_editor_findings': {'entropy': 7.2}
    }
    return pipeline

@pytest.fixture
def mock_plugin_manager():
    """Mock plugin manager for testing"""
    manager = Mock(spec=PluginManager)
    manager.discover_plugins.return_value = None
    manager.initialize_plugins.return_value = None
    manager.get_plugin.return_value = Mock()
    manager.get_plugins_by_category.return_value = {
        'Analysis': {'PEAnalyzer': Mock()},
        'Visualization': {'FunctionGraph': Mock()},
        'AI': {'CodeReconstruction': Mock()},
        'Security': {'MalwareDetection': Mock()}
    }
    manager.execute_plugin.return_value = {'status': 'success', 'result': 'analysis completed'}
    manager.list_plugins.return_value = [
        {'name': 'PEAnalyzer', 'version': '1.0.0', 'description': 'PE file analysis', 'category': 'Analysis'},
        {'name': 'FunctionGraph', 'version': '1.0.0', 'description': 'Function call graph', 'category': 'Visualization'}
    ]
    return manager

@pytest.fixture
def mock_behavioral_monitor():
    """Mock behavioral monitor for testing"""
    monitor = Mock(spec=BehavioralMonitor)
    monitor.monitor_execution.return_value = {
        'binary_path': 'test.exe',
        'execution_successful': True,
        'exit_code': 0,
        'stdout': 'Application executed successfully',
        'stderr': '',
        'processes_created': [
            {
                'pid': 1234,
                'name': 'test.exe',
                'command_line': 'test.exe',
                'parent_pid': None,
                'start_time': 1234567890.0,
                'end_time': 1234567895.0,
                'file_accesses': ['C:\\temp\\test.txt'],
                'registry_accesses': [],
                'network_connections': [],
                'api_calls': ['CreateFile', 'ReadFile'],
                'suspicious_activities': []
            }
        ],
        'overall_file_accesses': ['C:\\temp\\test.txt'],
        'overall_registry_accesses': [],
        'overall_network_connections': [],
        'suspicious_activities': []
    }
    return monitor

@pytest.fixture
def mock_memory_forensics():
    """Mock memory forensics for testing"""
    forensics = Mock(spec=MemoryForensics)
    forensics.analyze_process_memory.return_value = {
        'process_id': 1234,
        'process_name': 'test.exe',
        'memory_dump_path': '/tmp/memory.dmp',
        'extracted_strings': ['test string', 'another string'],
        'memory_regions': [
            {
                'start_address': '0x00400000',
                'end_address': '0x004FFFFF',
                'size': '1MB',
                'permissions': 'R-X',
                'module': 'test.exe',
                'is_suspicious': False,
                'suspicion_reason': None
            }
        ],
        'suspicious_regions': [],
        'extracted_credentials': [],
        'injected_code_indicators': []
    }
    return forensics

@pytest.fixture
def mock_ml_integration():
    """Mock ML integration for testing"""
    config = MLIntegrationConfig(
        enable_code_reconstruction=True,
        enable_anomaly_detection=True,
        enable_threat_intelligence=True,
        output_directory="ml_analysis"
    )
    integration = Mock(spec=MLIntegration)
    integration.analyze_binary.return_value = {
        'binary_path': 'test.exe',
        'analysis_timestamp': 1234567890.0,
        'ml_analysis': {
            'code_reconstruction': {
                'reconstructions': [
                    {
                        'task': 'decompilation',
                        'address': 0x401000,
                        'reconstructed_code': 'int main() { return 0; }',
                        'confidence': 0.85,
                        'model_used': 'codebert',
                        'processing_time': 1.5
                    }
                ],
                'summary': {
                    'total_reconstructions': 1,
                    'average_confidence': 0.85,
                    'total_processing_time': 1.5
                }
            },
            'anomaly_detection': {
                'anomalies': [
                    {
                        'anomaly_type': 'behavioral',
                        'severity': 'medium',
                        'confidence': 0.7,
                        'description': 'Unusual API call pattern detected'
                    }
                ],
                'summary': {
                    'total_anomalies': 1,
                    'average_confidence': 0.7
                }
            },
            'threat_intelligence': {
                'threat_intelligence': [
                    {
                        'threat_type': 'File System Manipulation',
                        'severity': 'LOW',
                        'confidence': 0.5,
                        'indicators': ['File operation: read'],
                        'description': 'Suspicious file system operations detected'
                    }
                ],
                'summary': {
                    'total_threats': 1,
                    'average_confidence': 0.5
                }
            }
        }
    }
    integration.get_model_status.return_value = {
        'code_reconstruction': {
            'available': True,
            'models': {
                'codebert': {'loaded': True, 'local': True},
                'codet5': {'loaded': True, 'local': True}
            }
        },
        'anomaly_detection': {
            'available': True,
            'models': {
                'behavioral': {'name': 'Behavioral Anomaly Detector', 'type': 'behavioral'},
                'structural': {'name': 'Structural Anomaly Detector', 'type': 'structural'}
            }
        }
    }
    return integration

@pytest.fixture
def karp_sample_files(temp_dir):
    """Create KARP sample files for testing"""
    karp_dir = Path(temp_dir) / "karp_samples"
    karp_dir.mkdir(exist_ok=True)

    # Create mock KARP.exe
    karp_exe = karp_dir / "KARP.exe"
    with open(karp_exe, 'wb') as f:
        f.write(b'\x4D\x5A\x90\x00' + b'\x00' * 1000)  # Mock PE header

    # Create mock .nessus file
    nessus_file = karp_dir / "21778.nessus"
    with open(nessus_file, 'w') as f:
        f.write("""<?xml version="1.0"?>
<report>
    <host>
        <name>test-host</name>
        <vulnerabilities>
            <item>
                <name>Test Vulnerability</name>
                <severity>High</severity>
                <description>Test vulnerability description</description>
            </item>
        </vulnerabilities>
    </host>
</report>""")

    return {
        'karp_exe': karp_exe,
        'nessus_file': nessus_file,
        'karp_dir': karp_dir
    }

@pytest.fixture
def test_scripts_dir(temp_dir):
    """Create test scripts directory"""
    scripts_dir = Path(temp_dir) / "scripts"
    scripts_dir.mkdir(exist_ok=True)

    # Create Ghidra scripts
    ghidra_dir = scripts_dir / "ghidra"
    ghidra_dir.mkdir(exist_ok=True)

    # Create test Ghidra script
    test_script = ghidra_dir / "test_script.py"
    with open(test_script, 'w') as f:
        f.write("""# Test Ghidra script
def main():
    print("Test Ghidra script executed")
    return "SUCCESS"
""")

    return {
        'scripts_dir': scripts_dir,
        'ghidra_dir': ghidra_dir,
        'test_script': test_script
    }

@pytest.fixture
def mock_analysis_data():
    """Mock analysis data for testing"""
    return {
        'file_info': {
            'size': 1024000,
            'entropy': 7.2,
            'file_type': 'PE32'
        },
        'pe_info': {
            'machine': 'x86',
            'subsystem': 'Windows GUI',
            'entry_point': 0x401000,
            'sections': ['.text', '.data', '.resources']
        },
        'imports': {
            'dlls': ['kernel32.dll', 'user32.dll'],
            'apis': ['CreateFile', 'ReadFile', 'MessageBox']
        },
        'strings': [
            'Application Name',
            'Version 1.0',
            'Company Name'
        ],
        'resources': {
            'icons': ['app.ico'],
            'strings': ['Application Name'],
            'manifests': ['app.manifest']
        }
    }

@pytest.fixture
def mock_malware_sample(temp_dir):
    """Create mock malware sample for testing"""
    malware_dir = Path(temp_dir) / "malware_samples"
    malware_dir.mkdir(exist_ok=True)

    # Create mock malware sample
    malware_file = malware_dir / "malware_sample.exe"
    with open(malware_file, 'wb') as f:
        f.write(b'\x4D\x5A\x90\x00' + b'\x00' * 2000)  # Mock PE header

    return {
        'malware_file': malware_file,
        'malware_dir': malware_dir
    }

# Test configuration
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as performance test"
    )
    config.addinivalue_line(
        "markers", "malware: mark test as malware analysis test"
    )
    config.addinivalue_line(
        "markers", "ghidra: mark test as Ghidra integration test"
    )
    config.addinivalue_line(
        "markers", "pipeline: mark test as pipeline test"
    )
    config.addinivalue_line(
        "markers", "ml: mark test as ML integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running test"
    )

def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location"""
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

        # Add markers based on test name
        if "malware" in item.name:
            item.add_marker(pytest.mark.malware)
        if "ghidra" in item.name:
            item.add_marker(pytest.mark.ghidra)
        if "pipeline" in item.name:
            item.add_marker(pytest.mark.pipeline)
        if "ml" in item.name:
            item.add_marker(pytest.mark.ml)
        if "slow" in item.name:
            item.add_marker(pytest.mark.slow)
