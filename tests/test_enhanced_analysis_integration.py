#!/usr/bin/env python3
"""
Enhanced Analysis Integration Tests
==================================

Comprehensive integration tests for AI-Enhanced Universal Analysis Engine.
Tests the integration between enhanced analysis modules and existing REVENG pipeline.

Author: REVENG Project - Testing Module
Version: 1.0
"""

import unittest
import tempfile
import shutil
import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from reveng_analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures
from tools.enhanced_config_manager import EnhancedConfigManager, EnhancedAnalysisConfiguration
from tools.enhanced_health_monitor import EnhancedHealthMonitor


class TestEnhancedAnalysisIntegration(unittest.TestCase):
    """Integration tests for enhanced analysis system"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_binary = self.test_dir / "test_binary.exe"
        
        # Create a dummy test binary
        self.test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)  # Minimal PE header
        
        # Create test configuration
        self.config_manager = EnhancedConfigManager()
        self.test_config_path = self.test_dir / "test_config.json"
        self.config_manager.create_default_config_file(str(self.test_config_path))
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_enhanced_features_configuration(self):
        """Test enhanced analysis features configuration"""
        # Test default configuration
        features = EnhancedAnalysisFeatures()
        self.assertTrue(features.enable_enhanced_analysis)
        self.assertTrue(features.enable_corporate_exposure)
        self.assertTrue(features.enable_vulnerability_discovery)
        self.assertTrue(features.enable_threat_intelligence)
        self.assertTrue(features.enable_enhanced_reconstruction)
        self.assertTrue(features.enable_demonstration_generation)
        
        # Test configuration from dict
        config_dict = {
            "enable_enhanced_analysis": False,
            "enable_corporate_exposure": False,
            "enable_vulnerability_discovery": True
        }
        
        features.from_config(config_dict)
        self.assertFalse(features.enable_enhanced_analysis)
        self.assertFalse(features.enable_corporate_exposure)
        self.assertTrue(features.enable_vulnerability_discovery)
        
        # Test is_any_enhanced_enabled
        self.assertFalse(features.is_any_enhanced_enabled())
        
        features.enable_enhanced_analysis = True
        self.assertTrue(features.is_any_enhanced_enabled())
    
    def test_reveng_analyzer_with_enhanced_features(self):
        """Test REVENG analyzer with enhanced features enabled"""
        # Create enhanced features configuration
        features = EnhancedAnalysisFeatures()
        features.enable_enhanced_analysis = True
        
        # Create analyzer with enhanced features
        analyzer = REVENGAnalyzer(
            binary_path=str(self.test_binary),
            check_ollama=False,
            enhanced_features=features
        )
        
        # Verify enhanced features are configured
        self.assertIsNotNone(analyzer.enhanced_features)
        self.assertTrue(analyzer.enhanced_features.is_any_enhanced_enabled())
        self.assertEqual(analyzer._count_enabled_modules(), 5)
        
        # Verify enhanced results storage
        self.assertIsInstance(analyzer.enhanced_results, dict)
    
    def test_reveng_analyzer_without_enhanced_features(self):
        """Test REVENG analyzer with enhanced features disabled"""
        # Create disabled enhanced features configuration
        features = EnhancedAnalysisFeatures()
        features.enable_enhanced_analysis = False
        
        # Create analyzer with disabled enhanced features
        analyzer = REVENGAnalyzer(
            binary_path=str(self.test_binary),
            check_ollama=False,
            enhanced_features=features
        )
        
        # Verify enhanced features are disabled
        self.assertFalse(analyzer.enhanced_features.is_any_enhanced_enabled())
        self.assertEqual(analyzer._count_enabled_modules(), 0)
    
    @patch('subprocess.run')
    def test_enhanced_analysis_steps_execution(self, mock_subprocess):
        """Test execution of enhanced analysis steps"""
        # Mock subprocess calls to prevent actual execution
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")
        
        # Create analyzer with enhanced features
        features = EnhancedAnalysisFeatures()
        analyzer = REVENGAnalyzer(
            binary_path=str(self.test_binary),
            check_ollama=False,
            enhanced_features=features
        )
        
        # Mock enhanced analysis modules
        with patch('tools.corporate_exposure_detector.CorporateExposureDetector') as mock_ced, \
             patch('tools.vulnerability_discovery_engine.VulnerabilityDiscoveryEngine') as mock_vde, \
             patch('tools.threat_intelligence_correlator.ThreatIntelligenceCorrelator') as mock_tic, \
             patch('tools.demonstration_generator.DemonstrationGenerator') as mock_dg:
            
            # Configure mocks
            mock_ced.return_value.analyze_file.return_value = Mock(
                credentials_found=[],
                business_logic_exposed=[],
                api_endpoints_discovered=[],
                risk_level="LOW"
            )
            
            mock_vde.return_value.analyze_file.return_value = Mock(
                total_vulnerabilities=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0
            )
            
            mock_tic.return_value.analyze_file.return_value = Mock(
                threat_level="LOW",
                apt_attribution=None,
                iocs_extracted=[],
                malware_classification=None
            )
            
            mock_dg.return_value.create_demonstration_package.return_value = Mock(
                components=[]
            )
            
            # Test individual enhanced analysis steps
            analyzer._step9_corporate_exposure()
            self.assertIn('step9', analyzer.enhanced_results)
            self.assertEqual(analyzer.enhanced_results['step9']['status'], 'success')
            
            analyzer._step10_vulnerability_discovery()
            self.assertIn('step10', analyzer.enhanced_results)
            self.assertEqual(analyzer.enhanced_results['step10']['status'], 'success')
            
            analyzer._step11_threat_intelligence()
            self.assertIn('step11', analyzer.enhanced_results)
            self.assertEqual(analyzer.enhanced_results['step11']['status'], 'success')
            
            analyzer._step12_enhanced_reconstruction()
            self.assertIn('step12', analyzer.enhanced_results)
            self.assertEqual(analyzer.enhanced_results['step12']['status'], 'success')
            
            analyzer._step13_demonstration_generation()
            self.assertIn('step13', analyzer.enhanced_results)
            self.assertEqual(analyzer.enhanced_results['step13']['status'], 'success')
    
    def test_enhanced_analysis_error_handling(self):
        """Test error handling in enhanced analysis steps"""
        # Create analyzer with enhanced features
        features = EnhancedAnalysisFeatures()
        analyzer = REVENGAnalyzer(
            binary_path=str(self.test_binary),
            check_ollama=False,
            enhanced_features=features
        )
        
        # Test error handling when modules are not available
        with patch('tools.corporate_exposure_detector.CorporateExposureDetector', side_effect=ImportError("Module not found")):
            analyzer._step9_corporate_exposure()
            self.assertIn('step9', analyzer.enhanced_results)
            self.assertEqual(analyzer.enhanced_results['step9']['status'], 'skipped')
            self.assertEqual(analyzer.enhanced_results['step9']['error'], 'module_not_found')
        
        # Test error handling when analysis fails
        with patch('tools.vulnerability_discovery_engine.VulnerabilityDiscoveryEngine') as mock_vde:
            mock_vde.return_value.analyze_file.side_effect = Exception("Analysis failed")
            
            analyzer._step10_vulnerability_discovery()
            self.assertIn('step10', analyzer.enhanced_results)
            self.assertEqual(analyzer.enhanced_results['step10']['status'], 'error')
            self.assertIn('Analysis failed', analyzer.enhanced_results['step10']['error'])
    
    def test_final_report_generation_with_enhanced_results(self):
        """Test final report generation includes enhanced results"""
        # Create analyzer with enhanced features
        features = EnhancedAnalysisFeatures()
        analyzer = REVENGAnalyzer(
            binary_path=str(self.test_binary),
            check_ollama=False,
            enhanced_features=features
        )
        
        # Add some mock enhanced results
        analyzer.enhanced_results = {
            'step9': {'status': 'success', 'credentials_count': 5},
            'step10': {'status': 'success', 'total_vulnerabilities': 3},
            'step11': {'status': 'warning', 'threat_level': 'MEDIUM'}
        }
        
        # Generate final report
        analyzer._generate_final_report()
        
        # Check if report file was created
        report_file = analyzer.analysis_folder / "universal_analysis_report.json"
        self.assertTrue(report_file.exists())
        
        # Load and verify report content
        with open(report_file, 'r') as f:
            report = json.load(f)
        
        # Verify enhanced analysis information is included
        self.assertTrue(report['enhanced_analysis_enabled'])
        self.assertEqual(report['enhanced_modules_enabled'], 5)
        self.assertIn('enhanced_steps', report)
        self.assertIn('step9_corporate_exposure', report['enhanced_steps'])
        self.assertIn('step10_vulnerability_discovery', report['enhanced_steps'])
        self.assertIn('step11_threat_intelligence', report['enhanced_steps'])
        
        # Verify summary includes enhanced steps
        self.assertEqual(report['summary']['total_steps'], 13)  # 8 core + 5 enhanced
        self.assertEqual(report['summary']['enhanced_steps'], 5)


class TestEnhancedConfigurationManager(unittest.TestCase):
    """Tests for enhanced configuration manager"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_config_path = self.test_dir / "test_config.json"
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_default_configuration_creation(self):
        """Test creation of default configuration"""
        manager = EnhancedConfigManager()
        manager.create_default_config_file(str(self.test_config_path))
        
        # Verify file was created
        self.assertTrue(self.test_config_path.exists())
        
        # Load and verify content
        with open(self.test_config_path, 'r') as f:
            config_data = json.load(f)
        
        # Verify required sections exist
        self.assertIn('ai_service', config_data)
        self.assertIn('corporate_exposure', config_data)
        self.assertIn('vulnerability_discovery', config_data)
        self.assertIn('threat_intelligence', config_data)
        self.assertIn('binary_reconstruction', config_data)
        self.assertIn('demonstration_generation', config_data)
        self.assertIn('deployment', config_data)
        self.assertIn('security', config_data)
    
    def test_configuration_validation(self):
        """Test configuration validation"""
        manager = EnhancedConfigManager()
        
        # Test valid configuration
        issues = manager.validate_configuration()
        self.assertEqual(len(issues), 0)
        
        # Test invalid configuration
        manager.config.ai_service.timeout = -1
        manager.config.deployment.max_concurrent_analyses = 0
        manager.config.security.max_file_size_mb = -10
        
        issues = manager.validate_configuration()
        self.assertGreater(len(issues), 0)
        self.assertTrue(any("timeout must be positive" in issue for issue in issues))
        self.assertTrue(any("Max concurrent analyses must be positive" in issue for issue in issues))
        self.assertTrue(any("Max file size must be positive" in issue for issue in issues))
    
    def test_configuration_loading_and_saving(self):
        """Test configuration loading and saving"""
        # Create initial configuration
        manager1 = EnhancedConfigManager()
        manager1.config.ai_service.provider = "test_provider"
        manager1.config.corporate_exposure.enabled = False
        manager1.save_configuration(str(self.test_config_path))
        
        # Load configuration in new manager
        manager2 = EnhancedConfigManager(str(self.test_config_path))
        
        # Verify configuration was loaded correctly
        self.assertEqual(manager2.config.ai_service.provider, "test_provider")
        self.assertFalse(manager2.config.corporate_exposure.enabled)


class TestEnhancedHealthMonitor(unittest.TestCase):
    """Tests for enhanced health monitor"""
    
    def setUp(self):
        """Set up test environment"""
        self.monitor = EnhancedHealthMonitor(check_interval=1)
    
    def tearDown(self):
        """Clean up test environment"""
        if self.monitor.running:
            self.monitor.stop_monitoring()
    
    def test_health_monitor_initialization(self):
        """Test health monitor initialization"""
        self.assertIsNotNone(self.monitor.checkers)
        self.assertIn('core_reveng', self.monitor.checkers)
        self.assertIn('enhanced_modules', self.monitor.checkers)
        self.assertIn('ai_service', self.monitor.checkers)
        self.assertIn('system_resources', self.monitor.checkers)
        
        self.assertFalse(self.monitor.running)
        self.assertEqual(len(self.monitor.health_history), 0)
    
    def test_single_health_check(self):
        """Test single health check execution"""
        system_health = self.monitor.check_all_components()
        
        # Verify system health object structure
        self.assertIsNotNone(system_health.overall_status)
        self.assertIn(system_health.overall_status, ["healthy", "warning", "critical", "unknown"])
        self.assertIsInstance(system_health.components, dict)
        self.assertIsInstance(system_health.alerts, list)
        
        # Verify all components were checked
        self.assertIn('core_reveng', system_health.components)
        self.assertIn('enhanced_modules', system_health.components)
        self.assertIn('ai_service', system_health.components)
        self.assertIn('system_resources', system_health.components)
        
        # Verify health history was updated
        self.assertEqual(len(self.monitor.health_history), 1)
    
    def test_health_monitor_start_stop(self):
        """Test health monitor start and stop"""
        # Start monitoring
        self.monitor.start_monitoring()
        self.assertTrue(self.monitor.running)
        self.assertIsNotNone(self.monitor.monitor_thread)
        
        # Wait a bit for at least one check
        import time
        time.sleep(2)
        
        # Verify health checks are running
        self.assertGreater(len(self.monitor.health_history), 0)
        
        # Stop monitoring
        self.monitor.stop_monitoring()
        self.assertFalse(self.monitor.running)
    
    def test_health_summary_generation(self):
        """Test health summary generation"""
        # Run a few health checks
        for _ in range(3):
            self.monitor.check_all_components()
        
        # Generate summary
        summary = self.monitor.get_health_summary(hours=1)
        
        # Verify summary structure
        self.assertIn('period_hours', summary)
        self.assertIn('total_checks', summary)
        self.assertIn('overall_uptime_percentage', summary)
        self.assertIn('current_status', summary)
        self.assertIn('component_statistics', summary)
        
        # Verify component statistics
        for component_name in self.monitor.checkers.keys():
            self.assertIn(component_name, summary['component_statistics'])
    
    def test_alert_callback_system(self):
        """Test alert callback system"""
        alert_messages = []
        
        def test_callback(message, component_health):
            alert_messages.append(message)
        
        # Add callback
        self.monitor.add_alert_callback(test_callback)
        
        # Mock a component to return warning status
        with patch.object(self.monitor.checkers['core_reveng'], 'check_health') as mock_check:
            from tools.enhanced_health_monitor import ComponentHealth, HealthMetric
            from datetime import datetime
            
            mock_check.return_value = ComponentHealth(
                component_name="core_reveng",
                status="warning",
                metrics=[HealthMetric(
                    name="test_metric",
                    value="test_value",
                    status="warning",
                    timestamp=datetime.now(),
                    message="Test warning"
                )],
                last_check=datetime.now(),
                error_count=1
            )
            
            # Run health check
            self.monitor.check_all_components()
            
            # Verify callback was called
            self.assertGreater(len(alert_messages), 0)
            self.assertTrue(any("core_reveng" in msg for msg in alert_messages))


class TestPerformanceBenchmarks(unittest.TestCase):
    """Performance benchmark tests for enhanced analysis"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_binary = self.test_dir / "test_binary.exe"
        self.test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)  # Larger test binary
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_enhanced_analysis_performance(self):
        """Test performance of enhanced analysis components"""
        import time
        
        # Create analyzer with enhanced features
        features = EnhancedAnalysisFeatures()
        analyzer = REVENGAnalyzer(
            binary_path=str(self.test_binary),
            check_ollama=False,
            enhanced_features=features
        )
        
        # Mock enhanced analysis modules for performance testing
        with patch('tools.corporate_exposure_detector.CorporateExposureDetector') as mock_ced, \
             patch('tools.vulnerability_discovery_engine.VulnerabilityDiscoveryEngine') as mock_vde, \
             patch('tools.threat_intelligence_correlator.ThreatIntelligenceCorrelator') as mock_tic, \
             patch('tools.demonstration_generator.DemonstrationGenerator') as mock_dg:
            
            # Configure mocks with realistic delays
            def slow_analysis(*args, **kwargs):
                time.sleep(0.1)  # Simulate analysis time
                return Mock(
                    credentials_found=[],
                    business_logic_exposed=[],
                    api_endpoints_discovered=[],
                    risk_level="LOW"
                )
            
            mock_ced.return_value.analyze_file.side_effect = slow_analysis
            mock_vde.return_value.analyze_file.side_effect = lambda *args, **kwargs: Mock(
                total_vulnerabilities=0, critical_count=0, high_count=0, medium_count=0, low_count=0
            )
            mock_tic.return_value.analyze_file.side_effect = lambda *args, **kwargs: Mock(
                threat_level="LOW", apt_attribution=None, iocs_extracted=[], malware_classification=None
            )
            mock_dg.return_value.create_demonstration_package.side_effect = lambda *args, **kwargs: Mock(
                components=[]
            )
            
            # Measure performance of each enhanced step
            performance_results = {}
            
            # Test corporate exposure analysis
            start_time = time.time()
            analyzer._step9_corporate_exposure()
            performance_results['corporate_exposure'] = time.time() - start_time
            
            # Test vulnerability discovery
            start_time = time.time()
            analyzer._step10_vulnerability_discovery()
            performance_results['vulnerability_discovery'] = time.time() - start_time
            
            # Test threat intelligence
            start_time = time.time()
            analyzer._step11_threat_intelligence()
            performance_results['threat_intelligence'] = time.time() - start_time
            
            # Test demonstration generation
            start_time = time.time()
            analyzer._step13_demonstration_generation()
            performance_results['demonstration_generation'] = time.time() - start_time
            
            # Verify performance is within acceptable limits (adjust as needed)
            for step, duration in performance_results.items():
                self.assertLess(duration, 5.0, f"{step} took too long: {duration:.2f}s")
                print(f"Performance - {step}: {duration:.3f}s")
    
    def test_health_monitor_performance(self):
        """Test performance of health monitoring"""
        import time
        
        monitor = EnhancedHealthMonitor(check_interval=1)
        
        # Measure single health check performance
        start_time = time.time()
        system_health = monitor.check_all_components()
        check_duration = time.time() - start_time
        
        # Verify health check completes quickly
        self.assertLess(check_duration, 10.0, f"Health check took too long: {check_duration:.2f}s")
        print(f"Health check performance: {check_duration:.3f}s")
        
        # Verify all components were checked
        self.assertEqual(len(system_health.components), 4)


def run_integration_tests():
    """Run all integration tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestEnhancedAnalysisIntegration,
        TestEnhancedConfigurationManager,
        TestEnhancedHealthMonitor,
        TestPerformanceBenchmarks
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)