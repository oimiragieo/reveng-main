#!/usr/bin/env python3
"""
Enhanced Analysis Modules Unit Tests
===================================

Unit tests for individual enhanced analysis modules.
Tests functionality, error handling, and edge cases.

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


class TestAIEnhancedAnalyzer(unittest.TestCase):
    """Unit tests for AI Enhanced Analyzer"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_binary = self.test_dir / "test_binary.exe"
        self.test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_ai_enhanced_analyzer_initialization(self):
        """Test AI Enhanced Analyzer initialization"""
        from tools.ai_enhanced_analyzer import AIEnhancedAnalyzer, EnhancedAnalysisConfig
        
        # Test with default configuration
        analyzer = AIEnhancedAnalyzer(str(self.test_binary))
        
        self.assertEqual(analyzer.binary_path, str(self.test_binary))
        self.assertIsNotNone(analyzer.config)
        self.assertIsInstance(analyzer.config, EnhancedAnalysisConfig)
        self.assertTrue(analyzer.analysis_folder.exists())
    
    def test_enhanced_analysis_config(self):
        """Test Enhanced Analysis Configuration"""
        from tools.ai_enhanced_analyzer import EnhancedAnalysisConfig
        
        # Test default configuration
        config = EnhancedAnalysisConfig()
        
        self.assertTrue(config.enable_corporate_exposure)
        self.assertTrue(config.enable_vulnerability_discovery)
        self.assertTrue(config.enable_threat_intelligence)
        self.assertTrue(config.enable_binary_reconstruction)
        self.assertTrue(config.enable_demonstration_generation)
        
        self.assertEqual(config.ai_provider, "ollama")
        self.assertEqual(config.ai_model, "auto")
        self.assertEqual(config.ai_timeout, 300)
        self.assertEqual(config.confidence_threshold, 0.7)
        
        # Test custom configuration
        config = EnhancedAnalysisConfig(
            enable_corporate_exposure=False,
            ai_provider="openai",
            confidence_threshold=0.9
        )
        
        self.assertFalse(config.enable_corporate_exposure)
        self.assertEqual(config.ai_provider, "openai")
        self.assertEqual(config.confidence_threshold, 0.9)
    
    @patch('reveng_analyzer.REVENGAnalyzer')
    def test_reveng_pipeline_integration(self, mock_reveng):
        """Test integration with REVENG pipeline"""
        from tools.ai_enhanced_analyzer import AIEnhancedAnalyzer
        
        # Mock REVENG analyzer
        mock_reveng_instance = Mock()
        mock_reveng_instance.analyze_binary.return_value = True
        mock_reveng_instance.results = {"step1": {"status": "success"}}
        mock_reveng.return_value = mock_reveng_instance
        
        # Create AI Enhanced Analyzer
        analyzer = AIEnhancedAnalyzer(str(self.test_binary))
        
        # Test REVENG pipeline execution
        analyzer._run_reveng_pipeline()
        
        # Verify REVENG analyzer was called
        mock_reveng.assert_called_once()
        mock_reveng_instance.analyze_binary.assert_called_once()
        
        # Verify results were stored
        self.assertEqual(analyzer.reveng_results, {"step1": {"status": "success"}})
    
    def test_file_type_detection(self):
        """Test file type detection"""
        from tools.ai_enhanced_analyzer import AIEnhancedAnalyzer
        
        with patch('tools.language_detector.LanguageDetector') as mock_detector:
            # Mock language detector
            mock_file_type = Mock()
            mock_file_type.language = "native"
            mock_file_type.format = "pe"
            mock_file_type.confidence = 0.95
            
            mock_detector_instance = Mock()
            mock_detector_instance.detect.return_value = mock_file_type
            mock_detector.return_value = mock_detector_instance
            
            # Create analyzer
            analyzer = AIEnhancedAnalyzer(str(self.test_binary))
            
            # Verify file type detection was called
            mock_detector_instance.detect.assert_called_once_with(str(self.test_binary))
            
            # Verify file type was set
            self.assertEqual(analyzer.file_type, mock_file_type)


class TestEnhancedConfigManager(unittest.TestCase):
    """Unit tests for Enhanced Config Manager"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_enhanced_analysis_configuration_dataclass(self):
        """Test Enhanced Analysis Configuration dataclass"""
        from tools.enhanced_config_manager import (
            EnhancedAnalysisConfiguration, AIServiceConfig, 
            AnalysisModuleConfig, DeploymentConfig, SecurityConfig
        )
        
        # Test default configuration
        config = EnhancedAnalysisConfiguration()
        
        # Verify all components are initialized
        self.assertIsInstance(config.ai_service, AIServiceConfig)
        self.assertIsInstance(config.corporate_exposure, AnalysisModuleConfig)
        self.assertIsInstance(config.vulnerability_discovery, AnalysisModuleConfig)
        self.assertIsInstance(config.threat_intelligence, AnalysisModuleConfig)
        self.assertIsInstance(config.binary_reconstruction, AnalysisModuleConfig)
        self.assertIsInstance(config.demonstration_generation, AnalysisModuleConfig)
        self.assertIsInstance(config.deployment, DeploymentConfig)
        self.assertIsInstance(config.security, SecurityConfig)
        
        # Verify default values
        self.assertTrue(config.enable_enhanced_analysis)
        self.assertEqual(config.version, "1.0")
        self.assertTrue(config.generate_executive_reports)
        self.assertTrue(config.generate_technical_reports)
    
    def test_config_manager_initialization(self):
        """Test config manager initialization"""
        from tools.enhanced_config_manager import EnhancedConfigManager
        
        # Test with no config file
        manager = EnhancedConfigManager()
        self.assertIsNotNone(manager.config)
        
        # Test with custom config path
        config_path = self.test_dir / "custom_config.json"
        manager = EnhancedConfigManager(str(config_path))
        self.assertEqual(manager.config_path, str(config_path))
    
    def test_config_validation(self):
        """Test configuration validation"""
        from tools.enhanced_config_manager import EnhancedConfigManager
        
        manager = EnhancedConfigManager()
        
        # Test valid configuration
        issues = manager.validate_configuration()
        self.assertEqual(len(issues), 0)
        
        # Test invalid AI provider
        manager.config.ai_service.provider = "invalid_provider"
        issues = manager.validate_configuration()
        self.assertGreater(len(issues), 0)
        self.assertTrue(any("Invalid AI provider" in issue for issue in issues))
        
        # Reset and test invalid timeout
        manager.config.ai_service.provider = "ollama"
        manager.config.ai_service.timeout = -1
        issues = manager.validate_configuration()
        self.assertGreater(len(issues), 0)
        self.assertTrue(any("timeout must be positive" in issue for issue in issues))
        
        # Test invalid confidence threshold
        manager.config.ai_service.timeout = 300
        manager.config.corporate_exposure.confidence_threshold = 1.5
        issues = manager.validate_configuration()
        self.assertGreater(len(issues), 0)
        self.assertTrue(any("confidence threshold must be between 0 and 1" in issue for issue in issues))
    
    def test_config_file_operations(self):
        """Test configuration file save and load operations"""
        from tools.enhanced_config_manager import EnhancedConfigManager
        
        # Create manager and modify configuration
        manager1 = EnhancedConfigManager()
        manager1.config.ai_service.provider = "test_provider"
        manager1.config.corporate_exposure.enabled = False
        manager1.config.deployment.max_concurrent_analyses = 8
        
        # Save configuration
        config_path = self.test_dir / "test_config.json"
        manager1.save_configuration(str(config_path))
        
        # Verify file was created
        self.assertTrue(config_path.exists())
        
        # Load configuration in new manager
        manager2 = EnhancedConfigManager(str(config_path))
        
        # Verify configuration was loaded correctly
        self.assertEqual(manager2.config.ai_service.provider, "test_provider")
        self.assertFalse(manager2.config.corporate_exposure.enabled)
        self.assertEqual(manager2.config.deployment.max_concurrent_analyses, 8)
    
    def test_default_config_creation(self):
        """Test default configuration file creation"""
        from tools.enhanced_config_manager import EnhancedConfigManager
        
        manager = EnhancedConfigManager()
        config_path = self.test_dir / "default_config.json"
        
        # Create default configuration file
        manager.create_default_config_file(str(config_path))
        
        # Verify file was created
        self.assertTrue(config_path.exists())
        
        # Load and verify content
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        # Verify required sections
        required_sections = [
            "ai_service", "corporate_exposure", "vulnerability_discovery",
            "threat_intelligence", "binary_reconstruction", "demonstration_generation",
            "deployment", "security"
        ]
        
        for section in required_sections:
            self.assertIn(section, config_data)
        
        # Verify comments are included
        self.assertIn("_comment", config_data)


class TestEnhancedHealthMonitor(unittest.TestCase):
    """Unit tests for Enhanced Health Monitor"""
    
    def setUp(self):
        """Set up test environment"""
        pass
    
    def tearDown(self):
        """Clean up test environment"""
        pass
    
    def test_health_metric_dataclass(self):
        """Test HealthMetric dataclass"""
        from tools.enhanced_health_monitor import HealthMetric
        from datetime import datetime
        
        # Test basic metric
        metric = HealthMetric(
            name="test_metric",
            value="test_value",
            status="healthy",
            timestamp=datetime.now()
        )
        
        self.assertEqual(metric.name, "test_metric")
        self.assertEqual(metric.value, "test_value")
        self.assertEqual(metric.status, "healthy")
        self.assertIsInstance(metric.timestamp, datetime)
        
        # Test metric with thresholds
        metric = HealthMetric(
            name="cpu_usage",
            value=75.5,
            status="warning",
            timestamp=datetime.now(),
            threshold_warning=70.0,
            threshold_critical=90.0,
            message="CPU usage is high"
        )
        
        self.assertEqual(metric.threshold_warning, 70.0)
        self.assertEqual(metric.threshold_critical, 90.0)
        self.assertEqual(metric.message, "CPU usage is high")
    
    def test_component_health_dataclass(self):
        """Test ComponentHealth dataclass"""
        from tools.enhanced_health_monitor import ComponentHealth, HealthMetric
        from datetime import datetime
        
        metrics = [
            HealthMetric("metric1", "value1", "healthy", datetime.now()),
            HealthMetric("metric2", "value2", "warning", datetime.now())
        ]
        
        component = ComponentHealth(
            component_name="test_component",
            status="warning",
            metrics=metrics,
            last_check=datetime.now(),
            uptime=3600.0,
            error_count=1
        )
        
        self.assertEqual(component.component_name, "test_component")
        self.assertEqual(component.status, "warning")
        self.assertEqual(len(component.metrics), 2)
        self.assertEqual(component.uptime, 3600.0)
        self.assertEqual(component.error_count, 1)
    
    def test_health_checker_base_class(self):
        """Test HealthChecker base class"""
        from tools.enhanced_health_monitor import HealthChecker
        
        checker = HealthChecker("test_component")
        
        self.assertEqual(checker.component_name, "test_component")
        self.assertIsNotNone(checker.start_time)
        
        # Test uptime calculation
        uptime = checker.get_uptime()
        self.assertGreaterEqual(uptime, 0.0)
        
        # Test abstract method
        with self.assertRaises(NotImplementedError):
            checker.check_health()
    
    def test_core_reveng_health_checker(self):
        """Test CoreREVENGHealthChecker"""
        from tools.enhanced_health_monitor import CoreREVENGHealthChecker
        
        checker = CoreREVENGHealthChecker()
        
        # Test health check
        health = checker.check_health()
        
        self.assertEqual(health.component_name, "core_reveng")
        self.assertIn(health.status, ["healthy", "warning", "critical"])
        self.assertIsInstance(health.metrics, list)
        self.assertGreaterEqual(len(health.metrics), 1)  # At least configuration check
    
    def test_enhanced_modules_health_checker(self):
        """Test EnhancedModulesHealthChecker"""
        from tools.enhanced_health_monitor import EnhancedModulesHealthChecker
        
        checker = EnhancedModulesHealthChecker()
        
        # Test health check
        health = checker.check_health()
        
        self.assertEqual(health.component_name, "enhanced_modules")
        self.assertIn(health.status, ["healthy", "warning", "critical"])
        self.assertIsInstance(health.metrics, list)
        self.assertGreaterEqual(len(health.metrics), 1)
    
    def test_system_resources_health_checker(self):
        """Test SystemResourcesHealthChecker"""
        from tools.enhanced_health_monitor import SystemResourcesHealthChecker
        
        checker = SystemResourcesHealthChecker()
        
        # Test health check
        health = checker.check_health()
        
        self.assertEqual(health.component_name, "system_resources")
        self.assertIn(health.status, ["healthy", "warning", "critical"])
        self.assertIsInstance(health.metrics, list)
        
        # Verify expected metrics
        metric_names = [metric.name for metric in health.metrics]
        self.assertIn("cpu_usage", metric_names)
        self.assertIn("memory_usage", metric_names)
        self.assertIn("disk_usage", metric_names)
    
    def test_enhanced_health_monitor_initialization(self):
        """Test EnhancedHealthMonitor initialization"""
        from tools.enhanced_health_monitor import EnhancedHealthMonitor
        
        monitor = EnhancedHealthMonitor(check_interval=30)
        
        self.assertEqual(monitor.check_interval, 30)
        self.assertFalse(monitor.running)
        self.assertIsNone(monitor.monitor_thread)
        self.assertEqual(len(monitor.health_history), 0)
        self.assertEqual(len(monitor.alert_callbacks), 0)
        
        # Verify checkers are initialized
        expected_checkers = ["core_reveng", "enhanced_modules", "ai_service", "system_resources"]
        for checker_name in expected_checkers:
            self.assertIn(checker_name, monitor.checkers)
    
    def test_health_monitor_single_check(self):
        """Test single health check execution"""
        from tools.enhanced_health_monitor import EnhancedHealthMonitor
        
        monitor = EnhancedHealthMonitor()
        
        # Run single health check
        system_health = monitor.check_all_components()
        
        # Verify system health structure
        self.assertIn(system_health.overall_status, ["healthy", "warning", "critical", "unknown"])
        self.assertIsInstance(system_health.components, dict)
        self.assertIsInstance(system_health.alerts, list)
        
        # Verify all components were checked
        expected_components = ["core_reveng", "enhanced_modules", "ai_service", "system_resources"]
        for component_name in expected_components:
            self.assertIn(component_name, system_health.components)
        
        # Verify health history was updated
        self.assertEqual(len(monitor.health_history), 1)
        self.assertEqual(monitor.health_history[0], system_health)
    
    def test_alert_callback_system(self):
        """Test alert callback system"""
        from tools.enhanced_health_monitor import EnhancedHealthMonitor
        
        monitor = EnhancedHealthMonitor()
        
        # Test callback registration
        callback_calls = []
        
        def test_callback(message, component_health):
            callback_calls.append((message, component_health))
        
        monitor.add_alert_callback(test_callback)
        self.assertEqual(len(monitor.alert_callbacks), 1)
        
        # Mock a component to return warning status
        with patch.object(monitor.checkers['core_reveng'], 'check_health') as mock_check:
            from tools.enhanced_health_monitor import ComponentHealth, HealthMetric
            from datetime import datetime
            
            mock_health = ComponentHealth(
                component_name="core_reveng",
                status="warning",
                metrics=[HealthMetric("test", "test", "warning", datetime.now())],
                last_check=datetime.now(),
                error_count=1
            )
            mock_check.return_value = mock_health
            
            # Run health check
            monitor.check_all_components()
            
            # Verify callback was called
            self.assertGreater(len(callback_calls), 0)


def run_unit_tests():
    """Run all unit tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestAIEnhancedAnalyzer,
        TestEnhancedConfigManager,
        TestEnhancedHealthMonitor
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_unit_tests()
    sys.exit(0 if success else 1)