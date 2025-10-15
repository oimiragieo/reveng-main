#!/usr/bin/env python3
"""
Enhanced Analysis Test Runner
============================

Comprehensive test runner for AI-Enhanced Universal Analysis Engine.
Runs unit tests, integration tests, performance benchmarks, and validation checks.

Author: REVENG Project - Testing Module
Version: 1.0
"""

import sys
import os
import time
import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import unittest
from dataclasses import dataclass, asdict

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Test result information"""
    test_name: str
    status: str  # "passed", "failed", "skipped", "error"
    duration: float
    details: str = ""
    error_message: str = ""


@dataclass
class TestSuiteResult:
    """Test suite result information"""
    suite_name: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    error_tests: int
    total_duration: float
    test_results: List[TestResult]
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100


@dataclass
class ValidationResult:
    """Validation result information"""
    validation_name: str
    status: str  # "passed", "failed", "warning"
    message: str
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class EnhancedTestRunner:
    """
    Comprehensive test runner for enhanced analysis system
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize test runner
        
        Args:
            output_dir: Directory to save test results
        """
        self.output_dir = Path(output_dir) if output_dir else Path("test_results")
        self.output_dir.mkdir(exist_ok=True)
        
        self.test_results: List[TestSuiteResult] = []
        self.validation_results: List[ValidationResult] = []
        
        logger.info(f"Enhanced Test Runner initialized - output: {self.output_dir}")
    
    def run_unit_tests(self) -> TestSuiteResult:
        """Run unit tests for enhanced analysis modules"""
        logger.info("Running unit tests...")
        
        start_time = time.time()
        test_results = []
        
        try:
            # Import and run unit tests
            from tests.test_enhanced_modules import run_unit_tests
            
            # Capture test output
            import io
            from contextlib import redirect_stdout, redirect_stderr
            
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                success = run_unit_tests()
            
            stdout_output = stdout_capture.getvalue()
            stderr_output = stderr_capture.getvalue()
            
            # Parse test results (simplified)
            if success:
                test_results.append(TestResult(
                    test_name="unit_tests_all",
                    status="passed",
                    duration=time.time() - start_time,
                    details=stdout_output
                ))
                passed_tests = 1
                failed_tests = 0
            else:
                test_results.append(TestResult(
                    test_name="unit_tests_all",
                    status="failed",
                    duration=time.time() - start_time,
                    details=stdout_output,
                    error_message=stderr_output
                ))
                passed_tests = 0
                failed_tests = 1
            
        except Exception as e:
            logger.error(f"Error running unit tests: {e}")
            test_results.append(TestResult(
                test_name="unit_tests_all",
                status="error",
                duration=time.time() - start_time,
                error_message=str(e)
            ))
            passed_tests = 0
            failed_tests = 0
        
        suite_result = TestSuiteResult(
            suite_name="unit_tests",
            total_tests=len(test_results),
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            skipped_tests=0,
            error_tests=len([r for r in test_results if r.status == "error"]),
            total_duration=time.time() - start_time,
            test_results=test_results
        )
        
        self.test_results.append(suite_result)
        logger.info(f"Unit tests completed - {suite_result.success_rate:.1f}% success rate")
        
        return suite_result
    
    def run_integration_tests(self) -> TestSuiteResult:
        """Run integration tests for enhanced analysis system"""
        logger.info("Running integration tests...")
        
        start_time = time.time()
        test_results = []
        
        try:
            # Import and run integration tests
            from tests.test_enhanced_analysis_integration import run_integration_tests
            
            # Capture test output
            import io
            from contextlib import redirect_stdout, redirect_stderr
            
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                success = run_integration_tests()
            
            stdout_output = stdout_capture.getvalue()
            stderr_output = stderr_capture.getvalue()
            
            # Parse test results (simplified)
            if success:
                test_results.append(TestResult(
                    test_name="integration_tests_all",
                    status="passed",
                    duration=time.time() - start_time,
                    details=stdout_output
                ))
                passed_tests = 1
                failed_tests = 0
            else:
                test_results.append(TestResult(
                    test_name="integration_tests_all",
                    status="failed",
                    duration=time.time() - start_time,
                    details=stdout_output,
                    error_message=stderr_output
                ))
                passed_tests = 0
                failed_tests = 1
            
        except Exception as e:
            logger.error(f"Error running integration tests: {e}")
            test_results.append(TestResult(
                test_name="integration_tests_all",
                status="error",
                duration=time.time() - start_time,
                error_message=str(e)
            ))
            passed_tests = 0
            failed_tests = 0
        
        suite_result = TestSuiteResult(
            suite_name="integration_tests",
            total_tests=len(test_results),
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            skipped_tests=0,
            error_tests=len([r for r in test_results if r.status == "error"]),
            total_duration=time.time() - start_time,
            test_results=test_results
        )
        
        self.test_results.append(suite_result)
        logger.info(f"Integration tests completed - {suite_result.success_rate:.1f}% success rate")
        
        return suite_result
    
    def run_performance_benchmarks(self) -> TestSuiteResult:
        """Run performance benchmarks"""
        logger.info("Running performance benchmarks...")
        
        start_time = time.time()
        test_results = []
        
        # Test 1: Enhanced analyzer initialization performance
        try:
            init_start = time.time()
            from tools.ai_enhanced_analyzer import AIEnhancedAnalyzer
            
            # Create temporary test file
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
                f.write(b"MZ\x90\x00" + b"\x00" * 100)
                test_file = f.name
            
            try:
                analyzer = AIEnhancedAnalyzer(test_file)
                init_duration = time.time() - init_start
                
                if init_duration < 5.0:  # Should initialize within 5 seconds
                    test_results.append(TestResult(
                        test_name="analyzer_initialization",
                        status="passed",
                        duration=init_duration,
                        details=f"Initialization took {init_duration:.3f}s"
                    ))
                else:
                    test_results.append(TestResult(
                        test_name="analyzer_initialization",
                        status="failed",
                        duration=init_duration,
                        error_message=f"Initialization too slow: {init_duration:.3f}s"
                    ))
            finally:
                os.unlink(test_file)
                
        except Exception as e:
            test_results.append(TestResult(
                test_name="analyzer_initialization",
                status="error",
                duration=time.time() - init_start,
                error_message=str(e)
            ))
        
        # Test 2: Configuration manager performance
        try:
            config_start = time.time()
            from tools.enhanced_config_manager import EnhancedConfigManager
            
            manager = EnhancedConfigManager()
            config_duration = time.time() - config_start
            
            if config_duration < 2.0:  # Should load within 2 seconds
                test_results.append(TestResult(
                    test_name="config_manager_performance",
                    status="passed",
                    duration=config_duration,
                    details=f"Config loading took {config_duration:.3f}s"
                ))
            else:
                test_results.append(TestResult(
                    test_name="config_manager_performance",
                    status="failed",
                    duration=config_duration,
                    error_message=f"Config loading too slow: {config_duration:.3f}s"
                ))
                
        except Exception as e:
            test_results.append(TestResult(
                test_name="config_manager_performance",
                status="error",
                duration=time.time() - config_start,
                error_message=str(e)
            ))
        
        # Test 3: Health monitor performance
        try:
            health_start = time.time()
            from tools.enhanced_health_monitor import EnhancedHealthMonitor
            
            monitor = EnhancedHealthMonitor()
            system_health = monitor.check_all_components()
            health_duration = time.time() - health_start
            
            if health_duration < 10.0:  # Should complete within 10 seconds
                test_results.append(TestResult(
                    test_name="health_monitor_performance",
                    status="passed",
                    duration=health_duration,
                    details=f"Health check took {health_duration:.3f}s"
                ))
            else:
                test_results.append(TestResult(
                    test_name="health_monitor_performance",
                    status="failed",
                    duration=health_duration,
                    error_message=f"Health check too slow: {health_duration:.3f}s"
                ))
                
        except Exception as e:
            test_results.append(TestResult(
                test_name="health_monitor_performance",
                status="error",
                duration=time.time() - health_start,
                error_message=str(e)
            ))
        
        # Calculate results
        passed_tests = len([r for r in test_results if r.status == "passed"])
        failed_tests = len([r for r in test_results if r.status == "failed"])
        error_tests = len([r for r in test_results if r.status == "error"])
        
        suite_result = TestSuiteResult(
            suite_name="performance_benchmarks",
            total_tests=len(test_results),
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            skipped_tests=0,
            error_tests=error_tests,
            total_duration=time.time() - start_time,
            test_results=test_results
        )
        
        self.test_results.append(suite_result)
        logger.info(f"Performance benchmarks completed - {suite_result.success_rate:.1f}% success rate")
        
        return suite_result
    
    def run_validation_checks(self) -> List[ValidationResult]:
        """Run system validation checks"""
        logger.info("Running validation checks...")
        
        validation_results = []
        
        # Validation 1: Check required modules are importable
        try:
            required_modules = [
                "reveng_analyzer",
                "tools.ai_enhanced_analyzer",
                "tools.enhanced_config_manager",
                "tools.enhanced_health_monitor",
                "tools.corporate_exposure_detector",
                "tools.vulnerability_discovery_engine",
                "tools.threat_intelligence_correlator",
                "tools.demonstration_generator"
            ]
            
            missing_modules = []
            for module in required_modules:
                try:
                    __import__(module)
                except ImportError:
                    missing_modules.append(module)
            
            if not missing_modules:
                validation_results.append(ValidationResult(
                    validation_name="module_imports",
                    status="passed",
                    message="All required modules are importable",
                    details={"checked_modules": required_modules}
                ))
            else:
                validation_results.append(ValidationResult(
                    validation_name="module_imports",
                    status="failed",
                    message=f"Missing modules: {missing_modules}",
                    details={"missing_modules": missing_modules}
                ))
                
        except Exception as e:
            validation_results.append(ValidationResult(
                validation_name="module_imports",
                status="failed",
                message=f"Error checking module imports: {e}"
            ))
        
        # Validation 2: Check configuration system
        try:
            from tools.enhanced_config_manager import EnhancedConfigManager
            
            manager = EnhancedConfigManager()
            issues = manager.validate_configuration()
            
            if not issues:
                validation_results.append(ValidationResult(
                    validation_name="configuration_validation",
                    status="passed",
                    message="Configuration validation passed"
                ))
            else:
                validation_results.append(ValidationResult(
                    validation_name="configuration_validation",
                    status="warning",
                    message=f"Configuration issues found: {len(issues)}",
                    details={"issues": issues}
                ))
                
        except Exception as e:
            validation_results.append(ValidationResult(
                validation_name="configuration_validation",
                status="failed",
                message=f"Error validating configuration: {e}"
            ))
        
        # Validation 3: Check health monitoring system
        try:
            from tools.enhanced_health_monitor import EnhancedHealthMonitor
            
            monitor = EnhancedHealthMonitor()
            system_health = monitor.check_all_components()
            
            if system_health.overall_status in ["healthy", "warning"]:
                validation_results.append(ValidationResult(
                    validation_name="health_monitoring",
                    status="passed",
                    message=f"Health monitoring operational - status: {system_health.overall_status}",
                    details={"overall_status": system_health.overall_status}
                ))
            else:
                validation_results.append(ValidationResult(
                    validation_name="health_monitoring",
                    status="warning",
                    message=f"Health monitoring shows issues - status: {system_health.overall_status}",
                    details={"overall_status": system_health.overall_status, "alerts": system_health.alerts}
                ))
                
        except Exception as e:
            validation_results.append(ValidationResult(
                validation_name="health_monitoring",
                status="failed",
                message=f"Error checking health monitoring: {e}"
            ))
        
        # Validation 4: Check REVENG integration
        try:
            from reveng_analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures
            
            # Test enhanced features integration
            features = EnhancedAnalysisFeatures()
            self.assertTrue(hasattr(features, 'enable_enhanced_analysis'))
            self.assertTrue(hasattr(features, 'is_any_enhanced_enabled'))
            
            validation_results.append(ValidationResult(
                validation_name="reveng_integration",
                status="passed",
                message="REVENG integration validated successfully"
            ))
            
        except Exception as e:
            validation_results.append(ValidationResult(
                validation_name="reveng_integration",
                status="failed",
                message=f"Error validating REVENG integration: {e}"
            ))
        
        self.validation_results.extend(validation_results)
        
        passed_validations = len([v for v in validation_results if v.status == "passed"])
        logger.info(f"Validation checks completed - {passed_validations}/{len(validation_results)} passed")
        
        return validation_results
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        logger.info("Generating test report...")
        
        # Calculate overall statistics
        total_tests = sum(suite.total_tests for suite in self.test_results)
        total_passed = sum(suite.passed_tests for suite in self.test_results)
        total_failed = sum(suite.failed_tests for suite in self.test_results)
        total_errors = sum(suite.error_tests for suite in self.test_results)
        total_duration = sum(suite.total_duration for suite in self.test_results)
        
        overall_success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        # Validation statistics
        passed_validations = len([v for v in self.validation_results if v.status == "passed"])
        failed_validations = len([v for v in self.validation_results if v.status == "failed"])
        warning_validations = len([v for v in self.validation_results if v.status == "warning"])
        
        report = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "summary": {
                "total_test_suites": len(self.test_results),
                "total_tests": total_tests,
                "total_passed": total_passed,
                "total_failed": total_failed,
                "total_errors": total_errors,
                "overall_success_rate": overall_success_rate,
                "total_duration": total_duration,
                "validations": {
                    "total": len(self.validation_results),
                    "passed": passed_validations,
                    "failed": failed_validations,
                    "warnings": warning_validations
                }
            },
            "test_suites": [asdict(suite) for suite in self.test_results],
            "validations": [asdict(validation) for validation in self.validation_results],
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Check overall success rate
        total_tests = sum(suite.total_tests for suite in self.test_results)
        total_passed = sum(suite.passed_tests for suite in self.test_results)
        success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        if success_rate < 80:
            recommendations.append("Overall test success rate is below 80%. Review failed tests and address issues.")
        
        # Check for performance issues
        for suite in self.test_results:
            if suite.suite_name == "performance_benchmarks":
                failed_perf_tests = [r for r in suite.test_results if r.status == "failed"]
                if failed_perf_tests:
                    recommendations.append("Performance benchmarks failed. Consider optimizing slow components.")
        
        # Check validation results
        failed_validations = [v for v in self.validation_results if v.status == "failed"]
        if failed_validations:
            recommendations.append("System validation checks failed. Review configuration and dependencies.")
        
        # Check for missing modules
        for validation in self.validation_results:
            if validation.validation_name == "module_imports" and validation.status == "failed":
                recommendations.append("Required modules are missing. Run deployment script to install dependencies.")
        
        if not recommendations:
            recommendations.append("All tests and validations passed successfully. System is ready for production use.")
        
        return recommendations
    
    def save_report(self, filename: str = None) -> str:
        """
        Save test report to file
        
        Args:
            filename: Optional filename for the report
            
        Returns:
            Path to saved report file
        """
        if filename is None:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"enhanced_analysis_test_report_{timestamp}.json"
        
        report_path = self.output_dir / filename
        report = self.generate_test_report()
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Test report saved to {report_path}")
        return str(report_path)
    
    def run_all_tests(self) -> bool:
        """
        Run all tests and validations
        
        Returns:
            True if all tests passed, False otherwise
        """
        logger.info("Starting comprehensive test suite...")
        
        start_time = time.time()
        
        try:
            # Run test suites
            self.run_unit_tests()
            self.run_integration_tests()
            self.run_performance_benchmarks()
            
            # Run validations
            self.run_validation_checks()
            
            # Generate and save report
            report_path = self.save_report()
            
            # Calculate overall success
            total_tests = sum(suite.total_tests for suite in self.test_results)
            total_passed = sum(suite.passed_tests for suite in self.test_results)
            success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
            
            failed_validations = len([v for v in self.validation_results if v.status == "failed"])
            
            total_duration = time.time() - start_time
            
            logger.info(f"Test suite completed in {total_duration:.2f}s")
            logger.info(f"Test success rate: {success_rate:.1f}%")
            logger.info(f"Failed validations: {failed_validations}")
            logger.info(f"Report saved to: {report_path}")
            
            # Consider success if >90% tests pass and no critical validations fail
            return success_rate >= 90 and failed_validations == 0
            
        except Exception as e:
            logger.error(f"Error running test suite: {e}")
            return False


def main():
    """Main function for test runner"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced Analysis Test Runner'
    )
    parser.add_argument('--unit-only', action='store_true',
                       help='Run unit tests only')
    parser.add_argument('--integration-only', action='store_true',
                       help='Run integration tests only')
    parser.add_argument('--performance-only', action='store_true',
                       help='Run performance benchmarks only')
    parser.add_argument('--validation-only', action='store_true',
                       help='Run validation checks only')
    parser.add_argument('--output-dir', default='test_results',
                       help='Output directory for test results')
    parser.add_argument('--report-file', help='Custom report filename')
    
    args = parser.parse_args()
    
    # Create test runner
    runner = EnhancedTestRunner(output_dir=args.output_dir)
    
    success = True
    
    try:
        if args.unit_only:
            result = runner.run_unit_tests()
            success = result.success_rate >= 90
        elif args.integration_only:
            result = runner.run_integration_tests()
            success = result.success_rate >= 90
        elif args.performance_only:
            result = runner.run_performance_benchmarks()
            success = result.success_rate >= 90
        elif args.validation_only:
            results = runner.run_validation_checks()
            failed = len([r for r in results if r.status == "failed"])
            success = failed == 0
        else:
            # Run all tests
            success = runner.run_all_tests()
        
        # Save report
        if args.report_file:
            runner.save_report(args.report_file)
        elif not (args.unit_only or args.integration_only or args.performance_only or args.validation_only):
            # Only auto-save for full test runs
            pass
        else:
            runner.save_report()
        
    except KeyboardInterrupt:
        logger.info("Test run interrupted by user")
        success = False
    except Exception as e:
        logger.error(f"Test run failed: {e}")
        success = False
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()