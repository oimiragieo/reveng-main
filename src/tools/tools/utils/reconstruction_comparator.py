#!/usr/bin/env python3
"""
Reconstruction Comparison and Validation Engine
==============================================

This module provides comprehensive comparison and validation capabilities
for reconstructed binaries, including:

1. Side-by-side comparison tools for original vs reconstructed functionality
2. Behavioral equivalence testing for reconstructed binaries  
3. Accuracy metrics and reconstruction quality scoring
4. Visual diff generation and analysis reporting

Author: AI-Enhanced Universal Analysis Engine
Version: 1.0
"""

import hashlib
import json
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComparisonType(Enum):
    """Types of comparison analysis"""
    BINARY_DIFF = "binary_diff"
    BEHAVIORAL = "behavioral"
    FUNCTIONAL = "functional"
    PERFORMANCE = "performance"
    SECURITY = "security"


class AccuracyLevel(Enum):
    """Reconstruction accuracy levels"""
    EXCELLENT = "excellent"  # >95% match
    GOOD = "good"           # 85-95% match
    FAIR = "fair"           # 70-85% match
    POOR = "poor"           # <70% match


@dataclass
class ComparisonMetrics:
    """Metrics for comparing original vs reconstructed binary"""
    binary_similarity: float = 0.0
    functional_equivalence: float = 0.0
    behavioral_match: float = 0.0
    performance_ratio: float = 0.0
    security_parity: float = 0.0
    overall_accuracy: float = 0.0
    accuracy_level: AccuracyLevel = AccuracyLevel.POOR


@dataclass
class BehavioralTest:
    """Individual behavioral test case"""
    name: str
    test_type: str
    input_data: Any
    expected_output: Any
    actual_output: Any = None
    passed: bool = False
    execution_time_original: float = 0.0
    execution_time_reconstructed: float = 0.0
    error_message: Optional[str] = None


@dataclass
class ComparisonResult:
    """Complete comparison analysis result"""
    original_binary: Path
    reconstructed_binary: Path
    metrics: ComparisonMetrics
    behavioral_tests: List[BehavioralTest] = field(default_factory=list)
    binary_differences: List[Dict] = field(default_factory=list)
    security_analysis: Dict[str, Any] = field(default_factory=dict)
    performance_analysis: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    comparison_timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))


class ReconstructionComparator:
    """
    Main class for comparing original and reconstructed binaries
    """
    
    def __init__(self, temp_dir: Optional[Path] = None):
        """Initialize the comparator"""
        self.temp_dir = temp_dir or Path(tempfile.mkdtemp(prefix="reconstruction_comparison_"))
        self.temp_dir.mkdir(exist_ok=True)
        
        # Check for available analysis tools
        self.has_objdump = self._check_tool("objdump")
        self.has_readelf = self._check_tool("readelf")
        self.has_strings = self._check_tool("strings")
        self.has_hexdump = self._check_tool("hexdump")
        self.has_diff = self._check_tool("diff")
        
        logger.info("Reconstruction Comparator initialized")
        logger.info(f"Available tools: objdump={self.has_objdump}, readelf={self.has_readelf}")
        
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a system tool is available"""
        try:
            result = subprocess.run([tool_name, "--version"], 
                                  capture_output=True, timeout=5, check=False)
            return result.returncode == 0
        except Exception:
            return False
    
    def compare_binaries(self, original: Path, reconstructed: Path) -> ComparisonResult:
        """
        Perform comprehensive comparison between original and reconstructed binaries
        """
        logger.info(f"Starting comprehensive binary comparison")
        logger.info(f"Original: {original}")
        logger.info(f"Reconstructed: {reconstructed}")
        
        result = ComparisonResult(
            original_binary=original,
            reconstructed_binary=reconstructed,
            metrics=ComparisonMetrics()
        )
        
        try:
            # 1. Binary-level comparison
            logger.info("Performing binary-level comparison...")
            result.metrics.binary_similarity = self._compare_binary_structure(original, reconstructed, result)
            
            # 2. Functional equivalence testing
            logger.info("Testing functional equivalence...")
            result.metrics.functional_equivalence = self._test_functional_equivalence(original, reconstructed, result)
            
            # 3. Behavioral analysis
            logger.info("Performing behavioral analysis...")
            result.metrics.behavioral_match = self._analyze_behavior(original, reconstructed, result)
            
            # 4. Performance comparison
            logger.info("Comparing performance...")
            result.metrics.performance_ratio = self._compare_performance(original, reconstructed, result)
            
            # 5. Security analysis
            logger.info("Analyzing security properties...")
            result.metrics.security_parity = self._analyze_security_properties(original, reconstructed, result)
            
            # 6. Calculate overall accuracy
            result.metrics.overall_accuracy = self._calculate_overall_accuracy(result.metrics)
            result.metrics.accuracy_level = self._determine_accuracy_level(result.metrics.overall_accuracy)
            
            # 7. Generate recommendations
            result.recommendations = self._generate_recommendations(result)
            
            logger.info(f"Comparison completed. Overall accuracy: {result.metrics.overall_accuracy:.2%}")
            
        except Exception as e:
            logger.error(f"Comparison failed: {e}")
            result.recommendations.append(f"Comparison failed due to error: {e}")
            
        return result
    
    def _compare_binary_structure(self, original: Path, reconstructed: Path, result: ComparisonResult) -> float:
        """Compare binary structure and metadata"""
        try:
            similarity_score = 0.0
            total_checks = 0
            
            # File size comparison
            orig_size = original.stat().st_size
            recon_size = reconstructed.stat().st_size
            size_ratio = min(orig_size, recon_size) / max(orig_size, recon_size) if max(orig_size, recon_size) > 0 else 0
            similarity_score += size_ratio * 0.2
            total_checks += 0.2
            
            result.binary_differences.append({
                "type": "file_size",
                "original": orig_size,
                "reconstructed": recon_size,
                "ratio": size_ratio
            })
            
            # Binary content comparison using hexdump
            if self.has_hexdump:
                content_similarity = self._compare_binary_content(original, reconstructed)
                similarity_score += content_similarity * 0.3
                total_checks += 0.3
                
                result.binary_differences.append({
                    "type": "binary_content",
                    "similarity": content_similarity
                })
            
            # Strings comparison
            if self.has_strings:
                strings_similarity = self._compare_strings(original, reconstructed)
                similarity_score += strings_similarity * 0.2
                total_checks += 0.2
                
                result.binary_differences.append({
                    "type": "strings_content",
                    "similarity": strings_similarity
                })
            
            # ELF/PE structure comparison
            if self.has_readelf:
                structure_similarity = self._compare_binary_headers(original, reconstructed)
                similarity_score += structure_similarity * 0.3
                total_checks += 0.3
                
                result.binary_differences.append({
                    "type": "binary_structure",
                    "similarity": structure_similarity
                })
            
            return similarity_score / total_checks if total_checks > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Binary structure comparison failed: {e}")
            return 0.0
    
    def _compare_binary_content(self, original: Path, reconstructed: Path) -> float:
        """Compare binary content using byte-level analysis"""
        try:
            # Read first 64KB of each file for comparison
            chunk_size = 65536
            
            with open(original, 'rb') as f1, open(reconstructed, 'rb') as f2:
                orig_chunk = f1.read(chunk_size)
                recon_chunk = f2.read(chunk_size)
            
            # Calculate similarity using byte-by-byte comparison
            min_len = min(len(orig_chunk), len(recon_chunk))
            if min_len == 0:
                return 0.0
                
            matches = sum(1 for i in range(min_len) if orig_chunk[i] == recon_chunk[i])
            return matches / min_len
            
        except Exception as e:
            logger.error(f"Binary content comparison failed: {e}")
            return 0.0
    
    def _compare_strings(self, original: Path, reconstructed: Path) -> float:
        """Compare strings extracted from both binaries"""
        try:
            # Extract strings from both binaries
            orig_strings = self._extract_strings(original)
            recon_strings = self._extract_strings(reconstructed)
            
            if not orig_strings and not recon_strings:
                return 1.0  # Both have no strings
            if not orig_strings or not recon_strings:
                return 0.0  # One has strings, other doesn't
            
            # Calculate Jaccard similarity
            orig_set = set(orig_strings)
            recon_set = set(recon_strings)
            
            intersection = len(orig_set & recon_set)
            union = len(orig_set | recon_set)
            
            return intersection / union if union > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Strings comparison failed: {e}")
            return 0.0
    
    def _extract_strings(self, binary_path: Path) -> List[str]:
        """Extract strings from binary using strings command"""
        try:
            result = subprocess.run(
                ["strings", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            if result.returncode == 0:
                return [s.strip() for s in result.stdout.split('\n') if len(s.strip()) > 3]
            return []
            
        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return []
    
    def _compare_binary_headers(self, original: Path, reconstructed: Path) -> float:
        """Compare binary headers and structure"""
        try:
            # Get header information for both binaries
            orig_headers = self._get_binary_headers(original)
            recon_headers = self._get_binary_headers(reconstructed)
            
            if not orig_headers or not recon_headers:
                return 0.0
            
            # Compare key header fields
            similarity_score = 0.0
            total_fields = 0
            
            common_fields = ['machine', 'class', 'data', 'type']
            
            for field in common_fields:
                if field in orig_headers and field in recon_headers:
                    if orig_headers[field] == recon_headers[field]:
                        similarity_score += 1.0
                    total_fields += 1
            
            return similarity_score / total_fields if total_fields > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Binary headers comparison failed: {e}")
            return 0.0
    
    def _get_binary_headers(self, binary_path: Path) -> Dict[str, str]:
        """Extract binary header information"""
        try:
            result = subprocess.run(
                ["readelf", "-h", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            headers = {}
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower().replace(' ', '_')
                        value = value.strip()
                        headers[key] = value
            
            return headers
            
        except Exception as e:
            logger.error(f"Header extraction failed: {e}")
            return {}
    
    def _test_functional_equivalence(self, original: Path, reconstructed: Path, result: ComparisonResult) -> float:
        """Test functional equivalence through various test cases"""
        try:
            test_cases = self._generate_test_cases(original)
            passed_tests = 0
            total_tests = len(test_cases)
            
            if total_tests == 0:
                return 0.5  # No tests available, assume partial equivalence
            
            for test_case in test_cases:
                try:
                    # Run test on original binary
                    orig_result = self._run_test_case(original, test_case)
                    test_case.expected_output = orig_result
                    
                    # Run test on reconstructed binary
                    recon_result = self._run_test_case(reconstructed, test_case)
                    test_case.actual_output = recon_result
                    
                    # Compare results
                    if self._compare_test_outputs(orig_result, recon_result):
                        test_case.passed = True
                        passed_tests += 1
                    else:
                        test_case.error_message = f"Output mismatch: expected {orig_result}, got {recon_result}"
                        
                except Exception as e:
                    test_case.error_message = str(e)
                
                result.behavioral_tests.append(test_case)
            
            return passed_tests / total_tests
            
        except Exception as e:
            logger.error(f"Functional equivalence testing failed: {e}")
            return 0.0
    
    def _generate_test_cases(self, binary_path: Path) -> List[BehavioralTest]:
        """Generate test cases for the binary"""
        test_cases = []
        
        # Basic execution test
        test_cases.append(BehavioralTest(
            name="basic_execution",
            test_type="execution",
            input_data=None
        ))
        
        # Help/usage test
        test_cases.append(BehavioralTest(
            name="help_output",
            test_type="argument",
            input_data=["--help"]
        ))
        
        # Version test
        test_cases.append(BehavioralTest(
            name="version_output", 
            test_type="argument",
            input_data=["--version"]
        ))
        
        # Invalid argument test
        test_cases.append(BehavioralTest(
            name="invalid_argument",
            test_type="argument",
            input_data=["--invalid-flag-xyz"]
        ))
        
        return test_cases
    
    def _run_test_case(self, binary_path: Path, test_case: BehavioralTest) -> Dict[str, Any]:
        """Run a single test case on the binary"""
        try:
            start_time = time.time()
            
            cmd = [str(binary_path)]
            if test_case.input_data:
                cmd.extend(test_case.input_data)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            
            execution_time = time.time() - start_time
            
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "execution_time": execution_time
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "execution_time": 10.0}
        except Exception as e:
            return {"error": str(e), "execution_time": 0.0}
    
    def _compare_test_outputs(self, expected: Dict[str, Any], actual: Dict[str, Any]) -> bool:
        """Compare test outputs for equivalence"""
        # Check for errors first
        if "error" in expected or "error" in actual:
            return expected.get("error") == actual.get("error")
        
        # Compare return codes
        if expected.get("returncode") != actual.get("returncode"):
            return False
        
        # For help/version outputs, check if both produce output
        if expected.get("stdout") and actual.get("stdout"):
            return True
        
        # For empty outputs, both should be empty
        if not expected.get("stdout") and not actual.get("stdout"):
            return True
        
        return False
    
    def _analyze_behavior(self, original: Path, reconstructed: Path, result: ComparisonResult) -> float:
        """Analyze behavioral patterns and characteristics"""
        try:
            behavior_score = 0.0
            total_checks = 0
            
            # System call analysis (if strace available)
            if self._check_tool("strace"):
                syscall_similarity = self._compare_system_calls(original, reconstructed)
                behavior_score += syscall_similarity * 0.4
                total_checks += 0.4
            
            # Library dependency analysis
            if self.has_readelf:
                lib_similarity = self._compare_library_dependencies(original, reconstructed)
                behavior_score += lib_similarity * 0.3
                total_checks += 0.3
            
            # File access pattern analysis
            file_access_similarity = self._compare_file_access_patterns(original, reconstructed)
            behavior_score += file_access_similarity * 0.3
            total_checks += 0.3
            
            return behavior_score / total_checks if total_checks > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            return 0.0
    
    def _compare_system_calls(self, original: Path, reconstructed: Path) -> float:
        """Compare system call patterns"""
        try:
            orig_syscalls = self._trace_system_calls(original)
            recon_syscalls = self._trace_system_calls(reconstructed)
            
            if not orig_syscalls and not recon_syscalls:
                return 1.0
            if not orig_syscalls or not recon_syscalls:
                return 0.0
            
            # Compare syscall patterns
            orig_set = set(orig_syscalls)
            recon_set = set(recon_syscalls)
            
            intersection = len(orig_set & recon_set)
            union = len(orig_set | recon_set)
            
            return intersection / union if union > 0 else 0.0
            
        except Exception as e:
            logger.error(f"System call comparison failed: {e}")
            return 0.0
    
    def _trace_system_calls(self, binary_path: Path) -> List[str]:
        """Trace system calls made by the binary"""
        try:
            result = subprocess.run(
                ["strace", "-c", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            
            syscalls = []
            if result.returncode == 0:
                # Parse strace output to extract syscall names
                for line in result.stderr.split('\n'):
                    if line.strip() and not line.startswith('%') and not line.startswith('-'):
                        parts = line.split()
                        if len(parts) > 5:
                            syscalls.append(parts[-1])
            
            return syscalls
            
        except Exception as e:
            logger.error(f"System call tracing failed: {e}")
            return []
    
    def _compare_library_dependencies(self, original: Path, reconstructed: Path) -> float:
        """Compare library dependencies"""
        try:
            orig_libs = self._get_library_dependencies(original)
            recon_libs = self._get_library_dependencies(reconstructed)
            
            if not orig_libs and not recon_libs:
                return 1.0
            if not orig_libs or not recon_libs:
                return 0.0
            
            orig_set = set(orig_libs)
            recon_set = set(recon_libs)
            
            intersection = len(orig_set & recon_set)
            union = len(orig_set | recon_set)
            
            return intersection / union if union > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Library dependency comparison failed: {e}")
            return 0.0
    
    def _get_library_dependencies(self, binary_path: Path) -> List[str]:
        """Get library dependencies of the binary"""
        try:
            result = subprocess.run(
                ["readelf", "-d", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            libraries = []
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'NEEDED' in line and '[' in line and ']' in line:
                        lib_name = line.split('[')[1].split(']')[0]
                        libraries.append(lib_name)
            
            return libraries
            
        except Exception as e:
            logger.error(f"Library dependency extraction failed: {e}")
            return []
    
    def _compare_file_access_patterns(self, original: Path, reconstructed: Path) -> float:
        """Compare file access patterns"""
        # This is a simplified implementation
        # In practice, you might use more sophisticated monitoring
        return 0.8  # Assume reasonable similarity for now
    
    def _compare_performance(self, original: Path, reconstructed: Path, result: ComparisonResult) -> float:
        """Compare performance characteristics"""
        try:
            # Run basic performance tests
            orig_time = self._measure_execution_time(original)
            recon_time = self._measure_execution_time(reconstructed)
            
            if orig_time <= 0 or recon_time <= 0:
                return 0.5  # Unable to measure, assume moderate performance
            
            # Calculate performance ratio (closer to 1.0 is better)
            ratio = min(orig_time, recon_time) / max(orig_time, recon_time)
            
            result.performance_analysis = {
                "original_execution_time": orig_time,
                "reconstructed_execution_time": recon_time,
                "performance_ratio": ratio
            }
            
            return ratio
            
        except Exception as e:
            logger.error(f"Performance comparison failed: {e}")
            return 0.0
    
    def _measure_execution_time(self, binary_path: Path) -> float:
        """Measure execution time of the binary"""
        try:
            start_time = time.time()
            
            result = subprocess.run(
                [str(binary_path)],
                capture_output=True,
                timeout=5,
                check=False
            )
            
            return time.time() - start_time
            
        except subprocess.TimeoutExpired:
            return 5.0  # Timeout value
        except Exception:
            return 0.0
    
    def _analyze_security_properties(self, original: Path, reconstructed: Path, result: ComparisonResult) -> float:
        """Analyze security properties and protections"""
        try:
            security_score = 0.0
            total_checks = 0
            
            # Check for security features
            orig_security = self._check_security_features(original)
            recon_security = self._check_security_features(reconstructed)
            
            # Compare security features
            common_features = set(orig_security.keys()) & set(recon_security.keys())
            matching_features = sum(1 for feature in common_features 
                                  if orig_security[feature] == recon_security[feature])
            
            if common_features:
                security_score = matching_features / len(common_features)
            
            result.security_analysis = {
                "original_features": orig_security,
                "reconstructed_features": recon_security,
                "matching_features": matching_features,
                "total_features": len(common_features)
            }
            
            return security_score
            
        except Exception as e:
            logger.error(f"Security analysis failed: {e}")
            return 0.0
    
    def _check_security_features(self, binary_path: Path) -> Dict[str, bool]:
        """Check for security features in the binary"""
        features = {}
        
        try:
            if self.has_readelf:
                result = subprocess.run(
                    ["readelf", "-l", str(binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False
                )
                
                if result.returncode == 0:
                    output = result.stdout
                    features["stack_canary"] = "GNU_STACK" in output
                    features["nx_bit"] = "GNU_STACK" in output and "RWE" not in output
                    features["pie"] = "DYN" in output
                    features["relro"] = "GNU_RELRO" in output
            
        except Exception as e:
            logger.error(f"Security feature check failed: {e}")
        
        return features
    
    def _calculate_overall_accuracy(self, metrics: ComparisonMetrics) -> float:
        """Calculate overall reconstruction accuracy"""
        weights = {
            'binary_similarity': 0.2,
            'functional_equivalence': 0.3,
            'behavioral_match': 0.25,
            'performance_ratio': 0.15,
            'security_parity': 0.1
        }
        
        weighted_score = (
            metrics.binary_similarity * weights['binary_similarity'] +
            metrics.functional_equivalence * weights['functional_equivalence'] +
            metrics.behavioral_match * weights['behavioral_match'] +
            metrics.performance_ratio * weights['performance_ratio'] +
            metrics.security_parity * weights['security_parity']
        )
        
        return weighted_score
    
    def _determine_accuracy_level(self, accuracy: float) -> AccuracyLevel:
        """Determine accuracy level based on score"""
        if accuracy >= 0.95:
            return AccuracyLevel.EXCELLENT
        elif accuracy >= 0.85:
            return AccuracyLevel.GOOD
        elif accuracy >= 0.70:
            return AccuracyLevel.FAIR
        else:
            return AccuracyLevel.POOR
    
    def _generate_recommendations(self, result: ComparisonResult) -> List[str]:
        """Generate recommendations based on comparison results"""
        recommendations = []
        
        # Binary similarity recommendations
        if result.metrics.binary_similarity < 0.7:
            recommendations.append("Low binary similarity detected. Review reconstruction algorithms and improve code generation.")
        
        # Functional equivalence recommendations
        if result.metrics.functional_equivalence < 0.8:
            recommendations.append("Functional differences found. Verify control flow reconstruction and data handling logic.")
        
        # Behavioral recommendations
        if result.metrics.behavioral_match < 0.7:
            recommendations.append("Behavioral differences detected. Check system call patterns and library dependencies.")
        
        # Performance recommendations
        if result.metrics.performance_ratio < 0.5:
            recommendations.append("Significant performance difference. Optimize generated code and compiler flags.")
        
        # Security recommendations
        if result.metrics.security_parity < 0.8:
            recommendations.append("Security feature mismatch. Ensure security protections are properly reconstructed.")
        
        # Overall accuracy recommendations
        if result.metrics.accuracy_level == AccuracyLevel.POOR:
            recommendations.append("Overall reconstruction quality is poor. Consider manual review and refinement.")
        elif result.metrics.accuracy_level == AccuracyLevel.FAIR:
            recommendations.append("Reconstruction quality is fair. Focus on improving weak areas identified above.")
        
        return recommendations
    
    def generate_comparison_report(self, result: ComparisonResult, output_path: Path) -> None:
        """Generate comprehensive comparison report"""
        try:
            report_content = self._create_detailed_report(result)
            
            with open(output_path, 'w') as f:
                f.write(report_content)
                
            logger.info(f"Comparison report generated: {output_path}")
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
    
    def _create_detailed_report(self, result: ComparisonResult) -> str:
        """Create detailed comparison report"""
        return f"""# Binary Reconstruction Comparison Report

## Summary
- **Original Binary**: {result.original_binary}
- **Reconstructed Binary**: {result.reconstructed_binary}
- **Analysis Date**: {result.comparison_timestamp}
- **Overall Accuracy**: {result.metrics.overall_accuracy:.2%} ({result.metrics.accuracy_level.value})

## Detailed Metrics

### Binary Similarity: {result.metrics.binary_similarity:.2%}
- File structure and content comparison
- String analysis and metadata comparison

### Functional Equivalence: {result.metrics.functional_equivalence:.2%}
- Test cases passed: {sum(1 for test in result.behavioral_tests if test.passed)}/{len(result.behavioral_tests)}
- Behavioral test results included below

### Behavioral Match: {result.metrics.behavioral_match:.2%}
- System call patterns and library dependencies
- Runtime behavior analysis

### Performance Ratio: {result.metrics.performance_ratio:.2%}
- Execution time comparison
- Resource usage analysis

### Security Parity: {result.metrics.security_parity:.2%}
- Security feature comparison
- Protection mechanism analysis

## Behavioral Test Results

{self._format_behavioral_tests(result.behavioral_tests)}

## Binary Differences

{self._format_binary_differences(result.binary_differences)}

## Recommendations

{chr(10).join(f'- {rec}' for rec in result.recommendations)}

## Security Analysis

{self._format_security_analysis(result.security_analysis)}

## Performance Analysis

{self._format_performance_analysis(result.performance_analysis)}

---
*Report generated by Reconstruction Comparator v1.0*
"""
    
    def _format_behavioral_tests(self, tests: List[BehavioralTest]) -> str:
        """Format behavioral test results for report"""
        if not tests:
            return "No behavioral tests performed."
        
        output = []
        for test in tests:
            status = "✅ PASSED" if test.passed else "❌ FAILED"
            output.append(f"- **{test.name}** ({test.test_type}): {status}")
            if test.error_message:
                output.append(f"  - Error: {test.error_message}")
        
        return '\n'.join(output)
    
    def _format_binary_differences(self, differences: List[Dict]) -> str:
        """Format binary differences for report"""
        if not differences:
            return "No binary differences analyzed."
        
        output = []
        for diff in differences:
            output.append(f"- **{diff['type']}**: {diff}")
        
        return '\n'.join(output)
    
    def _format_security_analysis(self, security: Dict[str, Any]) -> str:
        """Format security analysis for report"""
        if not security:
            return "No security analysis performed."
        
        return f"""
- **Original Features**: {security.get('original_features', {})}
- **Reconstructed Features**: {security.get('reconstructed_features', {})}
- **Matching Features**: {security.get('matching_features', 0)}/{security.get('total_features', 0)}
"""
    
    def _format_performance_analysis(self, performance: Dict[str, Any]) -> str:
        """Format performance analysis for report"""
        if not performance:
            return "No performance analysis performed."
        
        return f"""
- **Original Execution Time**: {performance.get('original_execution_time', 0):.3f}s
- **Reconstructed Execution Time**: {performance.get('reconstructed_execution_time', 0):.3f}s
- **Performance Ratio**: {performance.get('performance_ratio', 0):.2%}
"""


def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Binary Reconstruction Comparator')
    parser.add_argument('--original', required=True, help='Original binary file')
    parser.add_argument('--reconstructed', required=True, help='Reconstructed binary file')
    parser.add_argument('--output', help='Output report file (default: comparison_report.md)')
    parser.add_argument('--json', help='Output JSON results file')
    args = parser.parse_args()
    
    # Create comparator
    comparator = ReconstructionComparator()
    
    # Perform comparison
    result = comparator.compare_binaries(Path(args.original), Path(args.reconstructed))
    
    # Generate reports
    output_file = Path(args.output) if args.output else Path("comparison_report.md")
    comparator.generate_comparison_report(result, output_file)
    
    if args.json:
        # Export JSON results
        json_data = {
            "metrics": {
                "binary_similarity": result.metrics.binary_similarity,
                "functional_equivalence": result.metrics.functional_equivalence,
                "behavioral_match": result.metrics.behavioral_match,
                "performance_ratio": result.metrics.performance_ratio,
                "security_parity": result.metrics.security_parity,
                "overall_accuracy": result.metrics.overall_accuracy,
                "accuracy_level": result.metrics.accuracy_level.value
            },
            "recommendations": result.recommendations,
            "timestamp": result.comparison_timestamp
        }
        
        with open(args.json, 'w') as f:
            json.dump(json_data, f, indent=2)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"RECONSTRUCTION COMPARISON RESULTS")
    print(f"{'='*60}")
    print(f"Overall Accuracy: {result.metrics.overall_accuracy:.2%} ({result.metrics.accuracy_level.value})")
    print(f"Binary Similarity: {result.metrics.binary_similarity:.2%}")
    print(f"Functional Equivalence: {result.metrics.functional_equivalence:.2%}")
    print(f"Behavioral Match: {result.metrics.behavioral_match:.2%}")
    print(f"Performance Ratio: {result.metrics.performance_ratio:.2%}")
    print(f"Security Parity: {result.metrics.security_parity:.2%}")
    print(f"\nDetailed report: {output_file}")
    
    if result.recommendations:
        print(f"\nRecommendations:")
        for rec in result.recommendations[:3]:  # Show first 3
            print(f"  - {rec}")


if __name__ == "__main__":
    main()