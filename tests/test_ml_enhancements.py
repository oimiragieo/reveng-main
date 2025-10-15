#!/usr/bin/env python3
"""
Test ML Enhancements
===================

Test script for the ML enhancements in the AI-Enhanced Universal Binary Analysis Engine.
Tests vulnerability prediction, malware classification, and NLP code analysis.

Author: REVENG Project - AI Enhancement Module
Version: 1.0
"""

import sys
import os
import tempfile
from pathlib import Path

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent / "tools"))

def test_vulnerability_predictor():
    """Test ML vulnerability predictor"""
    print("=" * 60)
    print("Testing ML Vulnerability Predictor")
    print("=" * 60)
    
    try:
        from tools.ml_vulnerability_predictor import MLVulnerabilityPredictor
        
        predictor = MLVulnerabilityPredictor()
        
        # Test code with vulnerabilities
        test_code = """
        #include <stdio.h>
        #include <string.h>
        
        void vulnerable_function(char *input) {
            char buffer[100];
            strcpy(buffer, input);  // Buffer overflow vulnerability
            printf("%s", buffer);
        }
        
        void memory_leak() {
            char *ptr = malloc(100);
            if (some_condition) {
                return;  // Memory leak
            }
            free(ptr);
        }
        
        void sql_injection(char *user_input) {
            char query[500];
            sprintf(query, "SELECT * FROM users WHERE name='%s'", user_input);
            execute_query(query);  // SQL injection
        }
        """
        
        print("Analyzing test code for vulnerabilities...")
        predictions = predictor.predict_vulnerabilities(test_code, "c")
        
        print(f"Found {len(predictions)} vulnerability predictions:")
        for i, pred in enumerate(predictions, 1):
            print(f"  {i}. {pred.vulnerability_type}")
            print(f"     Confidence: {pred.confidence:.2f}")
            print(f"     Severity: {pred.severity}")
            print(f"     Vulnerable: {pred.is_vulnerable}")
            print(f"     Features: {pred.features_used[:3]}")  # Show first 3 features
            print()
        
        # Test training
        print("Testing model training...")
        training_data = predictor.generate_synthetic_training_data()
        success = predictor.train_model(training_data, "general")
        print(f"Training successful: {success}")
        
        return True
        
    except Exception as e:
        print(f"Error testing vulnerability predictor: {e}")
        return False


def test_malware_classifier():
    """Test ML malware classifier"""
    print("=" * 60)
    print("Testing ML Malware Classifier")
    print("=" * 60)
    
    try:
        from tools.ml_malware_classifier import MLMalwareClassifier
        
        classifier = MLMalwareClassifier()
        
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.exe', delete=False) as f:
            f.write("This is a test binary file for malware classification")
            test_file = f.name
        
        try:
            # Test data
            test_strings = [
                "http://malicious-domain.com",
                "CreateProcess",
                "RegSetValue",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "cmd.exe /c del",
                "bitcoin",
                "encrypt"
            ]
            
            test_apis = [
                "CreateProcess",
                "RegSetValue", 
                "InternetConnect",
                "WriteProcessMemory",
                "VirtualAlloc"
            ]
            
            test_code_analysis = {
                "function_count": 25,
                "import_count": 15,
                "section_count": 4,
                "entropy": 7.8,
                "is_packed": True
            }
            
            print("Classifying test sample...")
            classification = classifier.classify_malware(
                test_file, test_strings, test_apis, test_code_analysis
            )
            
            print(f"Classification Results:")
            print(f"  Family: {classification.family}")
            print(f"  Confidence: {classification.confidence:.2f}")
            print(f"  Is Malware: {classification.is_malware}")
            print(f"  Anomaly Score: {classification.anomaly_score:.2f}")
            print(f"  Behavioral Cluster: {classification.behavioral_cluster}")
            print(f"  Behavioral Patterns: {len(classification.behavioral_patterns)}")
            
            for pattern in classification.behavioral_patterns[:3]:  # Show first 3
                print(f"    - {pattern.type}: {pattern.description}")
            
            print(f"  Similarity Scores:")
            for family, score in list(classification.similarity_scores.items())[:5]:
                print(f"    - {family}: {score:.3f}")
            
            return True
            
        finally:
            # Clean up temp file
            os.unlink(test_file)
        
    except Exception as e:
        print(f"Error testing malware classifier: {e}")
        return False


def test_nlp_analyzer():
    """Test NLP code analyzer"""
    print("=" * 60)
    print("Testing NLP Code Analyzer")
    print("=" * 60)
    
    try:
        from tools.nlp_code_analyzer import DocumentationGenerator
        
        analyzer = DocumentationGenerator()
        
        # Test code for NLP analysis
        test_code = """
        #include <stdio.h>
        #include <stdlib.h>
        
        /**
         * Bubble sort implementation
         * Sorts an array of integers in ascending order
         */
        void bubble_sort(int arr[], int n) {
            // Outer loop for number of passes
            for (int i = 0; i < n-1; i++) {
                // Inner loop for comparisons in each pass
                for (int j = 0; j < n-i-1; j++) {
                    if (arr[j] > arr[j+1]) {
                        // Swap elements
                        int temp = arr[j];
                        arr[j] = arr[j+1];
                        arr[j+1] = temp;
                    }
                }
            }
        }
        
        /**
         * Binary search implementation
         * Searches for a target value in a sorted array
         */
        int binary_search(int arr[], int size, int target) {
            int left = 0;
            int right = size - 1;
            
            while (left <= right) {
                int mid = left + (right - left) / 2;
                
                if (arr[mid] == target) {
                    return mid;  // Found target
                }
                
                if (arr[mid] < target) {
                    left = mid + 1;
                } else {
                    right = mid - 1;
                }
            }
            
            return -1;  // Target not found
        }
        
        int main() {
            int data[] = {64, 34, 25, 12, 22, 11, 90};
            int size = sizeof(data)/sizeof(data[0]);
            
            printf("Original array: ");
            for (int i = 0; i < size; i++) {
                printf("%d ", data[i]);
            }
            
            bubble_sort(data, size);
            
            printf("\\nSorted array: ");
            for (int i = 0; i < size; i++) {
                printf("%d ", data[i]);
            }
            
            int target = 25;
            int result = binary_search(data, size, target);
            
            if (result != -1) {
                printf("\\nElement %d found at index %d\\n", target, result);
            } else {
                printf("\\nElement %d not found\\n", target);
            }
            
            return 0;
        }
        """
        
        print("Analyzing code with NLP...")
        summary = analyzer.generate_code_summary(test_code, "c")
        
        print(f"Code Summary:")
        print(f"  Overview: {summary.overview}")
        print(f"  Key Functions: {summary.key_functions}")
        print(f"  Algorithms Detected: {summary.algorithms_used}")
        print(f"  Design Patterns: {summary.design_patterns}")
        print(f"  Data Structures: {summary.data_structures}")
        
        if summary.complexity_analysis:
            print(f"  Complexity Analysis:")
            for metric, value in summary.complexity_analysis.items():
                print(f"    - {metric}: {value}")
        
        print(f"  Documentation Suggestions: {len(summary.documentation_suggestions)}")
        for suggestion in summary.documentation_suggestions[:3]:  # Show first 3
            print(f"    - {suggestion.type}: {suggestion.description}")
        
        if summary.semantic_analysis:
            print(f"  Semantic Analysis:")
            print(f"    - Comment Coverage: {summary.semantic_analysis.comment_coverage:.1f}%")
            print(f"    - Naming Quality: {summary.semantic_analysis.naming_quality:.1f}/10")
            print(f"    - Readability Score: {summary.semantic_analysis.readability_score:.1f}/10")
        
        return True
        
    except Exception as e:
        print(f"Error testing NLP analyzer: {e}")
        return False


def test_ml_pipeline():
    """Test complete ML pipeline"""
    print("=" * 60)
    print("Testing Complete ML Pipeline")
    print("=" * 60)
    
    try:
        from tools.ml_pipeline_orchestrator import MLPipelineOrchestrator
        
        orchestrator = MLPipelineOrchestrator()
        
        # Test data
        test_reveng_results = {
            'decompiled_code': '''
            #include <stdio.h>
            #include <string.h>
            
            void process_user_input(char *input) {
                char buffer[100];
                strcpy(buffer, input);  // Potential buffer overflow
                
                char query[500];
                sprintf(query, "SELECT * FROM users WHERE name='%s'", input);  // SQL injection
                
                system(input);  // Command injection
                
                printf("%s", buffer);
            }
            
            void crypto_function() {
                // Weak crypto implementation
                for (int i = 0; i < data_len; i++) {
                    data[i] ^= 0x42;  // Simple XOR
                }
            }
            ''',
            'strings': [
                'http://suspicious-domain.tk',
                'CreateProcess',
                'RegSetValue',
                'bitcoin',
                'encrypt',
                'payload'
            ],
            'api_calls': [
                'CreateProcess',
                'RegSetValue',
                'InternetConnect',
                'WriteProcessMemory',
                'VirtualAlloc',
                'CryptAcquireContext'
            ],
            'code_analysis': {
                'function_count': 15,
                'import_count': 25,
                'section_count': 5,
                'entropy': 8.2,
                'is_packed': True
            }
        }
        
        # Create temporary test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.exe', delete=False) as f:
            f.write("Test binary content for ML pipeline")
            test_file = f.name
        
        try:
            print("Running complete ML pipeline...")
            result = orchestrator.run_ml_pipeline(test_file, test_reveng_results)
            
            print(f"Pipeline Results:")
            print(f"  Success: {result.success}")
            print(f"  Execution Time: {result.execution_time:.2f}s")
            print(f"  Stages Completed: {result.stages_completed}")
            print(f"  Vulnerability Predictions: {len(result.vulnerability_predictions)}")
            print(f"  Malware Classifications: {len(result.malware_classifications)}")
            print(f"  Code Summaries: {len(result.code_summaries)}")
            
            if result.error_messages:
                print(f"  Errors: {result.error_messages}")
            
            # Show some detailed results
            if result.vulnerability_predictions:
                print(f"  Top Vulnerabilities:")
                for vuln in result.vulnerability_predictions[:3]:
                    print(f"    - {vuln.vulnerability_type} (confidence: {vuln.confidence:.2f})")
            
            if result.malware_classifications:
                classification = result.malware_classifications[0]
                print(f"  Malware Classification:")
                print(f"    - Family: {classification.family}")
                print(f"    - Confidence: {classification.confidence:.2f}")
                print(f"    - Is Malware: {classification.is_malware}")
            
            if result.code_summaries:
                summary = result.code_summaries[0]
                print(f"  Code Summary:")
                print(f"    - Algorithms: {summary.algorithms_used}")
                print(f"    - Key Functions: {summary.key_functions[:3]}")
            
            # Test performance report
            performance = orchestrator.get_performance_report()
            print(f"  Performance Report:")
            print(f"    - Execution Times: {performance['execution_times']}")
            print(f"    - Components Initialized: {performance['components_initialized']}")
            
            return True
            
        finally:
            # Clean up temp file
            os.unlink(test_file)
        
    except Exception as e:
        print(f"Error testing ML pipeline: {e}")
        return False


def main():
    """Main test function"""
    print("AI-Enhanced Universal Binary Analysis - ML Enhancements Test")
    print("=" * 80)
    
    tests = [
        ("Vulnerability Predictor", test_vulnerability_predictor),
        ("Malware Classifier", test_malware_classifier),
        ("NLP Code Analyzer", test_nlp_analyzer),
        ("Complete ML Pipeline", test_ml_pipeline)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\nRunning {test_name} test...")
        try:
            success = test_func()
            results[test_name] = success
            print(f"✓ {test_name}: {'PASSED' if success else 'FAILED'}")
        except Exception as e:
            results[test_name] = False
            print(f"✗ {test_name}: FAILED - {e}")
        
        print("-" * 60)
    
    # Summary
    print("\nTest Summary:")
    print("=" * 40)
    passed = sum(1 for success in results.values() if success)
    total = len(results)
    
    for test_name, success in results.items():
        status = "PASSED" if success else "FAILED"
        symbol = "✓" if success else "✗"
        print(f"{symbol} {test_name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All ML enhancement tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())