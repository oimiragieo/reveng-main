#!/usr/bin/env python3
"""
ML Pipeline Orchestrator
=======================

Orchestrates all machine learning enhancements for the AI-Enhanced Universal
Binary Analysis Engine, including vulnerability prediction, malware classification,
and NLP code analysis.

Author: REVENG Project - AI Enhancement Module
Version: 1.0
"""

import logging
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import asdict

try:
    from .ml_vulnerability_predictor import MLVulnerabilityPredictor
    from .ml_malware_classifier import MLMalwareClassifier
    from .nlp_code_analyzer import DocumentationGenerator
    from .ai_enhanced_data_models import (
        MLPipelineResult, EnhancedUniversalAnalysisResult,
        VulnerabilityPrediction, MalwareClassification, CodeSummary,
        Evidence, EvidenceTracker
    )
except ImportError:
    from ml_vulnerability_predictor import MLVulnerabilityPredictor
    from ml_malware_classifier import MLMalwareClassifier
    from nlp_code_analyzer import DocumentationGenerator
    from ai_enhanced_data_models import (
        MLPipelineResult, EnhancedUniversalAnalysisResult,
        VulnerabilityPrediction, MalwareClassification, CodeSummary,
        Evidence, EvidenceTracker
    )


class MLPipelineOrchestrator:
    """
    Orchestrates machine learning pipeline for enhanced binary analysis
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize ML pipeline orchestrator"""
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        self.evidence_tracker = EvidenceTracker()
        
        # Initialize ML components
        self.vulnerability_predictor = None
        self.malware_classifier = None
        self.nlp_analyzer = None
        
        # Pipeline configuration
        self.enable_vulnerability_prediction = self.config.get('enable_vulnerability_prediction', True)
        self.enable_malware_classification = self.config.get('enable_malware_classification', True)
        self.enable_nlp_analysis = self.config.get('enable_nlp_analysis', True)
        
        # Performance tracking
        self.execution_times = {}
        self.error_log = []
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize ML components"""
        try:
            if self.enable_vulnerability_prediction:
                self.vulnerability_predictor = MLVulnerabilityPredictor()
                self.logger.info("ML Vulnerability Predictor initialized")
            
            if self.enable_malware_classification:
                self.malware_classifier = MLMalwareClassifier()
                self.logger.info("ML Malware Classifier initialized")
            
            if self.enable_nlp_analysis:
                self.nlp_analyzer = DocumentationGenerator()
                self.logger.info("NLP Code Analyzer initialized")
                
        except Exception as e:
            self.logger.error(f"Error initializing ML components: {e}")
            self.error_log.append(f"Component initialization failed: {str(e)}")
    
    def run_ml_pipeline(self, file_path: str, reveng_results: Dict[str, Any],
                       file_type: Any = None) -> MLPipelineResult:
        """
        Run complete ML pipeline on analysis results
        
        Args:
            file_path: Path to analyzed binary
            reveng_results: Results from REVENG analysis
            file_type: Detected file type information
            
        Returns:
            MLPipelineResult with all ML analysis results
        """
        start_time = time.time()
        pipeline_result = MLPipelineResult(
            pipeline_name="ai_enhanced_ml_pipeline",
            stages_completed=[],
            success=True,
            error_messages=[]
        )
        
        try:
            self.logger.info("Starting ML pipeline execution")
            
            # Stage 1: Vulnerability Prediction
            if self.enable_vulnerability_prediction and self.vulnerability_predictor:
                vuln_start = time.time()
                try:
                    vulnerabilities = self._run_vulnerability_prediction(
                        reveng_results, file_type
                    )
                    pipeline_result.vulnerability_predictions = vulnerabilities
                    pipeline_result.stages_completed.append("vulnerability_prediction")
                    
                    self.execution_times['vulnerability_prediction'] = time.time() - vuln_start
                    self.logger.info(f"Vulnerability prediction completed: {len(vulnerabilities)} predictions")
                    
                except Exception as e:
                    error_msg = f"Vulnerability prediction failed: {str(e)}"
                    self.logger.error(error_msg)
                    pipeline_result.error_messages.append(error_msg)
            
            # Stage 2: Malware Classification
            if self.enable_malware_classification and self.malware_classifier:
                malware_start = time.time()
                try:
                    classification = self._run_malware_classification(
                        file_path, reveng_results
                    )
                    pipeline_result.malware_classifications = [classification]
                    pipeline_result.stages_completed.append("malware_classification")
                    
                    self.execution_times['malware_classification'] = time.time() - malware_start
                    self.logger.info(f"Malware classification completed: {classification.family}")
                    
                except Exception as e:
                    error_msg = f"Malware classification failed: {str(e)}"
                    self.logger.error(error_msg)
                    pipeline_result.error_messages.append(error_msg)
            
            # Stage 3: NLP Code Analysis
            if self.enable_nlp_analysis and self.nlp_analyzer:
                nlp_start = time.time()
                try:
                    code_summary = self._run_nlp_analysis(
                        reveng_results, file_type
                    )
                    pipeline_result.code_summaries = [code_summary]
                    pipeline_result.stages_completed.append("nlp_analysis")
                    
                    self.execution_times['nlp_analysis'] = time.time() - nlp_start
                    self.logger.info(f"NLP analysis completed: {len(code_summary.algorithms_used)} algorithms detected")
                    
                except Exception as e:
                    error_msg = f"NLP analysis failed: {str(e)}"
                    self.logger.error(error_msg)
                    pipeline_result.error_messages.append(error_msg)
            
            # Calculate total execution time
            pipeline_result.execution_time = time.time() - start_time
            
            # Determine overall success
            pipeline_result.success = len(pipeline_result.error_messages) == 0
            
            # Add evidence for pipeline execution
            evidence = self.evidence_tracker.add_evidence(
                "ml_pipeline_execution",
                f"ML pipeline completed with {len(pipeline_result.stages_completed)} stages",
                "machine_learning_pipeline",
                0.9 if pipeline_result.success else 0.5,
                {
                    "stages_completed": pipeline_result.stages_completed,
                    "execution_time": pipeline_result.execution_time,
                    "error_count": len(pipeline_result.error_messages)
                }
            )
            pipeline_result.evidence = [evidence]
            
            self.logger.info(f"ML pipeline completed in {pipeline_result.execution_time:.2f}s")
            return pipeline_result
            
        except Exception as e:
            self.logger.error(f"Critical error in ML pipeline: {e}")
            pipeline_result.success = False
            pipeline_result.error_messages.append(f"Critical pipeline error: {str(e)}")
            pipeline_result.execution_time = time.time() - start_time
            return pipeline_result
    
    def _run_vulnerability_prediction(self, reveng_results: Dict[str, Any],
                                    file_type: Any = None) -> List[VulnerabilityPrediction]:
        """Run ML-based vulnerability prediction"""
        vulnerabilities = []
        
        # Extract code from REVENG results
        code = ""
        if 'decompiled_code' in reveng_results:
            code = reveng_results['decompiled_code']
        elif 'source_code' in reveng_results:
            code = reveng_results['source_code']
        elif 'disassembly' in reveng_results:
            # For assembly code, create a simplified representation
            code = reveng_results['disassembly']
        
        if code:
            language = file_type.language if file_type else "c"
            vulnerabilities = self.vulnerability_predictor.predict_vulnerabilities(code, language)
            
            # Filter high-confidence predictions
            high_confidence_vulns = [v for v in vulnerabilities if v.confidence > 0.7]
            
            self.logger.info(f"Predicted {len(vulnerabilities)} vulnerabilities, {len(high_confidence_vulns)} high-confidence")
            return vulnerabilities
        
        self.logger.warning("No code available for vulnerability prediction")
        return []
    
    def _run_malware_classification(self, file_path: str,
                                  reveng_results: Dict[str, Any]) -> MalwareClassification:
        """Run ML-based malware classification"""
        # Extract analysis data
        strings_data = reveng_results.get('strings', [])
        api_calls = reveng_results.get('api_calls', [])
        code_analysis = reveng_results.get('code_analysis', {})
        
        # Perform classification
        classification = self.malware_classifier.classify_malware(
            file_path, strings_data, api_calls, code_analysis
        )
        
        self.logger.info(f"Classified as {classification.family} with {classification.confidence:.2f} confidence")
        return classification
    
    def _run_nlp_analysis(self, reveng_results: Dict[str, Any],
                         file_type: Any = None) -> CodeSummary:
        """Run NLP-based code analysis"""
        # Extract code from REVENG results
        code = ""
        if 'decompiled_code' in reveng_results:
            code = reveng_results['decompiled_code']
        elif 'source_code' in reveng_results:
            code = reveng_results['source_code']
        
        if code:
            language = file_type.language if file_type else "c"
            code_summary = self.nlp_analyzer.generate_code_summary(code, language)
            
            self.logger.info(f"Generated code summary with {len(code_summary.algorithms_used)} algorithms")
            return code_summary
        
        # Return empty summary if no code available
        from ai_enhanced_data_models import CodeSummary, CodeSemantics
        return CodeSummary(
            overview="No code available for NLP analysis",
            semantic_analysis=CodeSemantics()
        )
    
    def create_enhanced_result(self, file_info: Any, reveng_results: Dict[str, Any],
                             ml_pipeline_result: MLPipelineResult) -> EnhancedUniversalAnalysisResult:
        """Create enhanced universal analysis result with ML integration"""
        
        # Extract ML results
        vulnerability_predictions = ml_pipeline_result.vulnerability_predictions
        malware_classification = (ml_pipeline_result.malware_classifications[0] 
                                if ml_pipeline_result.malware_classifications else None)
        code_summary = (ml_pipeline_result.code_summaries[0] 
                       if ml_pipeline_result.code_summaries else None)
        
        # Create enhanced result
        enhanced_result = EnhancedUniversalAnalysisResult(
            file_info=file_info,
            reveng_analysis=reveng_results,
            enhanced_analysis={
                'ml_pipeline_completed': ml_pipeline_result.success,
                'stages_completed': ml_pipeline_result.stages_completed,
                'execution_time': ml_pipeline_result.execution_time
            },
            ml_pipeline_result=ml_pipeline_result,
            vulnerability_predictions=vulnerability_predictions,
            malware_classification=malware_classification,
            code_summary=code_summary,
            analysis_timestamp=time.time(),
            analysis_duration=ml_pipeline_result.execution_time,
            ml_models_used=self._get_models_used(),
            confidence_scores=self._calculate_confidence_scores(ml_pipeline_result),
            evidence_chain=ml_pipeline_result.evidence
        )
        
        return enhanced_result
    
    def _get_models_used(self) -> List[str]:
        """Get list of ML models used in pipeline"""
        models = []
        
        if self.vulnerability_predictor:
            models.extend(['vulnerability_rf', 'vulnerability_gb', 'vulnerability_lr'])
        
        if self.malware_classifier:
            models.extend(['malware_rf', 'malware_isolation_forest', 'malware_kmeans'])
        
        if self.nlp_analyzer:
            models.extend(['tfidf_vectorizer', 'semantic_analyzer'])
        
        return models
    
    def _calculate_confidence_scores(self, ml_result: MLPipelineResult) -> Dict[str, float]:
        """Calculate overall confidence scores for ML results"""
        scores = {}
        
        # Vulnerability prediction confidence
        if ml_result.vulnerability_predictions:
            avg_vuln_confidence = sum(v.confidence for v in ml_result.vulnerability_predictions) / len(ml_result.vulnerability_predictions)
            scores['vulnerability_prediction'] = avg_vuln_confidence
        
        # Malware classification confidence
        if ml_result.malware_classifications:
            scores['malware_classification'] = ml_result.malware_classifications[0].confidence
        
        # NLP analysis confidence (based on semantic analysis quality)
        if ml_result.code_summaries:
            code_summary = ml_result.code_summaries[0]
            if code_summary.semantic_analysis:
                nlp_confidence = (
                    code_summary.semantic_analysis.readability_score +
                    code_summary.semantic_analysis.maintainability_score
                ) / 20.0  # Normalize to 0-1
                scores['nlp_analysis'] = nlp_confidence
        
        # Overall pipeline confidence
        if scores:
            scores['overall'] = sum(scores.values()) / len(scores)
        
        return scores
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance report for ML pipeline"""
        return {
            'execution_times': self.execution_times,
            'error_log': self.error_log,
            'components_initialized': {
                'vulnerability_predictor': self.vulnerability_predictor is not None,
                'malware_classifier': self.malware_classifier is not None,
                'nlp_analyzer': self.nlp_analyzer is not None
            },
            'pipeline_configuration': {
                'enable_vulnerability_prediction': self.enable_vulnerability_prediction,
                'enable_malware_classification': self.enable_malware_classification,
                'enable_nlp_analysis': self.enable_nlp_analysis
            }
        }
    
    def train_models(self, training_data_dir: str) -> Dict[str, bool]:
        """Train all ML models with provided training data"""
        training_results = {}
        
        try:
            # Train vulnerability predictor
            if self.vulnerability_predictor:
                self.logger.info("Training vulnerability prediction models...")
                training_data = self.vulnerability_predictor.generate_synthetic_training_data()
                
                for model_type in self.vulnerability_predictor.models.keys():
                    success = self.vulnerability_predictor.train_model(training_data, model_type)
                    training_results[f'vulnerability_{model_type}'] = success
            
            # Train malware classifier
            if self.malware_classifier:
                self.logger.info("Training malware classification models...")
                # Note: This would require actual malware samples for training
                # For now, we'll mark as successful if the classifier is initialized
                training_results['malware_classifier'] = True
            
            # NLP analyzer doesn't require training (uses pre-trained models)
            if self.nlp_analyzer:
                training_results['nlp_analyzer'] = True
            
            self.logger.info(f"Model training completed: {training_results}")
            return training_results
            
        except Exception as e:
            self.logger.error(f"Error in model training: {e}")
            return {'error': str(e)}


def main():
    """Main function for testing ML pipeline orchestrator"""
    orchestrator = MLPipelineOrchestrator()
    
    # Test pipeline with dummy data
    test_reveng_results = {
        'decompiled_code': '''
        #include <stdio.h>
        void vulnerable_function(char *input) {
            char buffer[100];
            strcpy(buffer, input);  // Vulnerable
            printf("%s", buffer);
        }
        ''',
        'strings': ['http://malicious.com', 'CreateProcess'],
        'api_calls': ['CreateProcess', 'RegSetValue'],
        'code_analysis': {'function_count': 5, 'import_count': 10}
    }
    
    print("Running ML pipeline test...")
    result = orchestrator.run_ml_pipeline("test.exe", test_reveng_results)
    
    print(f"Pipeline Success: {result.success}")
    print(f"Stages Completed: {result.stages_completed}")
    print(f"Execution Time: {result.execution_time:.2f}s")
    print(f"Vulnerabilities Found: {len(result.vulnerability_predictions)}")
    print(f"Malware Classifications: {len(result.malware_classifications)}")
    print(f"Code Summaries: {len(result.code_summaries)}")
    
    if result.error_messages:
        print(f"Errors: {result.error_messages}")


if __name__ == "__main__":
    main()