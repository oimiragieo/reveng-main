#!/usr/bin/env python3
"""
AI-Enhanced Universal Binary Analysis Engine
===========================================

Extends REVENG's existing capabilities to create a comprehensive platform that demonstrates
how modern AI-powered reverse engineering has fundamentally changed the security landscape.

This orchestrator coordinates enhanced analysis modules while maintaining compatibility
with the existing REVENG pipeline.

Author: REVENG Project - AI Enhancement Module
Version: 1.0
"""

import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

# Import existing REVENG components
try:
    from tools.config_manager import ConfigManager, get_config
    from tools.language_detector import LanguageDetector
except ImportError as e:
    logging.warning(f"REVENG components not available: {e}")

logger = logging.getLogger(__name__)


@dataclass
class EnhancedAnalysisConfig:
    """Configuration for enhanced analysis modules"""
    enable_corporate_exposure: bool = True
    enable_vulnerability_discovery: bool = True
    enable_threat_intelligence: bool = True
    enable_binary_reconstruction: bool = True
    enable_demonstration_generation: bool = True
    
    # AI service configurations
    ai_provider: str = "ollama"
    ai_model: str = "auto"
    ai_timeout: int = 300
    
    # Analysis depth settings
    max_functions_to_analyze: int = 100
    confidence_threshold: float = 0.7
    
    # Output settings
    generate_executive_reports: bool = True
    generate_technical_reports: bool = True
    export_formats: List[str] = None
    
    def __post_init__(self):
        if self.export_formats is None:
            self.export_formats = ["json", "xml", "pdf"]


class AIEnhancedAnalyzer:
    """
    AI-Enhanced Universal Binary Analysis Engine
    
    Orchestrates enhanced analysis workflow while maintaining compatibility
    with existing REVENG pipeline.
    """
    
    def __init__(self, binary_path: str = None, config: EnhancedAnalysisConfig = None):
        """
        Initialize the AI-Enhanced Analyzer
        
        Args:
            binary_path: Path to binary to analyze
            config: Enhanced analysis configuration
        """
        self.binary_path = binary_path
        self.config = config or EnhancedAnalysisConfig()
        self.binary_name = Path(binary_path).stem if binary_path else "unknown"
        self.analysis_folder = Path(f"ai_enhanced_analysis_{self.binary_name}")
        
        # Analysis results storage
        self.reveng_results = {}
        self.enhanced_results = {}
        self.universal_analysis_result = None
        self.ml_pipeline_result = None
        
        # Initialize components
        self.language_detector = None
        self.file_type = None
        self.reveng_config = None
        
        # Create analysis folder
        self.analysis_folder.mkdir(exist_ok=True)
        
        # Initialize logging
        self._setup_logging()
        
        # Load REVENG configuration
        self._load_reveng_config()
        
        # Detect file type
        self._detect_file_type()
        
        logger.info("AI-Enhanced Analyzer initialized")
        logger.info(f"Target binary: {self.binary_path}")
        logger.info(f"Analysis folder: {self.analysis_folder}")
    
    def _setup_logging(self):
        """Setup enhanced logging for analysis"""
        log_file = self.analysis_folder / "ai_enhanced_analysis.log"
        
        # Create file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
        
        logger.info("Enhanced analysis logging initialized")
    
    def _load_reveng_config(self):
        """Load existing REVENG configuration"""
        try:
            self.reveng_config = get_config()
            logger.info("REVENG configuration loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load REVENG configuration: {e}")
            self.reveng_config = None
    
    def _detect_file_type(self):
        """Detect file type using enhanced language detector"""
        if not self.binary_path or not Path(self.binary_path).exists():
            logger.warning("Binary path not found, skipping file type detection")
            return
        
        try:
            self.language_detector = LanguageDetector()
            self.file_type = self.language_detector.detect(self.binary_path)
            
            logger.info(f"Detected file type: {self.file_type.language}/{self.file_type.format}")
            logger.info(f"Detection confidence: {self.file_type.confidence:.2%}")
            
        except Exception as e:
            logger.warning(f"Error detecting file type: {e}")
            self.file_type = None
    
    def analyze_universal(self, file_path: str = None) -> 'UniversalAnalysisResult':
        """
        Run comprehensive universal binary analysis
        
        Args:
            file_path: Optional override for binary path
            
        Returns:
            UniversalAnalysisResult containing all analysis findings
        """
        if file_path:
            self.binary_path = file_path
            self.binary_name = Path(file_path).stem
            self._detect_file_type()
        
        logger.info("Starting AI-Enhanced Universal Binary Analysis")
        
        print("=" * 80)
        print(" AI-ENHANCED UNIVERSAL BINARY ANALYSIS ENGINE")
        print(" Demonstrating Modern AI-Powered Reverse Engineering")
        print("=" * 80)
        print(f"Target: {self.binary_path}")
        print(f"File Type: {self.file_type.language if self.file_type else 'Unknown'}")
        print(f"Enhanced Analysis: [ENABLED]")
        print()
        
        try:
            # Step 1: Run existing REVENG pipeline (steps 1-7)
            print("[FOUNDATION] Running REVENG Core Analysis Pipeline...")
            self._run_reveng_pipeline()
            
            # Step 2: Enhanced analysis modules (steps 8-12)
            if self.config.enable_corporate_exposure:
                print("[EXPOSURE] Corporate Data Exposure Analysis...")
                self._analyze_corporate_exposure()
            
            if self.config.enable_vulnerability_discovery:
                print("[VULNERABILITY] Automated Vulnerability Discovery...")
                self._discover_vulnerabilities()
            
            if self.config.enable_threat_intelligence:
                print("[INTELLIGENCE] Threat Intelligence Correlation...")
                self._correlate_threat_intelligence()
            
            if self.config.enable_binary_reconstruction:
                print("[RECONSTRUCTION] Enhanced Binary Reconstruction...")
                self._enhance_binary_reconstruction()
            
            if self.config.enable_demonstration_generation:
                print("[DEMONSTRATION] Security Demonstration Generation...")
                self._generate_demonstrations()
            
            # Step 2.5: Run ML Pipeline (Advanced AI Enhancement)
            print("[ML-PIPELINE] Running Advanced ML Analysis Pipeline...")
            self._run_ml_pipeline()
            
            # Step 3: Synthesize results
            print("[SYNTHESIS] Synthesizing Universal Analysis Results...")
            self._synthesize_results()
            
            # Step 4: Generate reports
            print("[REPORTING] Generating Comprehensive Reports...")
            self._generate_reports()
            
            print("\n" + "=" * 80)
            print(" AI-ENHANCED ANALYSIS COMPLETED SUCCESSFULLY")
            print("=" * 80)
            print(f" Analysis folder: {self.analysis_folder}")
            print(f" Enhanced modules: {self._count_enabled_modules()}")
            print(f" Total findings: {self._count_total_findings()}")
            print("=" * 80)
            
            return self.universal_analysis_result
            
        except Exception as e:
            logger.error(f"Error in AI-Enhanced analysis: {e}")
            print(f"[ERROR] Enhanced analysis failed: {e}")
            raise
    
    def _run_reveng_pipeline(self):
        """Run existing REVENG pipeline (steps 1-7)"""
        logger.info("Running REVENG core pipeline")
        
        try:
            # Import and run existing REVENG analyzer
            from reveng_analyzer import REVENGAnalyzer
            
            # Create REVENG analyzer instance
            reveng_analyzer = REVENGAnalyzer(self.binary_path, check_ollama=False)
            
            # Run analysis
            success = reveng_analyzer.analyze_binary()
            
            # Store results
            self.reveng_results = reveng_analyzer.results
            
            logger.info(f"REVENG pipeline completed: {'success' if success else 'with errors'}")
            
        except Exception as e:
            logger.error(f"Error running REVENG pipeline: {e}")
            # Continue with enhanced analysis even if REVENG fails
            self.reveng_results = {"error": str(e)}
    
    def _analyze_corporate_exposure(self):
        """Analyze corporate data exposure (placeholder)"""
        logger.info("Analyzing corporate data exposure")
        
        # Placeholder for corporate exposure analysis
        # This will be implemented in task 2.1
        self.enhanced_results['corporate_exposure'] = {
            'status': 'placeholder',
            'message': 'Corporate exposure analysis will be implemented in task 2.1'
        }
    
    def _discover_vulnerabilities(self):
        """Discover vulnerabilities automatically with ML enhancement"""
        logger.info("Discovering vulnerabilities with ML enhancement")
        
        try:
            # Import ML vulnerability predictor
            from tools.ml_vulnerability_predictor import MLVulnerabilityPredictor
            
            # Initialize ML predictor
            ml_predictor = MLVulnerabilityPredictor()
            
            # Get code from REVENG analysis
            code = ""
            if 'decompiled_code' in self.reveng_results:
                code = self.reveng_results['decompiled_code']
            elif 'source_code' in self.reveng_results:
                code = self.reveng_results['source_code']
            
            # Predict vulnerabilities using ML
            if code:
                language = self.file_type.language if self.file_type else "c"
                ml_predictions = ml_predictor.predict_vulnerabilities(code, language)
                
                self.enhanced_results['vulnerability_discovery'] = {
                    'status': 'completed',
                    'ml_predictions': [pred.__dict__ for pred in ml_predictions],
                    'prediction_count': len(ml_predictions),
                    'high_confidence_count': len([p for p in ml_predictions if p.confidence > 0.8])
                }
                
                logger.info(f"ML vulnerability prediction completed: {len(ml_predictions)} predictions")
            else:
                self.enhanced_results['vulnerability_discovery'] = {
                    'status': 'no_code',
                    'message': 'No decompiled code available for ML analysis'
                }
                
        except Exception as e:
            logger.error(f"Error in ML vulnerability discovery: {e}")
            self.enhanced_results['vulnerability_discovery'] = {
                'status': 'error',
                'message': f'ML vulnerability discovery failed: {str(e)}'
            }
    
    def _correlate_threat_intelligence(self):
        """Correlate with threat intelligence with ML enhancement"""
        logger.info("Correlating threat intelligence with ML enhancement")
        
        try:
            # Import ML malware classifier
            from tools.ml_malware_classifier import MLMalwareClassifier
            
            # Initialize ML classifier
            ml_classifier = MLMalwareClassifier()
            
            # Get analysis data
            strings_data = self.reveng_results.get('strings', [])
            api_calls = self.reveng_results.get('api_calls', [])
            code_analysis = self.reveng_results.get('code_analysis', {})
            
            # Classify malware using ML
            if self.binary_path:
                ml_classification = ml_classifier.classify_malware(
                    self.binary_path, strings_data, api_calls, code_analysis
                )
                
                self.enhanced_results['threat_intelligence'] = {
                    'status': 'completed',
                    'ml_classification': ml_classification.__dict__,
                    'family': ml_classification.family,
                    'confidence': ml_classification.confidence,
                    'is_malware': ml_classification.is_malware,
                    'behavioral_patterns': len(ml_classification.behavioral_patterns),
                    'anomaly_score': ml_classification.anomaly_score
                }
                
                logger.info(f"ML malware classification completed: {ml_classification.family} ({ml_classification.confidence:.2f})")
            else:
                self.enhanced_results['threat_intelligence'] = {
                    'status': 'no_file',
                    'message': 'No binary file available for ML classification'
                }
                
        except Exception as e:
            logger.error(f"Error in ML threat intelligence correlation: {e}")
            self.enhanced_results['threat_intelligence'] = {
                'status': 'error',
                'message': f'ML threat intelligence correlation failed: {str(e)}'
            }
    
    def _enhance_binary_reconstruction(self):
        """Enhance binary reconstruction (placeholder)"""
        logger.info("Enhancing binary reconstruction")
        
        # Placeholder for enhanced binary reconstruction
        # This will be implemented in task 5.1
        self.enhanced_results['binary_reconstruction'] = {
            'status': 'placeholder',
            'message': 'Enhanced binary reconstruction will be implemented in task 5.1'
        }
    
    def _generate_demonstrations(self):
        """Generate security demonstrations with NLP enhancement"""
        logger.info("Generating security demonstrations with NLP enhancement")
        
        try:
            # Import NLP code analyzer
            from tools.nlp_code_analyzer import DocumentationGenerator
            
            # Initialize NLP analyzer
            nlp_analyzer = DocumentationGenerator()
            
            # Get code from REVENG analysis
            code = ""
            if 'decompiled_code' in self.reveng_results:
                code = self.reveng_results['decompiled_code']
            elif 'source_code' in self.reveng_results:
                code = self.reveng_results['source_code']
            
            # Generate code summary using NLP
            if code:
                language = self.file_type.language if self.file_type else "c"
                code_summary = nlp_analyzer.generate_code_summary(code, language)
                
                self.enhanced_results['demonstrations'] = {
                    'status': 'completed',
                    'code_summary': code_summary.__dict__,
                    'overview': code_summary.overview,
                    'algorithms_detected': code_summary.algorithms_used,
                    'design_patterns': code_summary.design_patterns,
                    'documentation_suggestions': len(code_summary.documentation_suggestions),
                    'complexity_score': code_summary.complexity_analysis.get('complexity_score', 0)
                }
                
                logger.info(f"NLP code analysis completed: {len(code_summary.algorithms_used)} algorithms detected")
            else:
                self.enhanced_results['demonstrations'] = {
                    'status': 'no_code',
                    'message': 'No decompiled code available for NLP analysis'
                }
                
        except Exception as e:
            logger.error(f"Error in NLP demonstration generation: {e}")
            self.enhanced_results['demonstrations'] = {
                'status': 'error',
                'message': f'NLP demonstration generation failed: {str(e)}'
            }
    
    def _synthesize_results(self):
        """Synthesize all analysis results into unified format"""
        logger.info("Synthesizing universal analysis results")
        
        # Create universal analysis result
        from tools.ai_enhanced_data_models import EnhancedUniversalAnalysisResult, FileInfo
        
        file_info = FileInfo(
            path=self.binary_path,
            name=self.binary_name,
            size=Path(self.binary_path).stat().st_size if Path(self.binary_path).exists() else 0,
            file_type=self.file_type.language if self.file_type else "unknown",
            format_type=self.file_type.format if self.file_type else "unknown",
            detection_confidence=self.file_type.confidence if self.file_type else 0.0
        )
        
        # Create enhanced result with ML integration
        if hasattr(self, 'ml_pipeline_result') and self.ml_pipeline_result:
            from tools.ml_pipeline_orchestrator import MLPipelineOrchestrator
            orchestrator = MLPipelineOrchestrator()
            
            self.universal_analysis_result = orchestrator.create_enhanced_result(
                file_info, self.reveng_results, self.ml_pipeline_result
            )
        else:
            # Fallback to basic enhanced result
            self.universal_analysis_result = EnhancedUniversalAnalysisResult(
                file_info=file_info,
                reveng_analysis=self.reveng_results,
                enhanced_analysis=self.enhanced_results,
                analysis_timestamp=time.time(),
                analysis_duration=0.0,
                confidence_scores={},
                evidence_chain=[]
            )
        
        logger.info("Enhanced universal analysis results synthesized")
    
    def _run_ml_pipeline(self):
        """Run advanced ML analysis pipeline"""
        logger.info("Running ML pipeline")
        
        try:
            # Import ML pipeline orchestrator
            from tools.ml_pipeline_orchestrator import MLPipelineOrchestrator
            
            # Initialize ML orchestrator
            ml_config = {
                'enable_vulnerability_prediction': True,
                'enable_malware_classification': True,
                'enable_nlp_analysis': True
            }
            ml_orchestrator = MLPipelineOrchestrator(ml_config)
            
            # Run ML pipeline
            ml_result = ml_orchestrator.run_ml_pipeline(
                self.binary_path, self.reveng_results, self.file_type
            )
            
            # Store ML results
            self.enhanced_results['ml_pipeline'] = {
                'status': 'completed' if ml_result.success else 'partial',
                'stages_completed': ml_result.stages_completed,
                'execution_time': ml_result.execution_time,
                'vulnerability_predictions': len(ml_result.vulnerability_predictions),
                'malware_classifications': len(ml_result.malware_classifications),
                'code_summaries': len(ml_result.code_summaries),
                'error_count': len(ml_result.error_messages)
            }
            
            # Store detailed ML results for synthesis
            self.ml_pipeline_result = ml_result
            
            logger.info(f"ML pipeline completed: {len(ml_result.stages_completed)} stages")
            
        except Exception as e:
            logger.error(f"Error in ML pipeline: {e}")
            self.enhanced_results['ml_pipeline'] = {
                'status': 'error',
                'message': f'ML pipeline failed: {str(e)}'
            }
            self.ml_pipeline_result = None
    
    def _generate_reports(self):
        """Generate comprehensive reports"""
        logger.info("Generating comprehensive reports")
        
        # Save universal analysis result
        result_file = self.analysis_folder / "universal_analysis_result.json"
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(self.universal_analysis_result), f, indent=2, default=str)
        
        # Save ML pipeline results if available
        if hasattr(self, 'ml_pipeline_result') and self.ml_pipeline_result:
            ml_result_file = self.analysis_folder / "ml_pipeline_result.json"
            with open(ml_result_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.ml_pipeline_result), f, indent=2, default=str)
            logger.info(f"ML pipeline result saved to {ml_result_file}")
        
        logger.info(f"Universal analysis result saved to {result_file}")
    
    def _count_enabled_modules(self) -> int:
        """Count enabled enhanced analysis modules"""
        enabled = 0
        if self.config.enable_corporate_exposure:
            enabled += 1
        if self.config.enable_vulnerability_discovery:
            enabled += 1
        if self.config.enable_threat_intelligence:
            enabled += 1
        if self.config.enable_binary_reconstruction:
            enabled += 1
        if self.config.enable_demonstration_generation:
            enabled += 1
        return enabled
    
    def _count_total_findings(self) -> int:
        """Count total findings across all modules"""
        # Placeholder - will be implemented as modules are added
        return len(self.enhanced_results)
    
    def generate_executive_report(self) -> 'ExecutiveReport':
        """
        Generate executive-level report for CISOs and security leadership
        
        Returns:
            ExecutiveReport with business impact and risk assessment
        """
        logger.info("Generating executive report")
        
        # Placeholder for executive report generation
        # This will be implemented in task 6.1
        from tools.ai_enhanced_data_models import ExecutiveReport
        
        return ExecutiveReport(
            executive_summary="Executive report generation will be implemented in task 6.1",
            risk_level="UNKNOWN",
            business_impact="TBD",
            recommendations=[]
        )
    
    def create_demonstration(self) -> 'DemonstrationPackage':
        """
        Create compelling security demonstration package
        
        Returns:
            DemonstrationPackage for presentations and training
        """
        logger.info("Creating demonstration package")
        
        # Placeholder for demonstration package creation
        # This will be implemented in task 7.1
        from tools.ai_enhanced_data_models import DemonstrationPackage
        
        return DemonstrationPackage(
            title=f"Security Analysis Demonstration: {self.binary_name}",
            description="Demonstration package creation will be implemented in task 7.1",
            components=[]
        )
    
    def assess_corporate_risk(self) -> 'CorporateRiskAssessment':
        """
        Assess corporate data exposure and business risks
        
        Returns:
            CorporateRiskAssessment with detailed risk analysis
        """
        logger.info("Assessing corporate risk")
        
        # Placeholder for corporate risk assessment
        # This will be implemented in task 2.1
        from tools.ai_enhanced_data_models import CorporateRiskAssessment
        
        return CorporateRiskAssessment(
            risk_score=0.0,
            exposure_categories=[],
            business_impact="Corporate risk assessment will be implemented in task 2.1",
            remediation_priority=[]
        )
    
    def discover_vulnerabilities(self) -> 'VulnerabilityReport':
        """
        Discover security vulnerabilities automatically
        
        Returns:
            VulnerabilityReport with detailed vulnerability analysis
        """
        logger.info("Discovering vulnerabilities")
        
        # Placeholder for vulnerability discovery
        # This will be implemented in task 3.1
        from tools.ai_enhanced_data_models import VulnerabilityReport
        
        return VulnerabilityReport(
            total_vulnerabilities=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            vulnerabilities=[],
            summary="Vulnerability discovery will be implemented in task 3.1"
        )


def main():
    """Main function for AI-Enhanced Analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='AI-Enhanced Universal Binary Analysis Engine'
    )
    parser.add_argument('binary_path', nargs='?', help='Path to binary file')
    parser.add_argument('--config', help='Path to enhanced analysis config file')
    parser.add_argument('--no-corporate', action='store_true', 
                       help='Disable corporate exposure analysis')
    parser.add_argument('--no-vuln', action='store_true',
                       help='Disable vulnerability discovery')
    parser.add_argument('--no-threat', action='store_true',
                       help='Disable threat intelligence')
    parser.add_argument('--no-reconstruction', action='store_true',
                       help='Disable binary reconstruction')
    parser.add_argument('--no-demo', action='store_true',
                       help='Disable demonstration generation')
    
    args = parser.parse_args()
    
    if not args.binary_path:
        print("Error: Binary path required")
        print("Usage: python ai_enhanced_analyzer.py <binary_path>")
        sys.exit(1)
    
    if not Path(args.binary_path).exists():
        print(f"Error: Binary not found: {args.binary_path}")
        sys.exit(1)
    
    # Create configuration
    config = EnhancedAnalysisConfig()
    if args.no_corporate:
        config.enable_corporate_exposure = False
    if args.no_vuln:
        config.enable_vulnerability_discovery = False
    if args.no_threat:
        config.enable_threat_intelligence = False
    if args.no_reconstruction:
        config.enable_binary_reconstruction = False
    if args.no_demo:
        config.enable_demonstration_generation = False
    
    # Create and run analyzer
    analyzer = AIEnhancedAnalyzer(args.binary_path, config)
    
    try:
        result = analyzer.analyze_universal()
        print(f"\n[SUCCESS] AI-Enhanced analysis completed!")
        print(f"Results saved to: {analyzer.analysis_folder}")
        
    except Exception as e:
        print(f"\n[ERROR] AI-Enhanced analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()