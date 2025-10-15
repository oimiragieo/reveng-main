#!/usr/bin/env python3
"""
AI Service Server
================

Dedicated Flask service for AI-enhanced analysis capabilities.
Provides REST API endpoints for enhanced analysis modules.
"""

import os
import sys
import json
import logging
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest, InternalServerError
import traceback

# Add tools directory to path
sys.path.append('/app')

# Import analysis modules
try:
    from ai_enhanced_analyzer import AIEnhancedAnalyzer
    from corporate_exposure_detector import CorporateExposureDetector
    from vulnerability_discovery_engine import VulnerabilityDiscoveryEngine
    from threat_intelligence_correlator import ThreatIntelligenceCorrelator
    from demonstration_generator import DemonstrationGenerator
except ImportError as e:
    print(f"Warning: Could not import analysis modules: {e}")
    # Create mock classes for development
    class AIEnhancedAnalyzer:
        def analyze_universal(self, file_path): return {"status": "mock"}
    class CorporateExposureDetector:
        def scan_for_credentials(self, code): return []
    class VulnerabilityDiscoveryEngine:
        def scan_memory_vulnerabilities(self, code): return []
    class ThreatIntelligenceCorrelator:
        def correlate_with_apt_groups(self, indicators): return {}
    class DemonstrationGenerator:
        def create_executive_dashboard(self, analysis): return {}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize analysis components
try:
    enhanced_analyzer = AIEnhancedAnalyzer()
    exposure_detector = CorporateExposureDetector()
    vuln_engine = VulnerabilityDiscoveryEngine()
    threat_correlator = ThreatIntelligenceCorrelator()
    demo_generator = DemonstrationGenerator()
    logger.info("AI analysis components initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize analysis components: {e}")
    # Use mock components
    enhanced_analyzer = AIEnhancedAnalyzer()
    exposure_detector = CorporateExposureDetector()
    vuln_engine = VulnerabilityDiscoveryEngine()
    threat_correlator = ThreatIntelligenceCorrelator()
    demo_generator = DemonstrationGenerator()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for container orchestration."""
    return jsonify({
        'status': 'healthy',
        'service': 'ai-service',
        'version': '1.0.0'
    })

@app.route('/analyze/enhanced', methods=['POST'])
def analyze_enhanced():
    """Enhanced universal analysis endpoint."""
    try:
        data = request.get_json()
        if not data or 'file_path' not in data:
            raise BadRequest("Missing file_path in request")
        
        file_path = data['file_path']
        options = data.get('options', {})
        
        logger.info(f"Starting enhanced analysis for: {file_path}")
        
        # Perform enhanced analysis
        result = enhanced_analyzer.analyze_universal(file_path)
        
        logger.info(f"Enhanced analysis completed for: {file_path}")
        
        return jsonify({
            'status': 'success',
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Enhanced analysis failed: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/analyze/corporate-exposure', methods=['POST'])
def analyze_corporate_exposure():
    """Corporate data exposure analysis endpoint."""
    try:
        data = request.get_json()
        if not data or 'code' not in data:
            raise BadRequest("Missing code in request")
        
        code = data['code']
        scan_type = data.get('scan_type', 'credentials')
        
        logger.info(f"Starting corporate exposure analysis: {scan_type}")
        
        if scan_type == 'credentials':
            result = exposure_detector.scan_for_credentials(code)
        elif scan_type == 'business_logic':
            functions = data.get('functions', [])
            result = exposure_detector.extract_business_logic(functions)
        elif scan_type == 'api_endpoints':
            result = exposure_detector.identify_api_endpoints(code)
        else:
            raise BadRequest(f"Unknown scan type: {scan_type}")
        
        logger.info(f"Corporate exposure analysis completed: {scan_type}")
        
        return jsonify({
            'status': 'success',
            'scan_type': scan_type,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Corporate exposure analysis failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/analyze/vulnerabilities', methods=['POST'])
def analyze_vulnerabilities():
    """Vulnerability discovery analysis endpoint."""
    try:
        data = request.get_json()
        if not data or 'code' not in data:
            raise BadRequest("Missing code in request")
        
        code = data['code']
        vuln_type = data.get('vuln_type', 'memory')
        
        logger.info(f"Starting vulnerability analysis: {vuln_type}")
        
        if vuln_type == 'memory':
            result = vuln_engine.scan_memory_vulnerabilities(code)
        elif vuln_type == 'injection':
            input_handlers = data.get('input_handlers', [])
            result = vuln_engine.detect_injection_points(input_handlers)
        elif vuln_type == 'crypto':
            result = vuln_engine.analyze_crypto_implementation(code)
        elif vuln_type == 'auth':
            result = vuln_engine.assess_auth_mechanisms(code)
        else:
            raise BadRequest(f"Unknown vulnerability type: {vuln_type}")
        
        logger.info(f"Vulnerability analysis completed: {vuln_type}")
        
        return jsonify({
            'status': 'success',
            'vuln_type': vuln_type,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/analyze/threat-intelligence', methods=['POST'])
def analyze_threat_intelligence():
    """Threat intelligence correlation endpoint."""
    try:
        data = request.get_json()
        if not data or 'indicators' not in data:
            raise BadRequest("Missing indicators in request")
        
        indicators = data['indicators']
        analysis_type = data.get('analysis_type', 'apt_correlation')
        
        logger.info(f"Starting threat intelligence analysis: {analysis_type}")
        
        if analysis_type == 'apt_correlation':
            result = threat_correlator.correlate_with_apt_groups(indicators)
        elif analysis_type == 'mitre_mapping':
            behaviors = data.get('behaviors', [])
            result = threat_correlator.map_to_mitre_attack(behaviors)
        elif analysis_type == 'yara_generation':
            patterns = data.get('patterns', [])
            result = threat_correlator.generate_yara_rules(patterns)
        else:
            raise BadRequest(f"Unknown analysis type: {analysis_type}")
        
        logger.info(f"Threat intelligence analysis completed: {analysis_type}")
        
        return jsonify({
            'status': 'success',
            'analysis_type': analysis_type,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Threat intelligence analysis failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/generate/demonstration', methods=['POST'])
def generate_demonstration():
    """Demonstration generation endpoint."""
    try:
        data = request.get_json()
        if not data or 'analysis_result' not in data:
            raise BadRequest("Missing analysis_result in request")
        
        analysis_result = data['analysis_result']
        demo_type = data.get('demo_type', 'executive_dashboard')
        
        logger.info(f"Starting demonstration generation: {demo_type}")
        
        if demo_type == 'executive_dashboard':
            result = demo_generator.create_executive_dashboard(analysis_result)
        elif demo_type == 'reconstruction_demo':
            original = data.get('original')
            reconstructed = data.get('reconstructed')
            result = demo_generator.generate_reconstruction_demo(original, reconstructed)
        elif demo_type == 'vulnerability_showcase':
            vulnerabilities = data.get('vulnerabilities', [])
            result = demo_generator.create_vulnerability_showcase(vulnerabilities)
        elif demo_type == 'training_materials':
            case_studies = data.get('case_studies', [])
            result = demo_generator.build_training_materials(case_studies)
        else:
            raise BadRequest(f"Unknown demonstration type: {demo_type}")
        
        logger.info(f"Demonstration generation completed: {demo_type}")
        
        return jsonify({
            'status': 'success',
            'demo_type': demo_type,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Demonstration generation failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'status': 'error',
        'message': 'Bad request',
        'details': str(error)
    }), 400

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error',
        'details': str(error)
    }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting AI Service on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)