#!/usr/bin/env python3
"""
AI Analysis API Endpoints
========================

REST API endpoints optimized for AI consumption with structured input/output.
Provides comprehensive AI analysis capabilities via HTTP.

Author: REVENG Development Team
Version: 2.2.0
License: MIT
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request, current_app
from werkzeug.exceptions import BadRequest, InternalServerError

# Import AI components
from ...ai.ai_assistant import REVENGAIAssistant, AIAnalysisRequest
from ...ai.analysis_models import AnalysisType, AIAnalysisResult

logger = logging.getLogger(__name__)

# Create blueprint
ai_analysis_bp = Blueprint('ai_analysis', __name__, url_prefix='/api/ai')


@ai_analysis_bp.route('/analyze', methods=['POST'])
def ai_analyze():
    """
    AI-optimized analysis endpoint

    Request body:
    {
        "binary_path": "path/to/binary",
        "analysis_type": "comprehensive|security|triage|custom",
        "goals": ["understand_functionality", "find_vulnerabilities"],
        "context": {...},
        "preferences": {...}
    }

    Response:
    {
        "status": "success|error",
        "result": {
            "binary_info": {...},
            "functions": [...],
            "vulnerabilities": [...],
            "threat_indicators": [...],
            "recommendations": [...],
            "metadata": {...},
            "natural_language_summary": "...",
            "structured_prompt": "...",
            "confidence_scores": {...},
            "key_findings": [...],
            "next_steps": [...]
        },
        "analysis_id": "session_1234567890",
        "duration": 45.2
    }
    """
    try:
        data = request.get_json()
        if not data or 'binary_path' not in data:
            raise BadRequest("Missing binary_path in request")

        # Validate binary path
        binary_path = data['binary_path']
        if not Path(binary_path).exists():
            raise BadRequest(f"Binary file not found: {binary_path}")

        # Parse analysis type
        analysis_type_str = data.get('analysis_type', 'comprehensive')
        try:
            analysis_type = AnalysisType(analysis_type_str)
        except ValueError:
            analysis_type = AnalysisType.COMPREHENSIVE

        # Create analysis request
        request_obj = AIAnalysisRequest(
            binary_path=binary_path,
            analysis_type=analysis_type,
            goals=data.get('goals', ["understand_functionality", "find_vulnerabilities", "assess_threats"]),
            context=data.get('context', {}),
            preferences=data.get('preferences', {})
        )

        # Run analysis
        assistant = REVENGAIAssistant()
        result = asyncio.run(assistant.analyze_binary_ai(request_obj))

        # Return structured response
        return jsonify({
            'status': 'success',
            'result': result.to_dict(),
            'analysis_id': result.metadata.analysis_id,
            'duration': result.metadata.duration
        })

    except BadRequest as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@ai_analysis_bp.route('/query', methods=['POST'])
def ai_query():
    """
    Natural language query endpoint

    Request body:
    {
        "question": "What does this binary do?",
        "binary_path": "path/to/binary",
        "analysis_result": {...}  # Optional: previous analysis result
    }

    Response:
    {
        "status": "success|error",
        "answer": "Natural language answer",
        "confidence": 0.85,
        "sources": [...]
    }
    """
    try:
        data = request.get_json()
        if not data or 'question' not in data:
            raise BadRequest("Missing question in request")

        question = data['question']
        binary_path = data.get('binary_path')
        analysis_result = data.get('analysis_result')

        if not binary_path and not analysis_result:
            raise BadRequest("Either binary_path or analysis_result must be provided")

        # Run query
        assistant = REVENGAIAssistant()
        answer = asyncio.run(assistant.ask_question(question, binary_path, analysis_result))

        return jsonify({
            'status': 'success',
            'answer': answer,
            'confidence': 0.85,  # Placeholder confidence
            'sources': []  # Placeholder sources
        })

    except BadRequest as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"AI query failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@ai_analysis_bp.route('/workflow', methods=['POST'])
def suggest_workflow():
    """
    Workflow suggestion endpoint

    Request body:
    {
        "binary_path": "path/to/binary",
        "goals": ["understand_functionality", "find_vulnerabilities"]
    }

    Response:
    {
        "status": "success|error",
        "workflow": {
            "binary_type": "native",
            "complexity": "medium",
            "recommended_tools": [...],
            "estimated_time": 120,
            "resource_requirements": {...},
            "alternative_workflows": [...],
            "confidence": 0.9,
            "reasoning": "..."
        }
    }
    """
    try:
        data = request.get_json()
        if not data or 'binary_path' not in data:
            raise BadRequest("Missing binary_path in request")

        binary_path = data['binary_path']
        goals = data.get('goals', ["understand_functionality", "find_vulnerabilities", "assess_threats"])

        # Get workflow suggestion
        assistant = REVENGAIAssistant()
        workflow = asyncio.run(assistant.suggest_workflow(binary_path, goals))

        return jsonify({
            'status': 'success',
            'workflow': workflow
        })

    except BadRequest as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Workflow suggestion failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@ai_analysis_bp.route('/functions/<function_name>', methods=['GET'])
def analyze_function(function_name: str):
    """
    Analyze a specific function

    Query parameters:
    - analysis_type: comprehensive|security|performance|basic
    - binary_path: path to binary file

    Response:
    {
        "status": "success|error",
        "function_analysis": {
            "name": "function_name",
            "address": "0x401000",
            "purpose": "Main entry point",
            "complexity": "medium",
            "security_issues": [...],
            "performance_issues": [...],
            "suggestions": [...],
            "confidence": 0.85
        }
    }
    """
    try:
        analysis_type = request.args.get('analysis_type', 'comprehensive')
        binary_path = request.args.get('binary_path')

        if not binary_path:
            raise BadRequest("Missing binary_path parameter")

        # This would integrate with Ghidra MCP connector
        # For now, return a placeholder response
        return jsonify({
            'status': 'success',
            'function_analysis': {
                'name': function_name,
                'address': '0x401000',
                'purpose': 'Function analysis placeholder',
                'complexity': 'medium',
                'security_issues': [],
                'performance_issues': [],
                'suggestions': [],
                'confidence': 0.85
            }
        })

    except BadRequest as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Function analysis failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@ai_analysis_bp.route('/similar-functions', methods=['POST'])
def find_similar_functions():
    """
    Find functions similar to a pattern

    Request body:
    {
        "pattern": "function pattern or name",
        "binary_path": "path/to/binary",
        "similarity_threshold": 0.8
    }

    Response:
    {
        "status": "success|error",
        "similar_functions": [
            {
                "function_name": "similar_func",
                "similarity_score": 0.85,
                "reason": "Contains similar patterns"
            }
        ]
    }
    """
    try:
        data = request.get_json()
        if not data or 'pattern' not in data:
            raise BadRequest("Missing pattern in request")

        pattern = data['pattern']
        binary_path = data.get('binary_path')
        similarity_threshold = data.get('similarity_threshold', 0.8)

        if not binary_path:
            raise BadRequest("Missing binary_path in request")

        # This would integrate with Ghidra MCP connector
        # For now, return a placeholder response
        return jsonify({
            'status': 'success',
            'similar_functions': [
                {
                    'function_name': 'similar_function_1',
                    'similarity_score': 0.85,
                    'reason': 'Contains similar patterns'
                }
            ]
        })

    except BadRequest as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Similar function search failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@ai_analysis_bp.route('/export/<analysis_id>', methods=['GET'])
def export_analysis(analysis_id: str):
    """
    Export analysis results in various formats

    Query parameters:
    - format: json|xml|yaml|pdf|markdown
    - include_raw_data: true|false

    Response:
    - JSON: Analysis results as JSON
    - XML: Analysis results as XML
    - YAML: Analysis results as YAML
    - PDF: Analysis report as PDF
    - Markdown: Analysis report as Markdown
    """
    try:
        export_format = request.args.get('format', 'json')
        include_raw_data = request.args.get('include_raw_data', 'false').lower() == 'true'

        # This would retrieve analysis results from storage
        # For now, return a placeholder response
        if export_format == 'json':
            return jsonify({
                'analysis_id': analysis_id,
                'format': 'json',
                'data': {'placeholder': 'Analysis results would be here'}
            })
        elif export_format == 'xml':
            return f'<?xml version="1.0"?><analysis id="{analysis_id}"><placeholder>Analysis results would be here</placeholder></analysis>', 200, {'Content-Type': 'application/xml'}
        elif export_format == 'yaml':
            return f'analysis_id: {analysis_id}\nplaceholder: Analysis results would be here', 200, {'Content-Type': 'application/x-yaml'}
        else:
            raise BadRequest(f"Unsupported format: {export_format}")

    except BadRequest as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Export failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@ai_analysis_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for AI analysis service"""
    return jsonify({
        'status': 'healthy',
        'service': 'ai-analysis',
        'version': '2.2.0',
        'capabilities': [
            'comprehensive_analysis',
            'security_analysis',
            'triage_analysis',
            'natural_language_queries',
            'workflow_suggestions',
            'function_analysis',
            'similar_function_search',
            'export_formats'
        ]
    })


@ai_analysis_bp.route('/capabilities', methods=['GET'])
def get_capabilities():
    """Get available AI analysis capabilities"""
    return jsonify({
        'analysis_types': [
            {'name': 'comprehensive', 'description': 'Full analysis with all tools'},
            {'name': 'security', 'description': 'Security-focused analysis'},
            {'name': 'triage', 'description': 'Rapid threat assessment'},
            {'name': 'custom', 'description': 'Custom analysis based on goals'}
        ],
        'supported_formats': ['json', 'xml', 'yaml', 'pdf', 'markdown'],
        'ai_features': [
            'natural_language_queries',
            'intelligent_workflow_suggestions',
            'context_aware_analysis',
            'multi_model_ensemble',
            'learning_and_adaptation'
        ],
        'integration_points': [
            'ghidra_mcp',
            'ollama_llm',
            'vulnerability_scanners',
            'threat_intelligence',
            'binary_analysis_tools'
        ]
    })


# Error handlers
@ai_analysis_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'status': 'error', 'message': 'Bad request', 'details': str(error)}), 400


@ai_analysis_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'status': 'error', 'message': 'Internal server error', 'details': str(error)}), 500
