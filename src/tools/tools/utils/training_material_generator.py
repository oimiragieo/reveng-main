#!/usr/bin/env python3
"""
Training Material and Case Study Generator

This module creates automated security training content generators for security awareness,
case study templates with real-world examples, and interactive learning modules.

Requirements: 8.2, 8.5
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import yaml
import markdown
from jinja2 import Template, Environment, FileSystemLoader

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TrainingModule:
    """Represents a training module with content and exercises"""
    title: str
    description: str
    learning_objectives: List[str]
    content_sections: List[Dict[str, Any]]
    exercises: List[Dict[str, Any]]
    assessment_questions: List[Dict[str, Any]]
    difficulty_level: str  # beginner, intermediate, advanced
    estimated_duration: int  # minutes
    prerequisites: List[str]
    tags: List[str]

@dataclass
class CaseStudy:
    """Represents a security case study with analysis and lessons"""
    title: str
    summary: str
    background: str
    technical_details: Dict[str, Any]
    analysis_findings: List[Dict[str, Any]]
    lessons_learned: List[str]
    recommendations: List[str]
    timeline: List[Dict[str, Any]]
    impact_assessment: Dict[str, Any]
    references: List[str]
    difficulty_level: str
    target_audience: List[str]

@dataclass
class InteractiveLearningModule:
    """Represents an interactive learning module with hands-on components"""
    module_id: str
    title: str
    description: str
    learning_path: List[str]
    hands_on_exercises: List[Dict[str, Any]]
    virtual_labs: List[Dict[str, Any]]
    simulation_scenarios: List[Dict[str, Any]]
    progress_tracking: Dict[str, Any]
    completion_criteria: List[str]

class TrainingContentGenerator:
    """Generates automated security training content"""
    
    def __init__(self, output_dir: str = "training_materials"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.output_dir / "templates"))
        )
        
        # Create templates directory
        (self.output_dir / "templates").mkdir(exist_ok=True)
        self._create_default_templates()
        
        logger.info(f"Training content generator initialized with output directory: {self.output_dir}")
    
    def _create_default_templates(self):
        """Create default Jinja2 templates for training materials"""
        
        # Training module template
        module_template = """
# {{ title }}

## Description
{{ description }}

## Learning Objectives
{% for objective in learning_objectives %}
- {{ objective }}
{% endfor %}

## Prerequisites
{% for prereq in prerequisites %}
- {{ prereq }}
{% endfor %}

## Estimated Duration
{{ estimated_duration }} minutes

## Difficulty Level
{{ difficulty_level }}

{% for section in content_sections %}
## {{ section.title }}
{{ section.content }}

{% if section.code_examples %}
### Code Examples
{% for example in section.code_examples %}
```{{ example.language }}
{{ example.code }}
```
{{ example.explanation }}
{% endfor %}
{% endif %}

{% endfor %}

## Hands-On Exercises
{% for exercise in exercises %}
### Exercise {{ loop.index }}: {{ exercise.title }}
**Objective:** {{ exercise.objective }}

**Instructions:**
{% for instruction in exercise.instructions %}
{{ loop.index }}. {{ instruction }}
{% endfor %}

**Expected Outcome:** {{ exercise.expected_outcome }}

{% if exercise.hints %}
**Hints:**
{% for hint in exercise.hints %}
- {{ hint }}
{% endfor %}
{% endif %}

{% endfor %}

## Assessment Questions
{% for question in assessment_questions %}
{{ loop.index }}. {{ question.question }}
{% if question.type == 'multiple_choice' %}
{% for option in question.options %}
   {{ option.letter }}. {{ option.text }}
{% endfor %}
{% endif %}

{% endfor %}

## Additional Resources
{% for tag in tags %}
- Related topic: {{ tag }}
{% endfor %}
"""
        
        with open(self.output_dir / "templates" / "training_module.md", "w") as f:
            f.write(module_template)
        
        # Case study template
        case_study_template = """
# Case Study: {{ title }}

## Executive Summary
{{ summary }}

## Background
{{ background }}

## Timeline of Events
{% for event in timeline %}
**{{ event.date }}** - {{ event.description }}
{% if event.technical_details %}
*Technical Details:* {{ event.technical_details }}
{% endif %}
{% endfor %}

## Technical Analysis
{% for finding in analysis_findings %}
### {{ finding.category }}
**Finding:** {{ finding.description }}
**Evidence:** {{ finding.evidence }}
**Impact:** {{ finding.impact }}
**CVSS Score:** {{ finding.cvss_score if finding.cvss_score else 'N/A' }}
{% endfor %}

## Impact Assessment
**Financial Impact:** {{ impact_assessment.financial }}
**Operational Impact:** {{ impact_assessment.operational }}
**Reputational Impact:** {{ impact_assessment.reputational }}
**Regulatory Impact:** {{ impact_assessment.regulatory }}

## Lessons Learned
{% for lesson in lessons_learned %}
- {{ lesson }}
{% endfor %}

## Recommendations
{% for recommendation in recommendations %}
- {{ recommendation }}
{% endfor %}

## Discussion Questions
1. What could have been done differently to prevent this incident?
2. How would you prioritize the remediation efforts?
3. What detection mechanisms could have identified this threat earlier?
4. How would you communicate this incident to stakeholders?

## References
{% for reference in references %}
- {{ reference }}
{% endfor %}

---
*Target Audience:* {{ target_audience | join(', ') }}
*Difficulty Level:* {{ difficulty_level }}
"""
        
        with open(self.output_dir / "templates" / "case_study.md", "w") as f:
            f.write(case_study_template)
    
    def generate_security_awareness_module(self, topic: str, analysis_results: Dict[str, Any]) -> TrainingModule:
        """Generate security awareness training module based on analysis results"""
        
        # Define common security awareness topics and their content
        topic_content = {
            "reverse_engineering_risks": {
                "title": "Understanding Reverse Engineering Risks in Modern Software",
                "description": "Learn how AI-powered reverse engineering tools can expose sensitive data in compiled applications",
                "learning_objectives": [
                    "Understand how modern reverse engineering tools work",
                    "Identify sensitive data that can be extracted from binaries",
                    "Learn protective measures against reverse engineering",
                    "Recognize the business impact of code exposure"
                ],
                "content_sections": [
                    {
                        "title": "Introduction to Modern Reverse Engineering",
                        "content": "Modern AI-powered tools can automatically analyze and reconstruct source code from compiled binaries, exposing sensitive information that developers thought was protected.",
                        "code_examples": [
                            {
                                "language": "python",
                                "code": "# This hardcoded API key will be visible in the compiled binary\nAPI_KEY = 'sk-1234567890abcdef'\nDATABASE_URL = 'postgresql://user:password@localhost/db'",
                                "explanation": "Hardcoded credentials like these are easily extracted by reverse engineering tools"
                            }
                        ]
                    }
                ]
            },
            "vulnerability_detection": {
                "title": "Automated Vulnerability Detection in Software",
                "description": "Understanding how AI can automatically identify security vulnerabilities in any codebase",
                "learning_objectives": [
                    "Learn about common vulnerability types",
                    "Understand automated detection techniques",
                    "Recognize vulnerable code patterns",
                    "Implement secure coding practices"
                ]
            },
            "threat_intelligence": {
                "title": "Threat Intelligence and Attribution Analysis",
                "description": "How modern tools correlate threats with known attack groups and campaigns",
                "learning_objectives": [
                    "Understand threat intelligence concepts",
                    "Learn about APT attribution methods",
                    "Recognize attack patterns and TTPs",
                    "Use threat intelligence for defense"
                ]
            }
        }
        
        base_content = topic_content.get(topic, topic_content["reverse_engineering_risks"])
        
        # Generate exercises based on analysis results
        exercises = []
        if analysis_results.get("credentials_found"):
            exercises.append({
                "title": "Identify Hardcoded Credentials",
                "objective": "Learn to identify and secure hardcoded credentials in source code",
                "instructions": [
                    "Review the provided code sample",
                    "Identify all hardcoded credentials",
                    "Suggest secure alternatives for each finding",
                    "Implement environment variable usage"
                ],
                "expected_outcome": "Students can identify credential exposure risks and implement secure storage methods",
                "hints": [
                    "Look for strings that appear to be passwords, API keys, or connection strings",
                    "Consider using environment variables or secure key management systems"
                ]
            })
        
        if analysis_results.get("vulnerabilities"):
            exercises.append({
                "title": "Vulnerability Assessment Exercise",
                "objective": "Practice identifying and classifying security vulnerabilities",
                "instructions": [
                    "Analyze the provided vulnerable code samples",
                    "Classify each vulnerability by type and severity",
                    "Propose remediation strategies",
                    "Estimate the business impact"
                ],
                "expected_outcome": "Students can systematically assess and prioritize security vulnerabilities",
                "hints": [
                    "Use the CVSS scoring system for severity assessment",
                    "Consider both technical and business impact"
                ]
            })
        
        # Generate assessment questions
        assessment_questions = [
            {
                "question": "Which of the following is the most effective way to protect sensitive data in compiled applications?",
                "type": "multiple_choice",
                "options": [
                    {"letter": "A", "text": "Code obfuscation"},
                    {"letter": "B", "text": "Runtime encryption with external key management"},
                    {"letter": "C", "text": "Removing debug symbols"},
                    {"letter": "D", "text": "Using proprietary compilers"}
                ],
                "correct_answer": "B",
                "explanation": "Runtime encryption with external key management provides the strongest protection"
            },
            {
                "question": "What is the primary risk of hardcoded credentials in compiled applications?",
                "type": "open_ended",
                "sample_answer": "Hardcoded credentials can be easily extracted through reverse engineering, leading to unauthorized access to systems and data breaches."
            }
        ]
        
        return TrainingModule(
            title=base_content["title"],
            description=base_content["description"],
            learning_objectives=base_content["learning_objectives"],
            content_sections=base_content.get("content_sections", []),
            exercises=exercises,
            assessment_questions=assessment_questions,
            difficulty_level="intermediate",
            estimated_duration=45,
            prerequisites=["Basic understanding of software development", "Familiarity with security concepts"],
            tags=["reverse-engineering", "security-awareness", "vulnerability-assessment"]
        )
    
    def generate_case_study(self, analysis_results: Dict[str, Any], incident_type: str = "data_exposure") -> CaseStudy:
        """Generate a case study based on analysis results"""
        
        # Extract relevant information from analysis results
        findings = analysis_results.get("analysis_findings", [])
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        credentials = analysis_results.get("credentials_found", [])
        
        # Generate case study based on incident type
        if incident_type == "data_exposure":
            title = "Corporate Data Exposure Through Reverse Engineering"
            summary = "A security assessment revealed that a mobile application contained hardcoded API keys and database credentials that could be extracted through automated reverse engineering tools."
            
            timeline = [
                {
                    "date": "Day 1",
                    "description": "Security team begins routine application assessment",
                    "technical_details": "Initial binary analysis using AI-enhanced tools"
                },
                {
                    "date": "Day 2", 
                    "description": "Automated tools identify hardcoded credentials",
                    "technical_details": f"Found {len(credentials)} credential exposures in compiled binary"
                },
                {
                    "date": "Day 3",
                    "description": "Business logic extraction reveals proprietary algorithms",
                    "technical_details": "Pricing algorithms and customer data processing logic exposed"
                },
                {
                    "date": "Day 5",
                    "description": "Executive briefing on security implications",
                    "technical_details": "Risk assessment completed with business impact analysis"
                }
            ]
            
            analysis_findings = []
            for i, cred in enumerate(credentials[:3]):  # Limit to first 3 for readability
                analysis_findings.append({
                    "category": "Credential Exposure",
                    "description": f"Hardcoded {cred.get('type', 'credential')} found in binary",
                    "evidence": f"String pattern matching identified credential at offset {cred.get('offset', 'unknown')}",
                    "impact": "High - Unauthorized access to backend systems",
                    "cvss_score": "8.5"
                })
            
            lessons_learned = [
                "Hardcoded credentials in compiled applications are easily extractable",
                "Modern AI tools can reverse engineer applications with minimal effort",
                "Traditional security through obscurity is ineffective",
                "Proper secret management is essential for application security"
            ]
            
            recommendations = [
                "Implement external key management system",
                "Use environment variables for configuration",
                "Implement runtime credential encryption",
                "Regular security assessments of compiled applications",
                "Developer training on secure coding practices"
            ]
        
        elif incident_type == "vulnerability_discovery":
            title = "Automated Vulnerability Discovery in Enterprise Software"
            summary = "AI-powered analysis tools automatically identified multiple security vulnerabilities in a legacy enterprise application, demonstrating the need for continuous security assessment."
            
            timeline = [
                {
                    "date": "Week 1",
                    "description": "Automated vulnerability scanning initiated",
                    "technical_details": "AI analysis of decompiled source code"
                },
                {
                    "date": "Week 2",
                    "description": "Critical vulnerabilities identified",
                    "technical_details": f"Found {len(vulnerabilities)} vulnerabilities across multiple categories"
                }
            ]
            
            analysis_findings = []
            for vuln in vulnerabilities[:5]:  # Limit for readability
                analysis_findings.append({
                    "category": vuln.get("type", "Security Vulnerability"),
                    "description": vuln.get("description", "Vulnerability detected"),
                    "evidence": vuln.get("evidence", "Automated analysis"),
                    "impact": vuln.get("impact", "Medium"),
                    "cvss_score": vuln.get("cvss_score", "6.5")
                })
            
            lessons_learned = [
                "Legacy applications often contain multiple security vulnerabilities",
                "Automated tools can identify vulnerabilities faster than manual review",
                "Regular security assessments are essential for maintaining security posture"
            ]
            
            recommendations = [
                "Implement automated vulnerability scanning in CI/CD pipeline",
                "Prioritize remediation based on CVSS scores and business impact",
                "Establish regular security assessment schedule"
            ]
        
        return CaseStudy(
            title=title,
            summary=summary,
            background="This case study demonstrates real-world security implications of modern reverse engineering capabilities.",
            technical_details=analysis_results,
            analysis_findings=analysis_findings,
            lessons_learned=lessons_learned,
            recommendations=recommendations,
            timeline=timeline,
            impact_assessment={
                "financial": "Potential data breach costs estimated at $2.5M",
                "operational": "Critical systems at risk of unauthorized access",
                "reputational": "Customer trust and brand reputation impact",
                "regulatory": "Potential GDPR and compliance violations"
            },
            references=[
                "OWASP Top 10 Security Risks",
                "NIST Cybersecurity Framework",
                "Industry security best practices"
            ],
            difficulty_level="intermediate",
            target_audience=["Security professionals", "Developers", "IT managers"]
        )
    
    def create_interactive_learning_module(self, topic: str, analysis_results: Dict[str, Any]) -> InteractiveLearningModule:
        """Create interactive learning module with hands-on exercises"""
        
        module_id = f"interactive_{topic}_{datetime.now().strftime('%Y%m%d')}"
        
        hands_on_exercises = [
            {
                "title": "Binary Analysis Workshop",
                "description": "Hands-on exercise using real analysis tools",
                "steps": [
                    "Download sample binary application",
                    "Run automated analysis tools",
                    "Identify security findings",
                    "Generate remediation report"
                ],
                "tools_required": ["Python", "Analysis tools", "Text editor"],
                "estimated_time": 30,
                "difficulty": "intermediate"
            },
            {
                "title": "Vulnerability Assessment Lab",
                "description": "Practice identifying and classifying vulnerabilities",
                "steps": [
                    "Analyze provided vulnerable code samples",
                    "Use automated scanning tools",
                    "Classify findings by severity",
                    "Create remediation plan"
                ],
                "tools_required": ["Static analysis tools", "CVSS calculator"],
                "estimated_time": 45,
                "difficulty": "advanced"
            }
        ]
        
        virtual_labs = [
            {
                "name": "Reverse Engineering Sandbox",
                "description": "Safe environment for practicing reverse engineering techniques",
                "environment": "Isolated VM with analysis tools",
                "scenarios": ["Mobile app analysis", "Desktop application assessment", "Web application review"]
            }
        ]
        
        simulation_scenarios = [
            {
                "name": "Incident Response Simulation",
                "description": "Simulated security incident requiring analysis and response",
                "objective": "Practice incident response procedures using analysis tools",
                "duration": 60,
                "participants": "1-4 people"
            }
        ]
        
        return InteractiveLearningModule(
            module_id=module_id,
            title=f"Interactive {topic.replace('_', ' ').title()} Training",
            description=f"Hands-on learning module for {topic} with practical exercises",
            learning_path=[
                "Introduction and setup",
                "Guided exercises",
                "Independent practice",
                "Assessment and feedback"
            ],
            hands_on_exercises=hands_on_exercises,
            virtual_labs=virtual_labs,
            simulation_scenarios=simulation_scenarios,
            progress_tracking={
                "completion_percentage": 0,
                "exercises_completed": 0,
                "assessment_score": 0,
                "time_spent": 0
            },
            completion_criteria=[
                "Complete all hands-on exercises",
                "Pass final assessment with 80% score",
                "Submit practical project"
            ]
        )
    
    def export_training_module(self, module: TrainingModule, format: str = "markdown") -> str:
        """Export training module to specified format"""
        
        if format == "markdown":
            template = self.jinja_env.get_template("training_module.md")
            content = template.render(**asdict(module))
            
            filename = f"{module.title.lower().replace(' ', '_')}.md"
            filepath = self.output_dir / "modules" / filename
            filepath.parent.mkdir(exist_ok=True)
            
            with open(filepath, "w") as f:
                f.write(content)
            
            logger.info(f"Training module exported to: {filepath}")
            return str(filepath)
        
        elif format == "json":
            filename = f"{module.title.lower().replace(' ', '_')}.json"
            filepath = self.output_dir / "modules" / filename
            filepath.parent.mkdir(exist_ok=True)
            
            with open(filepath, "w") as f:
                json.dump(asdict(module), f, indent=2)
            
            return str(filepath)
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def export_case_study(self, case_study: CaseStudy, format: str = "markdown") -> str:
        """Export case study to specified format"""
        
        if format == "markdown":
            template = self.jinja_env.get_template("case_study.md")
            content = template.render(**asdict(case_study))
            
            filename = f"{case_study.title.lower().replace(' ', '_')}_case_study.md"
            filepath = self.output_dir / "case_studies" / filename
            filepath.parent.mkdir(exist_ok=True)
            
            with open(filepath, "w") as f:
                f.write(content)
            
            logger.info(f"Case study exported to: {filepath}")
            return str(filepath)
        
        elif format == "json":
            filename = f"{case_study.title.lower().replace(' ', '_')}_case_study.json"
            filepath = self.output_dir / "case_studies" / filename
            filepath.parent.mkdir(exist_ok=True)
            
            with open(filepath, "w") as f:
                json.dump(asdict(case_study), f, indent=2)
            
            return str(filepath)
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def generate_training_curriculum(self, topics: List[str], analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate complete training curriculum with multiple modules"""
        
        curriculum = {
            "title": "AI-Enhanced Security Analysis Training Program",
            "description": "Comprehensive training program on modern security analysis techniques",
            "modules": [],
            "total_duration": 0,
            "learning_paths": {
                "beginner": [],
                "intermediate": [],
                "advanced": []
            }
        }
        
        for topic in topics:
            # Generate training module
            module = self.generate_security_awareness_module(topic, analysis_results)
            curriculum["modules"].append(asdict(module))
            curriculum["total_duration"] += module.estimated_duration
            
            # Add to appropriate learning path
            if module.difficulty_level in curriculum["learning_paths"]:
                curriculum["learning_paths"][module.difficulty_level].append(module.title)
            
            # Export module
            self.export_training_module(module)
            
            # Generate case study
            case_study = self.generate_case_study(analysis_results, topic)
            self.export_case_study(case_study)
            
            # Create interactive module
            interactive_module = self.create_interactive_learning_module(topic, analysis_results)
            
            # Export interactive module
            interactive_filename = f"interactive_{topic}.json"
            interactive_filepath = self.output_dir / "interactive" / interactive_filename
            interactive_filepath.parent.mkdir(exist_ok=True)
            
            with open(interactive_filepath, "w") as f:
                json.dump(asdict(interactive_module), f, indent=2)
        
        # Export curriculum
        curriculum_filepath = self.output_dir / "curriculum.json"
        with open(curriculum_filepath, "w") as f:
            json.dump(curriculum, f, indent=2)
        
        logger.info(f"Training curriculum generated with {len(topics)} modules")
        return curriculum

def main():
    """Main function for testing the training material generator"""
    
    # Sample analysis results for testing
    sample_analysis_results = {
        "credentials_found": [
            {"type": "API_KEY", "value": "sk-***", "offset": "0x1234"},
            {"type": "DATABASE_URL", "value": "postgresql://***", "offset": "0x5678"}
        ],
        "vulnerabilities": [
            {"type": "Buffer Overflow", "description": "Stack buffer overflow in input handler", "cvss_score": "8.5"},
            {"type": "SQL Injection", "description": "Unsanitized input in database query", "cvss_score": "7.2"}
        ],
        "analysis_findings": [
            {"category": "Security", "description": "Multiple security issues identified"},
            {"category": "Data Exposure", "description": "Sensitive data found in binary"}
        ]
    }
    
    # Initialize generator
    generator = TrainingContentGenerator()
    
    # Generate training curriculum
    topics = ["reverse_engineering_risks", "vulnerability_detection", "threat_intelligence"]
    curriculum = generator.generate_training_curriculum(topics, sample_analysis_results)
    
    print(f"Generated training curriculum with {len(curriculum['modules'])} modules")
    print(f"Total estimated duration: {curriculum['total_duration']} minutes")

if __name__ == "__main__":
    main()