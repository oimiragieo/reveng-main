#!/usr/bin/env python3
"""
Demonstration and Presentation Generator
=======================================

This module creates compelling demonstrations and presentations for security
research, executive briefings, and educational purposes. It showcases the
capabilities of AI-enhanced binary analysis and reconstruction.

Features:
1. Interactive web-based demonstrations of analysis capabilities
2. Executive-level presentations with risk visualizations
3. Security awareness training materials
4. Live demonstration workflows for client presentations

Author: AI-Enhanced Universal Analysis Engine
Version: 1.0
"""

import base64
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DemoType(Enum):
    """Types of demonstrations"""
    EXECUTIVE_DASHBOARD = "executive_dashboard"
    TECHNICAL_ANALYSIS = "technical_analysis"
    SECURITY_AWARENESS = "security_awareness"
    LIVE_PRESENTATION = "live_presentation"
    TRAINING_MATERIAL = "training_material"


class RiskLevel(Enum):
    """Risk levels for visualizations"""
    CRITICAL = ("critical", "#dc3545", "🔴")
    HIGH = ("high", "#fd7e14", "🟠")
    MEDIUM = ("medium", "#ffc107", "🟡")
    LOW = ("low", "#28a745", "🟢")
    INFO = ("info", "#17a2b8", "🔵")


@dataclass
class DemoConfig:
    """Configuration for demonstration generation"""
    demo_type: DemoType
    target_audience: str = "technical"  # "executive", "technical", "general"
    include_live_demo: bool = True
    include_risk_matrix: bool = True
    include_code_samples: bool = True
    include_recommendations: bool = True
    branding_enabled: bool = True
    export_formats: List[str] = field(default_factory=lambda: ["html", "pdf"])


@dataclass
class AnalysisEvidence:
    """Evidence from binary analysis"""
    evidence_type: str
    description: str
    risk_level: RiskLevel
    technical_details: Dict[str, Any]
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class DemonstrationPackage:
    """Complete demonstration package"""
    demo_id: str
    demo_type: DemoType
    target_audience: str
    generated_files: List[Path] = field(default_factory=list)
    web_demo_url: Optional[str] = None
    presentation_slides: Optional[Path] = None
    executive_summary: Optional[Path] = None
    technical_report: Optional[Path] = None
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    creation_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class DemonstrationGenerator:
    """
    Main class for generating security demonstrations and presentations
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """Initialize the demonstration generator"""
        self.output_dir = output_dir or Path(tempfile.mkdtemp(prefix="security_demo_"))
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.output_dir / "web").mkdir(exist_ok=True)
        (self.output_dir / "presentations").mkdir(exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)
        (self.output_dir / "assets").mkdir(exist_ok=True)
        
        logger.info(f"Demonstration Generator initialized")
        logger.info(f"Output directory: {self.output_dir}")
    
    def create_demonstration(
        self, 
        analysis_results: Dict[str, Any],
        config: DemoConfig
    ) -> DemonstrationPackage:
        """
        Create a complete demonstration package
        """
        logger.info(f"Creating {config.demo_type.value} demonstration")
        
        demo_id = f"demo_{int(time.time())}"
        package = DemonstrationPackage(
            demo_id=demo_id,
            demo_type=config.demo_type,
            target_audience=config.target_audience
        )
        
        try:
            # Extract evidence from analysis results
            evidence = self._extract_evidence(analysis_results)
            
            # Generate risk assessment
            package.risk_assessment = self._generate_risk_assessment(evidence)
            
            # Generate recommendations
            package.recommendations = self._generate_recommendations(evidence, config.target_audience)
            
            # Create demonstration based on type
            if config.demo_type == DemoType.EXECUTIVE_DASHBOARD:
                self._create_executive_dashboard(package, evidence, config)
            elif config.demo_type == DemoType.TECHNICAL_ANALYSIS:
                self._create_technical_analysis(package, evidence, config)
            elif config.demo_type == DemoType.SECURITY_AWARENESS:
                self._create_security_awareness(package, evidence, config)
            elif config.demo_type == DemoType.LIVE_PRESENTATION:
                self._create_live_presentation(package, evidence, config)
            elif config.demo_type == DemoType.TRAINING_MATERIAL:
                self._create_training_material(package, evidence, config)
            
            # Generate web demo if requested
            if config.include_live_demo:
                package.web_demo_url = self._create_web_demo(package, evidence, config)
            
            logger.info(f"Demonstration package created: {demo_id}")
            
        except Exception as e:
            logger.error(f"Demonstration creation failed: {e}")
            package.recommendations.append(f"Demo generation failed: {e}")
        
        return package
    
    def _extract_evidence(self, analysis_results: Dict[str, Any]) -> List[AnalysisEvidence]:
        """Extract evidence from analysis results"""
        evidence = []
        
        try:
            # Corporate exposure evidence
            if "corporate_exposure" in analysis_results:
                corp_data = analysis_results["corporate_exposure"]
                
                if corp_data.get("credentials_found"):
                    evidence.append(AnalysisEvidence(
                        evidence_type="credential_exposure",
                        description=f"Found {len(corp_data['credentials_found'])} hardcoded credentials",
                        risk_level=RiskLevel.CRITICAL,
                        technical_details={"credentials": corp_data["credentials_found"]},
                        remediation="Remove hardcoded credentials and use secure credential management"
                    ))
                
                if corp_data.get("api_endpoints_discovered"):
                    evidence.append(AnalysisEvidence(
                        evidence_type="api_exposure",
                        description=f"Discovered {len(corp_data['api_endpoints_discovered'])} API endpoints",
                        risk_level=RiskLevel.HIGH,
                        technical_details={"endpoints": corp_data["api_endpoints_discovered"]},
                        remediation="Review API security and implement proper authentication"
                    ))
            
            # Vulnerability evidence
            if "vulnerabilities" in analysis_results:
                vuln_data = analysis_results["vulnerabilities"]
                
                if vuln_data.get("memory_vulnerabilities"):
                    evidence.append(AnalysisEvidence(
                        evidence_type="memory_vulnerability",
                        description=f"Found {len(vuln_data['memory_vulnerabilities'])} memory vulnerabilities",
                        risk_level=RiskLevel.CRITICAL,
                        technical_details={"vulnerabilities": vuln_data["memory_vulnerabilities"]},
                        remediation="Implement bounds checking and memory safety measures"
                    ))
                
                if vuln_data.get("injection_vulnerabilities"):
                    evidence.append(AnalysisEvidence(
                        evidence_type="injection_vulnerability",
                        description=f"Found {len(vuln_data['injection_vulnerabilities'])} injection vulnerabilities",
                        risk_level=RiskLevel.HIGH,
                        technical_details={"vulnerabilities": vuln_data["injection_vulnerabilities"]},
                        remediation="Implement input validation and parameterized queries"
                    ))
            
            # Threat intelligence evidence
            if "threat_intelligence" in analysis_results:
                threat_data = analysis_results["threat_intelligence"]
                
                if threat_data.get("apt_attribution"):
                    evidence.append(AnalysisEvidence(
                        evidence_type="apt_attribution",
                        description=f"Potential APT group attribution: {threat_data['apt_attribution']}",
                        risk_level=RiskLevel.CRITICAL,
                        technical_details={"attribution": threat_data["apt_attribution"]},
                        remediation="Implement advanced threat detection and response measures"
                    ))
            
            # Reconstruction evidence
            if "reconstruction_demo" in analysis_results:
                recon_data = analysis_results["reconstruction_demo"]
                
                evidence.append(AnalysisEvidence(
                    evidence_type="reconstruction_capability",
                    description="Complete binary reconstruction achieved",
                    risk_level=RiskLevel.HIGH,
                    technical_details={"reconstruction": recon_data},
                    remediation="Implement code obfuscation and anti-reverse engineering measures"
                ))
            
        except Exception as e:
            logger.error(f"Evidence extraction failed: {e}")
        
        return evidence
    
    def _generate_risk_assessment(self, evidence: List[AnalysisEvidence]) -> Dict[str, Any]:
        """Generate comprehensive risk assessment"""
        risk_counts = {level: 0 for level in RiskLevel}
        
        for item in evidence:
            risk_counts[item.risk_level] += 1
        
        # Calculate overall risk score
        risk_score = (
            risk_counts[RiskLevel.CRITICAL] * 10 +
            risk_counts[RiskLevel.HIGH] * 7 +
            risk_counts[RiskLevel.MEDIUM] * 4 +
            risk_counts[RiskLevel.LOW] * 1
        )
        
        # Determine overall risk level
        if risk_score >= 20:
            overall_risk = RiskLevel.CRITICAL
        elif risk_score >= 10:
            overall_risk = RiskLevel.HIGH
        elif risk_score >= 5:
            overall_risk = RiskLevel.MEDIUM
        else:
            overall_risk = RiskLevel.LOW
        
        return {
            "overall_risk": overall_risk.value[0],
            "risk_score": risk_score,
            "risk_distribution": {level.value[0]: count for level, count in risk_counts.items()},
            "total_findings": len(evidence),
            "critical_findings": risk_counts[RiskLevel.CRITICAL],
            "high_findings": risk_counts[RiskLevel.HIGH]
        }
    
    def _generate_recommendations(self, evidence: List[AnalysisEvidence], audience: str) -> List[str]:
        """Generate recommendations based on evidence and audience"""
        recommendations = []
        
        if audience == "executive":
            recommendations.extend([
                "Implement comprehensive security assessment program",
                "Invest in advanced threat detection and response capabilities",
                "Establish secure software development lifecycle (SSDLC)",
                "Conduct regular security awareness training for all staff",
                "Engage third-party security experts for independent validation"
            ])
        elif audience == "technical":
            recommendations.extend([
                "Implement static and dynamic code analysis in CI/CD pipeline",
                "Deploy runtime application self-protection (RASP) solutions",
                "Establish secure coding standards and peer review processes",
                "Implement comprehensive logging and monitoring",
                "Deploy advanced endpoint detection and response (EDR) tools"
            ])
        else:  # general
            recommendations.extend([
                "Enhance overall security posture through comprehensive assessment",
                "Implement multi-layered security controls and monitoring",
                "Establish incident response and recovery procedures",
                "Conduct regular security training and awareness programs",
                "Engage security experts for ongoing assessment and improvement"
            ])
        
        # Add specific recommendations based on evidence
        for item in evidence:
            if item.remediation and item.remediation not in recommendations:
                recommendations.append(item.remediation)
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _create_executive_dashboard(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        config: DemoConfig
    ) -> None:
        """Create executive dashboard presentation"""
        logger.info("Creating executive dashboard")
        
        # Generate executive summary
        summary_path = self.output_dir / "reports" / f"{package.demo_id}_executive_summary.md"
        self._generate_executive_summary(package, evidence, summary_path)
        package.executive_summary = summary_path
        package.generated_files.append(summary_path)
        
        # Generate PowerPoint-style presentation
        presentation_path = self.output_dir / "presentations" / f"{package.demo_id}_executive_presentation.html"
        self._generate_executive_presentation(package, evidence, presentation_path)
        package.presentation_slides = presentation_path
        package.generated_files.append(presentation_path)
        
        # Generate risk matrix visualization
        if config.include_risk_matrix:
            risk_matrix_path = self.output_dir / "assets" / f"{package.demo_id}_risk_matrix.html"
            self._generate_risk_matrix(package, evidence, risk_matrix_path)
            package.generated_files.append(risk_matrix_path)
    
    def _create_technical_analysis(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        config: DemoConfig
    ) -> None:
        """Create technical analysis demonstration"""
        logger.info("Creating technical analysis demonstration")
        
        # Generate detailed technical report
        report_path = self.output_dir / "reports" / f"{package.demo_id}_technical_report.md"
        self._generate_technical_report(package, evidence, report_path)
        package.technical_report = report_path
        package.generated_files.append(report_path)
        
        # Generate code analysis samples
        if config.include_code_samples:
            code_samples_path = self.output_dir / "reports" / f"{package.demo_id}_code_samples.html"
            self._generate_code_samples(package, evidence, code_samples_path)
            package.generated_files.append(code_samples_path)
    
    def _create_security_awareness(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        config: DemoConfig
    ) -> None:
        """Create security awareness materials"""
        logger.info("Creating security awareness materials")
        
        # Generate awareness presentation
        awareness_path = self.output_dir / "presentations" / f"{package.demo_id}_security_awareness.html"
        self._generate_awareness_presentation(package, evidence, awareness_path)
        package.generated_files.append(awareness_path)
    
    def _create_live_presentation(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        config: DemoConfig
    ) -> None:
        """Create live presentation materials"""
        logger.info("Creating live presentation materials")
        
        # Generate speaker notes
        notes_path = self.output_dir / "presentations" / f"{package.demo_id}_speaker_notes.md"
        self._generate_speaker_notes(package, evidence, notes_path)
        package.generated_files.append(notes_path)
        
        # Generate live demo script
        script_path = self.output_dir / "presentations" / f"{package.demo_id}_demo_script.md"
        self._generate_demo_script(package, evidence, script_path)
        package.generated_files.append(script_path)
    
    def _create_training_material(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        config: DemoConfig
    ) -> None:
        """Create training materials"""
        logger.info("Creating training materials")
        
        # Generate training modules
        training_path = self.output_dir / "presentations" / f"{package.demo_id}_training_modules.html"
        self._generate_training_modules(package, evidence, training_path)
        package.generated_files.append(training_path)
    
    def _create_web_demo(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        config: DemoConfig
    ) -> str:
        """Create interactive web demonstration"""
        logger.info("Creating interactive web demonstration")
        
        web_demo_path = self.output_dir / "web" / f"{package.demo_id}_interactive_demo.html"
        
        # Generate interactive web demo
        self._generate_interactive_web_demo(package, evidence, web_demo_path)
        package.generated_files.append(web_demo_path)
        
        return f"file://{web_demo_path.absolute()}"
    
    def _generate_executive_summary(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate executive summary document"""
        
        critical_count = sum(1 for e in evidence if e.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for e in evidence if e.risk_level == RiskLevel.HIGH)
        
        content = f"""# Executive Security Assessment Summary

## Key Findings

**Overall Risk Level**: {package.risk_assessment.get('overall_risk', 'Unknown').upper()}

- **Critical Issues**: {critical_count}
- **High Risk Issues**: {high_count}
- **Total Findings**: {len(evidence)}

## Executive Summary

This assessment demonstrates how modern AI-powered reverse engineering tools can automatically analyze and reconstruct software, exposing significant security risks that traditional security measures may not address.

### Key Security Concerns

{self._format_evidence_for_executives(evidence)}

### Business Impact

The identified vulnerabilities and exposures could result in:

- **Data Breach**: Exposed credentials and API keys could lead to unauthorized access
- **Intellectual Property Theft**: Proprietary algorithms and business logic are easily extractable
- **Compliance Violations**: Security weaknesses may violate regulatory requirements
- **Reputation Damage**: Security incidents could damage brand reputation and customer trust
- **Financial Loss**: Potential costs from breaches, fines, and remediation efforts

### Immediate Actions Required

{chr(10).join(f'1. {rec}' for rec in package.recommendations[:5])}

### Investment Recommendations

- Implement comprehensive security assessment program
- Invest in advanced threat detection and response capabilities
- Establish secure software development lifecycle (SSDLC)
- Engage third-party security experts for validation

---
*Assessment conducted using AI-Enhanced Universal Binary Analysis Engine*
*Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_executive_presentation(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate executive presentation in HTML format"""
        
        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment - Executive Presentation</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; }}
        .slide {{ width: 100vw; height: 100vh; padding: 60px; box-sizing: border-box; display: none; }}
        .slide.active {{ display: flex; flex-direction: column; justify-content: center; }}
        .slide h1 {{ font-size: 3em; color: #2c3e50; margin-bottom: 30px; }}
        .slide h2 {{ font-size: 2.5em; color: #34495e; margin-bottom: 20px; }}
        .slide h3 {{ font-size: 2em; color: #7f8c8d; margin-bottom: 15px; }}
        .risk-critical {{ color: #e74c3c; font-weight: bold; }}
        .risk-high {{ color: #f39c12; font-weight: bold; }}
        .risk-medium {{ color: #f1c40f; font-weight: bold; }}
        .risk-low {{ color: #27ae60; font-weight: bold; }}
        .navigation {{ position: fixed; bottom: 20px; right: 20px; }}
        .nav-btn {{ padding: 10px 20px; margin: 5px; background: #3498db; color: white; border: none; cursor: pointer; }}
        .findings-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 30px; margin-top: 30px; }}
        .finding-card {{ background: #ecf0f1; padding: 20px; border-radius: 10px; border-left: 5px solid #e74c3c; }}
    </style>
</head>
<body>
    <!-- Title Slide -->
    <div class="slide active">
        <h1>🔒 Security Assessment Results</h1>
        <h2>AI-Enhanced Binary Analysis</h2>
        <p style="font-size: 1.5em; color: #7f8c8d;">
            Demonstrating Modern Reverse Engineering Capabilities<br>
            <strong>Date:</strong> {datetime.now().strftime("%B %d, %Y")}
        </p>
    </div>

    <!-- Executive Summary Slide -->
    <div class="slide">
        <h1>📊 Executive Summary</h1>
        <div style="font-size: 1.8em; line-height: 1.6;">
            <p><strong>Overall Risk Level:</strong> 
               <span class="risk-{package.risk_assessment.get('overall_risk', 'unknown')}">
                   {package.risk_assessment.get('overall_risk', 'Unknown').upper()}
               </span>
            </p>
            <p><strong>Critical Issues:</strong> {sum(1 for e in evidence if e.risk_level == RiskLevel.CRITICAL)}</p>
            <p><strong>High Risk Issues:</strong> {sum(1 for e in evidence if e.risk_level == RiskLevel.HIGH)}</p>
            <p><strong>Total Findings:</strong> {len(evidence)}</p>
        </div>
    </div>

    <!-- Key Findings Slide -->
    <div class="slide">
        <h1>🎯 Key Security Findings</h1>
        <div class="findings-grid">
            {self._generate_finding_cards_html(evidence[:4])}
        </div>
    </div>

    <!-- Business Impact Slide -->
    <div class="slide">
        <h1>💼 Business Impact</h1>
        <div style="font-size: 1.5em; line-height: 1.8;">
            <h3>🚨 Immediate Risks:</h3>
            <ul>
                <li>Data breach through exposed credentials</li>
                <li>Intellectual property theft</li>
                <li>Compliance violations</li>
                <li>Reputation damage</li>
            </ul>
            <h3>💰 Financial Impact:</h3>
            <ul>
                <li>Potential breach costs: $100K - $10M+</li>
                <li>Regulatory fines and penalties</li>
                <li>Remediation and recovery costs</li>
                <li>Lost business and customer trust</li>
            </ul>
        </div>
    </div>

    <!-- Recommendations Slide -->
    <div class="slide">
        <h1>🛡️ Strategic Recommendations</h1>
        <div style="font-size: 1.4em; line-height: 1.6;">
            <ol>
                {chr(10).join(f'<li>{rec}</li>' for rec in package.recommendations[:6])}
            </ol>
        </div>
    </div>

    <!-- Next Steps Slide -->
    <div class="slide">
        <h1>🚀 Next Steps</h1>
        <div style="font-size: 1.6em; line-height: 1.8;">
            <h3>Immediate (30 days):</h3>
            <ul>
                <li>Address critical security vulnerabilities</li>
                <li>Implement emergency security controls</li>
                <li>Conduct security awareness training</li>
            </ul>
            <h3>Short-term (90 days):</h3>
            <ul>
                <li>Deploy comprehensive security monitoring</li>
                <li>Establish secure development practices</li>
                <li>Engage security experts for ongoing assessment</li>
            </ul>
        </div>
    </div>

    <div class="navigation">
        <button class="nav-btn" onclick="previousSlide()">← Previous</button>
        <button class="nav-btn" onclick="nextSlide()">Next →</button>
    </div>

    <script>
        let currentSlide = 0;
        const slides = document.querySelectorAll('.slide');
        
        function showSlide(n) {{
            slides[currentSlide].classList.remove('active');
            currentSlide = (n + slides.length) % slides.length;
            slides[currentSlide].classList.add('active');
        }}
        
        function nextSlide() {{ showSlide(currentSlide + 1); }}
        function previousSlide() {{ showSlide(currentSlide - 1); }}
        
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'ArrowRight') nextSlide();
            if (e.key === 'ArrowLeft') previousSlide();
        }});
    </script>
</body>
</html>"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_finding_cards_html(self, evidence: List[AnalysisEvidence]) -> str:
        """Generate HTML cards for findings"""
        cards = []
        for item in evidence:
            risk_class = f"risk-{item.risk_level.value[0]}"
            cards.append(f"""
            <div class="finding-card">
                <h3 class="{risk_class}">{item.risk_level.value[2]} {item.evidence_type.replace('_', ' ').title()}</h3>
                <p>{item.description}</p>
                {f'<p><strong>Remediation:</strong> {item.remediation}</p>' if item.remediation else ''}
            </div>
            """)
        return ''.join(cards)
    
    def _generate_technical_report(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate detailed technical report"""
        
        content = f"""# Technical Security Analysis Report

## Analysis Overview

**Analysis ID**: {package.demo_id}
**Analysis Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Analysis Type**: AI-Enhanced Binary Analysis
**Target Audience**: Technical Teams

## Methodology

This analysis was conducted using advanced AI-powered reverse engineering techniques:

1. **Binary Disassembly**: Machine code converted to assembly language
2. **Control Flow Analysis**: Program structure and logic flow reconstructed
3. **Data Flow Analysis**: Variable usage and data dependencies identified
4. **Pattern Recognition**: Common vulnerabilities and attack patterns detected
5. **Threat Intelligence**: Correlation with known attack techniques and indicators

## Detailed Findings

{self._format_evidence_for_technical(evidence)}

## Risk Assessment Matrix

| Risk Level | Count | Percentage |
|------------|-------|------------|
| Critical   | {sum(1 for e in evidence if e.risk_level == RiskLevel.CRITICAL)} | {sum(1 for e in evidence if e.risk_level == RiskLevel.CRITICAL)/len(evidence)*100:.1f}% |
| High       | {sum(1 for e in evidence if e.risk_level == RiskLevel.HIGH)} | {sum(1 for e in evidence if e.risk_level == RiskLevel.HIGH)/len(evidence)*100:.1f}% |
| Medium     | {sum(1 for e in evidence if e.risk_level == RiskLevel.MEDIUM)} | {sum(1 for e in evidence if e.risk_level == RiskLevel.MEDIUM)/len(evidence)*100:.1f}% |
| Low        | {sum(1 for e in evidence if e.risk_level == RiskLevel.LOW)} | {sum(1 for e in evidence if e.risk_level == RiskLevel.LOW)/len(evidence)*100:.1f}% |

## Technical Recommendations

{chr(10).join(f'### {i+1}. {rec}' for i, rec in enumerate(package.recommendations))}

## Proof of Concept Examples

{self._generate_poc_examples(evidence)}

## Remediation Roadmap

### Phase 1: Critical Issues (Immediate - 30 days)
- Address all critical vulnerabilities
- Implement emergency security controls
- Deploy monitoring for active threats

### Phase 2: High Priority (30-90 days)
- Resolve high-risk vulnerabilities
- Implement comprehensive security controls
- Establish secure development practices

### Phase 3: Medium Priority (90-180 days)
- Address remaining medium-risk issues
- Implement advanced security measures
- Conduct security training and awareness

## Conclusion

The analysis reveals significant security risks that require immediate attention. The AI-enhanced analysis capabilities demonstrate how easily modern software can be reverse engineered, highlighting the need for comprehensive security measures.

---
*Technical analysis conducted using AI-Enhanced Universal Binary Analysis Engine*
"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_interactive_web_demo(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate interactive web demonstration"""
        
        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive Security Analysis Demo</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .card {{ background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .risk-critical {{ border-left: 5px solid #e74c3c; }}
        .risk-high {{ border-left: 5px solid #f39c12; }}
        .risk-medium {{ border-left: 5px solid #f1c40f; }}
        .risk-low {{ border-left: 5px solid #27ae60; }}
        .metric {{ text-align: center; padding: 20px; }}
        .metric-value {{ font-size: 3em; font-weight: bold; color: #2c3e50; }}
        .metric-label {{ font-size: 1.2em; color: #7f8c8d; }}
        .progress-bar {{ width: 100%; height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; margin: 10px 0; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #27ae60, #f39c12, #e74c3c); transition: width 0.3s; }}
        .tab-container {{ margin: 20px 0; }}
        .tab-buttons {{ display: flex; background: white; border-radius: 10px 10px 0 0; overflow: hidden; }}
        .tab-button {{ flex: 1; padding: 15px; background: #ecf0f1; border: none; cursor: pointer; font-size: 1.1em; }}
        .tab-button.active {{ background: #3498db; color: white; }}
        .tab-content {{ background: white; padding: 20px; border-radius: 0 0 10px 10px; }}
        .tab-panel {{ display: none; }}
        .tab-panel.active {{ display: block; }}
        .finding-item {{ padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #3498db; }}
        .animate-in {{ animation: slideIn 0.5s ease-out; }}
        @keyframes slideIn {{ from {{ opacity: 0; transform: translateY(20px); }} to {{ opacity: 1; transform: translateY(0); }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 AI-Enhanced Security Analysis</h1>
        <p>Interactive Demonstration of Binary Analysis Capabilities</p>
    </div>

    <div class="container">
        <!-- Risk Overview Dashboard -->
        <div class="dashboard">
            <div class="card metric">
                <div class="metric-value" id="totalFindings">{len(evidence)}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="card metric risk-critical">
                <div class="metric-value" id="criticalFindings">{sum(1 for e in evidence if e.risk_level == RiskLevel.CRITICAL)}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
            <div class="card metric risk-high">
                <div class="metric-value" id="highFindings">{sum(1 for e in evidence if e.risk_level == RiskLevel.HIGH)}</div>
                <div class="metric-label">High Risk Issues</div>
            </div>
            <div class="card metric">
                <div class="metric-value" id="riskScore">{package.risk_assessment.get('risk_score', 0)}</div>
                <div class="metric-label">Risk Score</div>
            </div>
        </div>

        <!-- Risk Level Progress Bar -->
        <div class="card">
            <h3>Overall Risk Assessment</h3>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {min(package.risk_assessment.get('risk_score', 0) * 2, 100)}%"></div>
            </div>
            <p>Risk Level: <strong>{package.risk_assessment.get('overall_risk', 'Unknown').upper()}</strong></p>
        </div>

        <!-- Tabbed Content -->
        <div class="tab-container">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab('findings')">Security Findings</button>
                <button class="tab-button" onclick="showTab('analysis')">Analysis Details</button>
                <button class="tab-button" onclick="showTab('recommendations')">Recommendations</button>
                <button class="tab-button" onclick="showTab('demo')">Live Demo</button>
            </div>

            <div class="tab-content">
                <!-- Findings Tab -->
                <div class="tab-panel active" id="findings">
                    <h3>Security Findings</h3>
                    {self._generate_findings_html(evidence)}
                </div>

                <!-- Analysis Tab -->
                <div class="tab-panel" id="analysis">
                    <h3>Analysis Methodology</h3>
                    <p>This analysis demonstrates how AI-powered tools can automatically:</p>
                    <ul style="margin: 20px 0; padding-left: 20px; line-height: 1.6;">
                        <li>Disassemble and analyze binary code</li>
                        <li>Identify security vulnerabilities and exposures</li>
                        <li>Extract sensitive data and credentials</li>
                        <li>Reconstruct proprietary algorithms</li>
                        <li>Generate actionable security intelligence</li>
                    </ul>
                </div>

                <!-- Recommendations Tab -->
                <div class="tab-panel" id="recommendations">
                    <h3>Security Recommendations</h3>
                    <ol style="margin: 20px 0; padding-left: 20px; line-height: 1.8;">
                        {chr(10).join(f'<li>{rec}</li>' for rec in package.recommendations)}
                    </ol>
                </div>

                <!-- Demo Tab -->
                <div class="tab-panel" id="demo">
                    <h3>Live Analysis Demonstration</h3>
                    <p>This interactive demo shows real-time binary analysis capabilities:</p>
                    <div style="margin: 20px 0;">
                        <button onclick="simulateAnalysis()" style="padding: 15px 30px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 1.1em;">
                            🔍 Start Analysis Simulation
                        </button>
                    </div>
                    <div id="analysisOutput" style="background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 5px; font-family: monospace; display: none;">
                        <div id="analysisLog"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function showTab(tabName) {{
            // Hide all tab panels
            document.querySelectorAll('.tab-panel').forEach(panel => {{
                panel.classList.remove('active');
            }});
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-button').forEach(button => {{
                button.classList.remove('active');
            }});
            
            // Show selected tab panel
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked button
            event.target.classList.add('active');
        }}

        function simulateAnalysis() {{
            const output = document.getElementById('analysisOutput');
            const log = document.getElementById('analysisLog');
            
            output.style.display = 'block';
            log.innerHTML = '';
            
            const steps = [
                'Initializing AI-Enhanced Binary Analysis Engine...',
                'Loading binary file for analysis...',
                'Performing disassembly and control flow analysis...',
                'Scanning for hardcoded credentials and secrets...',
                'Identifying potential vulnerabilities...',
                'Analyzing network communication patterns...',
                'Correlating with threat intelligence databases...',
                'Generating security assessment report...',
                'Analysis complete! Found {len(evidence)} security issues.'
            ];
            
            let i = 0;
            const interval = setInterval(() => {{
                if (i < steps.length) {{
                    log.innerHTML += steps[i] + '<br>';
                    log.scrollTop = log.scrollHeight;
                    i++;
                }} else {{
                    clearInterval(interval);
                    log.innerHTML += '<br><span style="color: #e74c3c; font-weight: bold;">⚠️  CRITICAL SECURITY ISSUES DETECTED!</span><br>';
                    log.innerHTML += '<span style="color: #f39c12;">Review the Security Findings tab for detailed results.</span>';
                }}
            }}, 800);
        }}

        // Animate metrics on page load
        window.addEventListener('load', function() {{
            document.querySelectorAll('.card').forEach((card, index) => {{
                setTimeout(() => {{
                    card.classList.add('animate-in');
                }}, index * 100);
            }});
        }});
    </script>
</body>
</html>"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_findings_html(self, evidence: List[AnalysisEvidence]) -> str:
        """Generate HTML for security findings"""
        findings_html = []
        
        for item in evidence:
            risk_class = f"risk-{item.risk_level.value[0]}"
            findings_html.append(f"""
            <div class="finding-item {risk_class}">
                <h4>{item.risk_level.value[2]} {item.evidence_type.replace('_', ' ').title()}</h4>
                <p><strong>Description:</strong> {item.description}</p>
                {f'<p><strong>Remediation:</strong> {item.remediation}</p>' if item.remediation else ''}
            </div>
            """)
        
        return ''.join(findings_html)
    
    def _format_evidence_for_executives(self, evidence: List[AnalysisEvidence]) -> str:
        """Format evidence for executive audience"""
        formatted = []
        for item in evidence:
            risk_emoji = item.risk_level.value[2]
            formatted.append(f"**{risk_emoji} {item.evidence_type.replace('_', ' ').title()}**: {item.description}")
        return '\n'.join(formatted)
    
    def _format_evidence_for_technical(self, evidence: List[AnalysisEvidence]) -> str:
        """Format evidence for technical audience"""
        formatted = []
        for i, item in enumerate(evidence, 1):
            risk_level = item.risk_level.value[0].upper()
            formatted.append(f"""
### Finding {i}: {item.evidence_type.replace('_', ' ').title()}

**Risk Level**: {risk_level}
**Description**: {item.description}

**Technical Details**:
```json
{json.dumps(item.technical_details, indent=2)}
```

{f'**Proof of Concept**: {item.proof_of_concept}' if item.proof_of_concept else ''}

{f'**Remediation**: {item.remediation}' if item.remediation else ''}

---
""")
        return '\n'.join(formatted)
    
    def _generate_poc_examples(self, evidence: List[AnalysisEvidence]) -> str:
        """Generate proof of concept examples"""
        examples = []
        for item in evidence:
            if item.proof_of_concept:
                examples.append(f"""
### {item.evidence_type.replace('_', ' ').title()}

```
{item.proof_of_concept}
```
""")
        
        return '\n'.join(examples) if examples else "No proof of concept examples available."
    
    def _generate_risk_matrix(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate risk matrix visualization"""
        # This would generate an interactive risk matrix
        # For brevity, creating a simple HTML version
        
        content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Risk Matrix</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; }}
        .risk-matrix {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; max-width: 600px; }}
        .risk-cell {{ padding: 20px; text-align: center; border-radius: 5px; color: white; font-weight: bold; }}
        .critical {{ background: #e74c3c; }}
        .high {{ background: #f39c12; }}
        .medium {{ background: #f1c40f; color: black; }}
        .low {{ background: #27ae60; }}
    </style>
</head>
<body>
    <h1>Security Risk Matrix</h1>
    <div class="risk-matrix">
        <div class="risk-cell critical">Critical<br>{sum(1 for e in evidence if e.risk_level == RiskLevel.CRITICAL)}</div>
        <div class="risk-cell high">High<br>{sum(1 for e in evidence if e.risk_level == RiskLevel.HIGH)}</div>
        <div class="risk-cell medium">Medium<br>{sum(1 for e in evidence if e.risk_level == RiskLevel.MEDIUM)}</div>
        <div class="risk-cell low">Low<br>{sum(1 for e in evidence if e.risk_level == RiskLevel.LOW)}</div>
    </div>
</body>
</html>"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_awareness_presentation(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate security awareness presentation"""
        # Simplified version for brevity
        content = f"""# Security Awareness: The Reality of Modern Reverse Engineering

## What This Demonstration Shows

This analysis reveals how easily modern AI tools can:
- Extract secrets from compiled software
- Identify security vulnerabilities automatically
- Reconstruct proprietary algorithms
- Generate actionable attack intelligence

## Key Takeaways

{chr(10).join(f'- {rec}' for rec in package.recommendations[:5])}

## Your Role in Security

Everyone has a role in maintaining security:
- Report suspicious activities
- Follow secure coding practices
- Keep software updated
- Use strong authentication
- Be aware of social engineering

---
*Generated by AI-Enhanced Universal Analysis Engine*
"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_speaker_notes(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate speaker notes for live presentation"""
        
        content = f"""# Speaker Notes: Security Analysis Presentation

## Opening (5 minutes)
- Welcome audience and introduce the demonstration
- Explain the purpose: showing modern AI reverse engineering capabilities
- Set expectations: this is a security research demonstration

## Key Points to Emphasize:
1. **AI has changed the game**: What used to take weeks now takes minutes
2. **No software is immune**: From mobile apps to enterprise systems
3. **Traditional security assumptions are obsolete**: Obfuscation and compilation provide minimal protection
4. **This is happening now**: These tools are available and being used

## Demonstration Flow (20 minutes)

### Part 1: Binary Analysis (5 minutes)
- Show the original binary file
- Explain what we're going to extract
- Run the AI analysis tool
- Highlight the speed and automation

### Part 2: Results Review (10 minutes)
- Walk through the {len(evidence)} findings
- Focus on the most critical issues:
  {chr(10).join(f'  - {e.description}' for e in evidence[:3] if e.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH])}

### Part 3: Business Impact (5 minutes)
- Translate technical findings to business risks
- Discuss potential financial and reputational impact
- Emphasize the urgency of addressing these issues

## Q&A Preparation (10 minutes)

### Common Questions:
1. **"How accurate is this analysis?"**
   - Explain the validation process and confidence levels
   - Mention that manual verification is recommended

2. **"What can we do to protect ourselves?"**
   - Reference the recommendations provided
   - Emphasize the need for comprehensive security programs

3. **"Is this legal?"**
   - Explain the legitimate security research context
   - Mention responsible disclosure practices

4. **"How much would this cost to fix?"**
   - Provide rough estimates based on finding severity
   - Emphasize that prevention is cheaper than remediation

## Closing (5 minutes)
- Summarize key findings and recommendations
- Provide next steps and contact information
- Offer to conduct similar analysis for their organization

## Technical Backup Information

### Analysis Details:
- Analysis ID: {package.demo_id}
- Analysis Date: {package.creation_timestamp}
- Total Findings: {len(evidence)}
- Risk Score: {package.risk_assessment.get('risk_score', 0)}

### Key Statistics:
- Critical Issues: {sum(1 for e in evidence if e.risk_level == RiskLevel.CRITICAL)}
- High Risk Issues: {sum(1 for e in evidence if e.risk_level == RiskLevel.HIGH)}
- Medium Risk Issues: {sum(1 for e in evidence if e.risk_level == RiskLevel.MEDIUM)}

### Recommendations Summary:
{chr(10).join(f'{i+1}. {rec}' for i, rec in enumerate(package.recommendations))}
"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_demo_script(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate demo script for live presentation"""
        
        content = f"""# Live Demonstration Script

## Pre-Demo Setup Checklist
- [ ] Ensure all analysis tools are installed and working
- [ ] Prepare sample binary for analysis
- [ ] Test network connectivity for threat intelligence lookups
- [ ] Have backup slides ready in case of technical issues
- [ ] Prepare handouts with key findings summary

## Demo Script

### Introduction (2 minutes)
"Today I'm going to show you something that will fundamentally change how you think about software security. We're going to take a compiled binary - something that most people think is secure and protected - and in just a few minutes, extract secrets, find vulnerabilities, and even reconstruct the original source code."

### Step 1: Show the Target (1 minute)
"Here's our target binary. It looks like a simple executable file, but let's see what's really inside."

**Action**: Display the binary file properties, size, etc.

### Step 2: Launch Analysis (1 minute)
"I'm now launching our AI-enhanced analysis engine. This tool combines traditional reverse engineering with modern AI capabilities."

**Action**: Run the analysis command
```bash
python tools/ai_enhanced_analyzer.py --target [binary] --full-analysis
```

### Step 3: Real-time Results (5 minutes)
"As you can see, the analysis is already finding issues. Let me walk you through what we're discovering..."

**Key Points to Highlight**:
- Speed of analysis (minutes vs. weeks)
- Automatic vulnerability detection
- Credential extraction
- Business logic reconstruction

### Step 4: Review Critical Findings (8 minutes)
"Let's look at the most critical findings:"

{chr(10).join(f'**Finding {i+1}**: {e.description}' for i, e in enumerate([e for e in evidence if e.risk_level == RiskLevel.CRITICAL][:3], 1))}

**For each finding**:
1. Explain what was found
2. Show the technical evidence
3. Explain the business impact
4. Discuss remediation options

### Step 5: Demonstrate Reconstruction (3 minutes)
"Now let me show you something really impressive - we can actually reconstruct the original source code."

**Action**: Show the reconstructed code side-by-side with disassembly

### Closing (2 minutes)
"This entire analysis took less than 10 minutes. Imagine what a motivated attacker could do with hours or days. The key takeaway is that traditional security assumptions no longer apply in the age of AI-powered analysis."

## Backup Demonstrations
If live demo fails, have these ready:
1. Pre-recorded video of the analysis
2. Static screenshots of key findings
3. Sample reconstructed code examples

## Audience Interaction Points
- Ask about their current security practices
- Poll on their awareness of reverse engineering risks
- Invite questions throughout the demo
- Encourage them to think about their own software

## Technical Notes
- Keep terminal/console visible for transparency
- Explain each step as you perform it
- Don't rush - let the audience absorb the implications
- Be prepared to explain technical concepts in business terms

## Follow-up Actions
- Provide contact information for security assessments
- Offer to analyze their software (with proper agreements)
- Share educational resources about secure development
- Schedule follow-up meetings for interested parties
"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def _generate_training_modules(
        self, 
        package: DemonstrationPackage, 
        evidence: List[AnalysisEvidence], 
        output_path: Path
    ) -> None:
        """Generate training modules"""
        
        content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Training Modules</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        .module {{ background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 10px; }}
        .quiz {{ background: #e3f2fd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .answer {{ display: none; background: #c8e6c9; padding: 10px; margin: 5px 0; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>🎓 Security Awareness Training</h1>
    
    <div class="module">
        <h2>Module 1: Understanding Modern Threats</h2>
        <p>Learn about AI-powered reverse engineering and its implications for software security.</p>
        
        <h3>Key Concepts:</h3>
        <ul>
            <li>Binary analysis and reverse engineering</li>
            <li>Automated vulnerability discovery</li>
            <li>Credential extraction from compiled code</li>
            <li>Business logic reconstruction</li>
        </ul>
        
        <div class="quiz">
            <h4>Quiz Question:</h4>
            <p>What can AI-powered analysis tools extract from compiled binaries?</p>
            <button onclick="showAnswer('q1')">Show Answer</button>
            <div id="q1" class="answer">
                AI tools can extract: hardcoded credentials, API keys, business logic, 
                vulnerabilities, network endpoints, and even reconstruct source code.
            </div>
        </div>
    </div>
    
    <div class="module">
        <h2>Module 2: Real-World Impact</h2>
        <p>Understanding the business and security implications of these capabilities.</p>
        
        <h3>Case Study: Analysis Results</h3>
        <p>Our analysis found {len(evidence)} security issues, including:</p>
        <ul>
            {chr(10).join(f'<li>{e.description}</li>' for e in evidence[:5])}
        </ul>
    </div>
    
    <div class="module">
        <h2>Module 3: Protection Strategies</h2>
        <p>Learn how to protect your organization and software.</p>
        
        <h3>Recommended Actions:</h3>
        <ol>
            {chr(10).join(f'<li>{rec}</li>' for rec in package.recommendations[:8])}
        </ol>
    </div>

    <script>
        function showAnswer(id) {{
            document.getElementById(id).style.display = 'block';
        }}
    </script>
</body>
</html>"""
        
        with open(output_path, 'w') as f:
            f.write(content)


def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Demonstration Generator')
    parser.add_argument('--analysis-results', required=True, help='JSON file with analysis results')
    parser.add_argument('--demo-type', choices=[t.value for t in DemoType], 
                        default='executive_dashboard', help='Type of demonstration to create')
    parser.add_argument('--audience', choices=['executive', 'technical', 'general'], 
                        default='executive', help='Target audience')
    parser.add_argument('--output-dir', help='Output directory for generated files')
    args = parser.parse_args()
    
    # Load analysis results
    try:
        with open(args.analysis_results, 'r') as f:
            analysis_data = json.load(f)
    except Exception as e:
        print(f"Error loading analysis results: {e}")
        return 1
    
    # Create demonstration generator
    output_dir = Path(args.output_dir) if args.output_dir else None
    generator = DemonstrationGenerator(output_dir)
    
    # Configure demonstration
    config = DemoConfig(
        demo_type=DemoType(args.demo_type),
        target_audience=args.audience
    )
    
    # Generate demonstration
    package = generator.create_demonstration(analysis_data, config)
    
    # Print results
    print(f"\n{'='*60}")
    print(f"DEMONSTRATION PACKAGE CREATED")
    print(f"{'='*60}")
    print(f"Demo ID: {package.demo_id}")
    print(f"Demo Type: {package.demo_type.value}")
    print(f"Target Audience: {package.target_audience}")
    print(f"Files Generated: {len(package.generated_files)}")
    
    for file_path in package.generated_files:
        print(f"  - {file_path}")
    
    if package.web_demo_url:
        print(f"\nWeb Demo: {package.web_demo_url}")
    
    print(f"\nOutput Directory: {generator.output_dir}")
    
    return 0


if __name__ == "__main__":
    exit(main())