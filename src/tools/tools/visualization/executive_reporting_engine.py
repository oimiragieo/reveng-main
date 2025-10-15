#!/usr/bin/env python3
"""
Executive Reporting and Risk Visualization Engine

This module creates executive dashboard templates with risk matrices and business impact,
builds automated PowerPoint and PDF generation for C-suite presentations, and implements
risk scoring algorithms and remediation roadmaps.

Requirements: 7.1, 7.5
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import seaborn as sns
from jinja2 import Template, Environment, FileSystemLoader
import pandas as pd
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

class BusinessImpact(Enum):
    """Business impact categories"""
    CATASTROPHIC = "Catastrophic"
    MAJOR = "Major"
    MODERATE = "Moderate"
    MINOR = "Minor"
    NEGLIGIBLE = "Negligible"

@dataclass
class RiskMetric:
    """Individual risk metric"""
    category: str
    description: str
    risk_level: RiskLevel
    business_impact: BusinessImpact
    likelihood: float  # 0.0 to 1.0
    impact_score: float  # 0.0 to 1.0
    risk_score: float  # Calculated composite score
    evidence: List[str]
    remediation_effort: str  # Low, Medium, High
    timeline: str  # Immediate, Short-term, Long-term

@dataclass
class ExecutiveSummary:
    """Executive summary data structure"""
    organization: str
    assessment_date: datetime
    analyst: str
    total_assets_analyzed: int
    critical_findings: int
    high_risk_findings: int
    overall_risk_score: float
    key_recommendations: List[str]
    executive_summary: str

@dataclass
class RemediationRoadmap:
    """Remediation roadmap item"""
    priority: int
    task: str
    description: str
    effort: str
    timeline: str
    cost_estimate: str
    business_justification: str
    success_metrics: List[str]

class ExecutiveReportingEngine:
    """
    Executive reporting and risk visualization engine for creating
    C-suite presentations and risk assessments.
    """
    
    def __init__(self, output_dir: str = "reports/executive"):
        """Initialize the executive reporting engine"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment for templates
        self.template_dir = Path("templates/executive")
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.jinja_env = Environment(loader=FileSystemLoader(str(self.template_dir)))
        
        # Create default templates if they don't exist
        self._create_default_templates()
        
        # Risk scoring weights
        self.risk_weights = {
            'likelihood': 0.4,
            'impact': 0.6
        }
        
        logger.info(f"Executive reporting engine initialized with output directory: {self.output_dir}")
    
    def calculate_risk_score(self, likelihood: float, impact: float) -> float:
        """
        Calculate composite risk score from likelihood and impact
        
        Args:
            likelihood: Probability of occurrence (0.0 to 1.0)
            impact: Business impact severity (0.0 to 1.0)
            
        Returns:
            Composite risk score (0.0 to 1.0)
        """
        return (likelihood * self.risk_weights['likelihood'] + 
                impact * self.risk_weights['impact'])
    
    def categorize_risk_level(self, risk_score: float) -> RiskLevel:
        """
        Categorize risk score into risk level
        
        Args:
            risk_score: Composite risk score (0.0 to 1.0)
            
        Returns:
            Risk level category
        """
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def create_risk_matrix(self, risks: List[RiskMetric], save_path: Optional[str] = None) -> str:
        """
        Create risk matrix visualization
        
        Args:
            risks: List of risk metrics
            save_path: Optional path to save the plot
            
        Returns:
            Path to saved risk matrix image
        """
        # Set up the plot
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Define risk matrix colors
        colors_matrix = {
            (0, 0): '#90EE90',  # Light green
            (0, 1): '#FFFF99',  # Light yellow
            (0, 2): '#FFB366',  # Light orange
            (0, 3): '#FF9999',  # Light red
            (0, 4): '#FF6666',  # Red
            (1, 0): '#FFFF99',  # Light yellow
            (1, 1): '#FFB366',  # Light orange
            (1, 2): '#FF9999',  # Light red
            (1, 3): '#FF6666',  # Red
            (1, 4): '#CC0000',  # Dark red
            (2, 0): '#FFB366',  # Light orange
            (2, 1): '#FF9999',  # Light red
            (2, 2): '#FF6666',  # Red
            (2, 3): '#CC0000',  # Dark red
            (2, 4): '#990000',  # Very dark red
            (3, 0): '#FF9999',  # Light red
            (3, 1): '#FF6666',  # Red
            (3, 2): '#CC0000',  # Dark red
            (3, 3): '#990000',  # Very dark red
            (3, 4): '#660000',  # Darkest red
            (4, 0): '#FF6666',  # Red
            (4, 1): '#CC0000',  # Dark red
            (4, 2): '#990000',  # Very dark red
            (4, 3): '#660000',  # Darkest red
            (4, 4): '#330000',  # Black red
        }
        
        # Create risk matrix background
        for i in range(5):
            for j in range(5):
                rect = patches.Rectangle((j, i), 1, 1, 
                                       facecolor=colors_matrix.get((i, j), '#FFFFFF'),
                                       edgecolor='black', linewidth=1)
                ax.add_patch(rect)
        
        # Plot risks on matrix
        for risk in risks:
            likelihood_pos = int(risk.likelihood * 4)
            impact_pos = int(risk.impact_score * 4)
            
            # Add risk point
            ax.scatter(likelihood_pos + 0.5, impact_pos + 0.5, 
                      s=100, c='black', marker='o', alpha=0.7)
            
            # Add risk label
            ax.annotate(risk.category[:10], 
                       (likelihood_pos + 0.5, impact_pos + 0.5),
                       xytext=(5, 5), textcoords='offset points',
                       fontsize=8, ha='left')
        
        # Set labels and title
        ax.set_xlim(0, 5)
        ax.set_ylim(0, 5)
        ax.set_xlabel('Likelihood', fontsize=12, fontweight='bold')
        ax.set_ylabel('Impact', fontsize=12, fontweight='bold')
        ax.set_title('Risk Assessment Matrix', fontsize=16, fontweight='bold')
        
        # Set tick labels
        ax.set_xticks([0.5, 1.5, 2.5, 3.5, 4.5])
        ax.set_xticklabels(['Very Low', 'Low', 'Medium', 'High', 'Very High'])
        ax.set_yticks([0.5, 1.5, 2.5, 3.5, 4.5])
        ax.set_yticklabels(['Very Low', 'Low', 'Medium', 'High', 'Very High'])
        
        # Add legend
        legend_elements = [
            patches.Patch(color='#90EE90', label='Low Risk'),
            patches.Patch(color='#FFFF99', label='Medium Risk'),
            patches.Patch(color='#FFB366', label='High Risk'),
            patches.Patch(color='#FF6666', label='Critical Risk')
        ]
        ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1.05, 1))
        
        plt.tight_layout()
        
        # Save the plot
        if not save_path:
            save_path = str(self.output_dir / f"risk_matrix_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Risk matrix saved to: {save_path}")
        return save_path
    
    def create_risk_distribution_chart(self, risks: List[RiskMetric], save_path: Optional[str] = None) -> str:
        """
        Create risk distribution pie chart
        
        Args:
            risks: List of risk metrics
            save_path: Optional path to save the chart
            
        Returns:
            Path to saved chart image
        """
        # Count risks by level
        risk_counts = {}
        for risk in risks:
            level = self.categorize_risk_level(risk.risk_score)
            risk_counts[level.value] = risk_counts.get(level.value, 0) + 1
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(10, 8))
        
        labels = list(risk_counts.keys())
        sizes = list(risk_counts.values())
        colors = ['#FF0000', '#FF8000', '#FFFF00', '#00FF00', '#0080FF'][:len(labels)]
        
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                                         startangle=90, textprops={'fontsize': 12})
        
        ax.set_title('Risk Distribution by Severity', fontsize=16, fontweight='bold')
        
        # Save the chart
        if not save_path:
            save_path = str(self.output_dir / f"risk_distribution_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Risk distribution chart saved to: {save_path}")
        return save_path    

    def generate_executive_dashboard(self, analysis_results: Dict[str, Any], 
                                   executive_summary: ExecutiveSummary) -> str:
        """
        Generate comprehensive executive dashboard
        
        Args:
            analysis_results: Complete analysis results
            executive_summary: Executive summary data
            
        Returns:
            Path to generated dashboard HTML file
        """
        # Extract risk metrics from analysis results
        risks = self._extract_risk_metrics(analysis_results)
        
        # Create visualizations
        risk_matrix_path = self.create_risk_matrix(risks)
        risk_distribution_path = self.create_risk_distribution_chart(risks)
        
        # Generate remediation roadmap
        roadmap = self._generate_remediation_roadmap(risks)
        
        # Prepare dashboard data
        dashboard_data = {
            'executive_summary': executive_summary,
            'risks': risks,
            'risk_matrix_path': risk_matrix_path,
            'risk_distribution_path': risk_distribution_path,
            'roadmap': roadmap,
            'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_risks': len(risks),
            'critical_risks': len([r for r in risks if self.categorize_risk_level(r.risk_score) == RiskLevel.CRITICAL]),
            'high_risks': len([r for r in risks if self.categorize_risk_level(r.risk_score) == RiskLevel.HIGH])
        }
        
        # Render dashboard template
        template = self.jinja_env.get_template('executive_dashboard.html')
        dashboard_html = template.render(**dashboard_data)
        
        # Save dashboard
        dashboard_path = self.output_dir / f"executive_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            f.write(dashboard_html)
        
        logger.info(f"Executive dashboard generated: {dashboard_path}")
        return str(dashboard_path)
    
    def generate_pdf_report(self, analysis_results: Dict[str, Any], 
                           executive_summary: ExecutiveSummary) -> str:
        """
        Generate PDF executive report
        
        Args:
            analysis_results: Complete analysis results
            executive_summary: Executive summary data
            
        Returns:
            Path to generated PDF report
        """
        # Extract risk metrics
        risks = self._extract_risk_metrics(analysis_results)
        
        # Create PDF document
        pdf_path = self.output_dir / f"executive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
        # Build PDF content
        story = []
        
        # Title page
        story.append(Paragraph("Executive Security Assessment Report", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"Organization: {executive_summary.organization}", styles['Heading2']))
        story.append(Paragraph(f"Assessment Date: {executive_summary.assessment_date.strftime('%Y-%m-%d')}", styles['Normal']))
        story.append(Paragraph(f"Analyst: {executive_summary.analyst}", styles['Normal']))
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Paragraph(executive_summary.executive_summary, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Key Metrics
        story.append(Paragraph("Key Metrics", styles['Heading2']))
        metrics_data = [
            ['Metric', 'Value'],
            ['Total Assets Analyzed', str(executive_summary.total_assets_analyzed)],
            ['Critical Findings', str(executive_summary.critical_findings)],
            ['High Risk Findings', str(executive_summary.high_risk_findings)],
            ['Overall Risk Score', f"{executive_summary.overall_risk_score:.2f}/1.0"]
        ]
        
        metrics_table = Table(metrics_data)
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 30))
        
        # Risk Summary
        story.append(Paragraph("Risk Summary", styles['Heading2']))
        
        # Create risk summary table
        risk_summary_data = [['Risk Level', 'Count', 'Percentage']]
        total_risks = len(risks)
        
        for level in RiskLevel:
            count = len([r for r in risks if self.categorize_risk_level(r.risk_score) == level])
            percentage = (count / total_risks * 100) if total_risks > 0 else 0
            risk_summary_data.append([level.value, str(count), f"{percentage:.1f}%"])
        
        risk_table = Table(risk_summary_data)
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 20))
        
        # Key Recommendations
        story.append(Paragraph("Key Recommendations", styles['Heading2']))
        for i, recommendation in enumerate(executive_summary.key_recommendations, 1):
            story.append(Paragraph(f"{i}. {recommendation}", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"PDF executive report generated: {pdf_path}")
        return str(pdf_path)
    
    def _extract_risk_metrics(self, analysis_results: Dict[str, Any]) -> List[RiskMetric]:
        """
        Extract risk metrics from analysis results
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            List of risk metrics
        """
        risks = []
        
        # Extract corporate exposure risks
        if 'corporate_exposure' in analysis_results:
            exposure = analysis_results['corporate_exposure']
            
            # Credential exposures
            for cred in exposure.get('credentials_found', []):
                risk = RiskMetric(
                    category="Credential Exposure",
                    description=f"Hardcoded credentials found: {cred.get('type', 'Unknown')}",
                    risk_level=RiskLevel.HIGH,
                    business_impact=BusinessImpact.MAJOR,
                    likelihood=0.9,
                    impact_score=0.8,
                    risk_score=self.calculate_risk_score(0.9, 0.8),
                    evidence=[cred.get('location', 'Unknown location')],
                    remediation_effort="Medium",
                    timeline="Immediate"
                )
                risks.append(risk)
            
            # API endpoint exposures
            for endpoint in exposure.get('api_endpoints_discovered', []):
                risk = RiskMetric(
                    category="API Exposure",
                    description=f"Exposed API endpoint: {endpoint.get('url', 'Unknown')}",
                    risk_level=RiskLevel.MEDIUM,
                    business_impact=BusinessImpact.MODERATE,
                    likelihood=0.7,
                    impact_score=0.6,
                    risk_score=self.calculate_risk_score(0.7, 0.6),
                    evidence=[endpoint.get('method', 'Unknown method')],
                    remediation_effort="Low",
                    timeline="Short-term"
                )
                risks.append(risk)
        
        # Extract vulnerability risks
        if 'vulnerabilities' in analysis_results:
            vulns = analysis_results['vulnerabilities']
            
            # Memory vulnerabilities
            for vuln in vulns.get('memory_vulnerabilities', []):
                severity_map = {
                    'Critical': (RiskLevel.CRITICAL, BusinessImpact.CATASTROPHIC, 0.8, 0.9),
                    'High': (RiskLevel.HIGH, BusinessImpact.MAJOR, 0.7, 0.8),
                    'Medium': (RiskLevel.MEDIUM, BusinessImpact.MODERATE, 0.5, 0.6),
                    'Low': (RiskLevel.LOW, BusinessImpact.MINOR, 0.3, 0.4)
                }
                
                severity = vuln.get('severity', 'Medium')
                risk_level, impact, likelihood, impact_score = severity_map.get(severity, severity_map['Medium'])
                
                risk = RiskMetric(
                    category="Memory Vulnerability",
                    description=f"{vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}",
                    risk_level=risk_level,
                    business_impact=impact,
                    likelihood=likelihood,
                    impact_score=impact_score,
                    risk_score=self.calculate_risk_score(likelihood, impact_score),
                    evidence=[vuln.get('location', 'Unknown location')],
                    remediation_effort="High",
                    timeline="Immediate" if severity in ['Critical', 'High'] else "Short-term"
                )
                risks.append(risk)
        
        # Extract threat intelligence risks
        if 'threat_intelligence' in analysis_results:
            threat_intel = analysis_results['threat_intelligence']
            
            # APT attribution
            if threat_intel.get('apt_attribution'):
                apt = threat_intel['apt_attribution']
                risk = RiskMetric(
                    category="APT Attribution",
                    description=f"Potential APT activity detected: {apt.get('group', 'Unknown')}",
                    risk_level=RiskLevel.CRITICAL,
                    business_impact=BusinessImpact.CATASTROPHIC,
                    likelihood=0.6,
                    impact_score=0.9,
                    risk_score=self.calculate_risk_score(0.6, 0.9),
                    evidence=[f"Confidence: {apt.get('confidence', 0):.2f}"],
                    remediation_effort="High",
                    timeline="Immediate"
                )
                risks.append(risk)
        
        return risks
    
    def _generate_remediation_roadmap(self, risks: List[RiskMetric]) -> List[RemediationRoadmap]:
        """
        Generate remediation roadmap from risks
        
        Args:
            risks: List of risk metrics
            
        Returns:
            Prioritized remediation roadmap
        """
        roadmap = []
        
        # Sort risks by score (highest first)
        sorted_risks = sorted(risks, key=lambda r: r.risk_score, reverse=True)
        
        for i, risk in enumerate(sorted_risks[:10], 1):  # Top 10 risks
            remediation = RemediationRoadmap(
                priority=i,
                task=f"Address {risk.category}",
                description=f"Remediate: {risk.description}",
                effort=risk.remediation_effort,
                timeline=risk.timeline,
                cost_estimate=self._estimate_cost(risk.remediation_effort),
                business_justification=f"Reduces {risk.business_impact.value.lower()} business impact",
                success_metrics=[
                    "Risk score reduction",
                    "Vulnerability elimination",
                    "Compliance improvement"
                ]
            )
            roadmap.append(remediation)
        
        return roadmap
    
    def _estimate_cost(self, effort: str) -> str:
        """Estimate cost based on effort level"""
        cost_map = {
            "Low": "$5,000 - $15,000",
            "Medium": "$15,000 - $50,000",
            "High": "$50,000 - $150,000"
        }
        return cost_map.get(effort, "$10,000 - $30,000")
    
    def _create_default_templates(self):
        """Create default HTML templates"""
        dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metrics { display: flex; justify-content: space-around; margin: 20px 0; }
        .metric { background-color: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric h3 { margin: 0; color: #2c3e50; }
        .metric .value { font-size: 2em; font-weight: bold; color: #e74c3c; }
        .chart { text-align: center; margin: 20px 0; }
        .chart img { max-width: 100%; height: auto; }
        .roadmap { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .roadmap-item { border-left: 4px solid #3498db; padding: 10px; margin: 10px 0; background-color: #ecf0f1; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #f39c12; }
        .medium { border-left-color: #f1c40f; }
        .low { border-left-color: #27ae60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Executive Security Assessment Dashboard</h1>
        <p>Organization: {{ executive_summary.organization }}</p>
        <p>Assessment Date: {{ executive_summary.assessment_date.strftime('%Y-%m-%d') }}</p>
        <p>Generated: {{ generation_date }}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>{{ executive_summary.executive_summary }}</p>
    </div>
    
    <div class="metrics">
        <div class="metric">
            <h3>Total Risks</h3>
            <div class="value">{{ total_risks }}</div>
        </div>
        <div class="metric">
            <h3>Critical Risks</h3>
            <div class="value">{{ critical_risks }}</div>
        </div>
        <div class="metric">
            <h3>High Risks</h3>
            <div class="value">{{ high_risks }}</div>
        </div>
        <div class="metric">
            <h3>Overall Score</h3>
            <div class="value">{{ "%.2f"|format(executive_summary.overall_risk_score) }}</div>
        </div>
    </div>
    
    <div class="chart">
        <h2>Risk Assessment Matrix</h2>
        <img src="{{ risk_matrix_path }}" alt="Risk Matrix">
    </div>
    
    <div class="chart">
        <h2>Risk Distribution</h2>
        <img src="{{ risk_distribution_path }}" alt="Risk Distribution">
    </div>
    
    <div class="roadmap">
        <h2>Remediation Roadmap</h2>
        {% for item in roadmap %}
        <div class="roadmap-item {{ item.effort.lower() }}">
            <h4>Priority {{ item.priority }}: {{ item.task }}</h4>
            <p><strong>Description:</strong> {{ item.description }}</p>
            <p><strong>Timeline:</strong> {{ item.timeline }} | <strong>Effort:</strong> {{ item.effort }} | <strong>Cost:</strong> {{ item.cost_estimate }}</p>
            <p><strong>Business Justification:</strong> {{ item.business_justification }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="summary">
        <h2>Key Recommendations</h2>
        <ul>
        {% for recommendation in executive_summary.key_recommendations %}
            <li>{{ recommendation }}</li>
        {% endfor %}
        </ul>
    </div>
</body>
</html>
        """
        
        template_path = self.template_dir / "executive_dashboard.html"
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(dashboard_template)
        
        logger.info(f"Default dashboard template created: {template_path}")

# Example usage and testing
if __name__ == "__main__":
    # Initialize the engine
    engine = ExecutiveReportingEngine()
    
    # Create sample data for testing
    sample_executive_summary = ExecutiveSummary(
        organization="ACME Corporation",
        assessment_date=datetime.now(),
        analyst="Security Team",
        total_assets_analyzed=25,
        critical_findings=3,
        high_risk_findings=8,
        overall_risk_score=0.75,
        key_recommendations=[
            "Implement immediate credential rotation for exposed API keys",
            "Deploy memory protection mechanisms for critical applications",
            "Establish threat intelligence monitoring for APT indicators",
            "Create incident response procedures for security breaches"
        ],
        executive_summary="This assessment reveals significant security risks across the analyzed software portfolio, with critical vulnerabilities in credential management and memory safety requiring immediate attention."
    )
    
    # Sample analysis results
    sample_analysis_results = {
        'corporate_exposure': {
            'credentials_found': [
                {'type': 'AWS API Key', 'location': 'config.js:42'},
                {'type': 'Database Password', 'location': 'app.properties:15'}
            ],
            'api_endpoints_discovered': [
                {'url': '/api/admin/users', 'method': 'GET'},
                {'url': '/api/internal/config', 'method': 'POST'}
            ]
        },
        'vulnerabilities': {
            'memory_vulnerabilities': [
                {'type': 'Buffer Overflow', 'severity': 'Critical', 'description': 'Stack buffer overflow in login function', 'location': 'auth.c:156'},
                {'type': 'Use After Free', 'severity': 'High', 'description': 'Memory use after free in cleanup routine', 'location': 'cleanup.c:89'}
            ]
        },
        'threat_intelligence': {
            'apt_attribution': {
                'group': 'APT29',
                'confidence': 0.85
            }
        }
    }
    
    # Generate reports
    try:
        dashboard_path = engine.generate_executive_dashboard(sample_analysis_results, sample_executive_summary)
        pdf_path = engine.generate_pdf_report(sample_analysis_results, sample_executive_summary)
        
        print(f"Executive dashboard generated: {dashboard_path}")
        print(f"PDF report generated: {pdf_path}")
        
    except Exception as e:
        logger.error(f"Error generating reports: {e}")
        print(f"Error: {e}")