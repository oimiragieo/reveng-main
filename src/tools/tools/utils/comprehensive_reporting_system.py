#!/usr/bin/env python3
"""
Comprehensive Reporting and Visualization System

This module orchestrates all reporting components to create a unified reporting system
that combines executive reporting, technical documentation, and multi-format exports.

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum

# Import our reporting engines
from executive_reporting_engine import (
    ExecutiveReportingEngine, ExecutiveSummary, RiskMetric, RemediationRoadmap,
    RiskLevel, BusinessImpact
)
from technical_reporting_engine import (
    TechnicalReportingEngine, Finding, Evidence, Methodology, Dataset,
    EvidenceType, ReportFormat
)
from export_integration_engine import (
    ExportIntegrationEngine, ThreatIntelligence, IOCData, TLPLevel,
    ExportFormat, SIEMType, CustomBranding
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReportType(Enum):
    """Types of reports that can be generated"""
    EXECUTIVE_DASHBOARD = "executive_dashboard"
    EXECUTIVE_PDF = "executive_pdf"
    TECHNICAL_HTML = "technical_html"
    TECHNICAL_PDF = "technical_pdf"
    ACADEMIC_PAPER = "academic_paper"
    RESEARCH_PACKAGE = "research_package"
    THREAT_INTELLIGENCE = "threat_intelligence"
    SIEM_INTEGRATION = "siem_integration"
    CUSTOM_REPORT = "custom_report"

@dataclass
class ReportConfiguration:
    """Configuration for report generation"""
    report_types: List[ReportType]
    output_directory: str
    organization_name: str
    analyst_name: str
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_threat_intelligence: bool = True
    export_formats: List[ExportFormat] = None
    siem_integrations: List[SIEMType] = None
    custom_branding: Optional[CustomBranding] = None
    tlp_level: TLPLevel = TLPLevel.AMBER

class ComprehensiveReportingSystem:
    """
    Unified reporting system that orchestrates executive reporting,
    technical documentation, and multi-format exports.
    """
    
    def __init__(self, config: ReportConfiguration):
        """Initialize the comprehensive reporting system"""
        self.config = config
        
        # Initialize component engines
        self.executive_engine = ExecutiveReportingEngine(
            output_dir=f"{config.output_directory}/executive"
        )
        self.technical_engine = TechnicalReportingEngine(
            output_dir=f"{config.output_directory}/technical"
        )
        self.export_engine = ExportIntegrationEngine(
            output_dir=f"{config.output_directory}/exports"
        )
        
        # Create main output directory
        self.output_dir = Path(config.output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Comprehensive reporting system initialized for {config.organization_name}")
    
    def generate_comprehensive_report(self, analysis_results: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate comprehensive report package with all requested formats
        
        Args:
            analysis_results: Complete analysis results from AI-Enhanced analyzer
            
        Returns:
            Dictionary mapping report types to file paths
        """
        generated_reports = {}
        
        try:
            # Extract and prepare data
            executive_summary = self._create_executive_summary(analysis_results)
            findings = self._extract_technical_findings(analysis_results)
            methodology = self._create_methodology_info(analysis_results)
            threat_intel = self._extract_threat_intelligence(analysis_results)
            
            # Generate executive reports
            if ReportType.EXECUTIVE_DASHBOARD in self.config.report_types:
                dashboard_path = self.executive_engine.generate_executive_dashboard(
                    analysis_results, executive_summary
                )
                generated_reports[ReportType.EXECUTIVE_DASHBOARD.value] = dashboard_path
            
            if ReportType.EXECUTIVE_PDF in self.config.report_types:
                pdf_path = self.executive_engine.generate_pdf_report(
                    analysis_results, executive_summary
                )
                generated_reports[ReportType.EXECUTIVE_PDF.value] = pdf_path
            
            # Generate technical reports
            if ReportType.TECHNICAL_HTML in self.config.report_types:
                html_path = self.technical_engine.generate_technical_report(
                    findings, methodology,
                    title=f"Technical Analysis Report - {self.config.organization_name}",
                    author=self.config.analyst_name,
                    format=ReportFormat.HTML
                )
                generated_reports[ReportType.TECHNICAL_HTML.value] = html_path
            
            if ReportType.TECHNICAL_PDF in self.config.report_types:
                pdf_path = self.technical_engine.generate_technical_report(
                    findings, methodology,
                    title=f"Technical Analysis Report - {self.config.organization_name}",
                    author=self.config.analyst_name,
                    format=ReportFormat.PDF
                )
                generated_reports[ReportType.TECHNICAL_PDF.value] = pdf_path
            
            # Generate academic paper
            if ReportType.ACADEMIC_PAPER in self.config.report_types:
                datasets = self._create_dataset_info(analysis_results)
                paper_path = self.technical_engine.generate_academic_paper(
                    findings, methodology, datasets,
                    title="AI-Enhanced Binary Analysis: Security Implications and Findings",
                    authors=[self.config.analyst_name],
                    abstract=self._generate_abstract(executive_summary, findings)
                )
                generated_reports[ReportType.ACADEMIC_PAPER.value] = paper_path
            
            # Generate research package
            if ReportType.RESEARCH_PACKAGE in self.config.report_types:
                datasets = self._create_dataset_info(analysis_results)
                package_path = self.technical_engine.create_reproducible_research_package(
                    findings, methodology, datasets
                )
                generated_reports[ReportType.RESEARCH_PACKAGE.value] = package_path
            
            # Generate threat intelligence exports
            if ReportType.THREAT_INTELLIGENCE in self.config.report_types and threat_intel:
                ti_exports = self._generate_threat_intelligence_exports(threat_intel)
                generated_reports.update(ti_exports)
            
            # Generate SIEM integrations
            if ReportType.SIEM_INTEGRATION in self.config.report_types and threat_intel:
                siem_exports = self._generate_siem_integrations(threat_intel)
                generated_reports.update(siem_exports)
            
            # Generate master index
            index_path = self._generate_master_index(generated_reports, analysis_results)
            generated_reports["master_index"] = index_path
            
            logger.info(f"Comprehensive report generation completed. {len(generated_reports)} files generated.")
            return generated_reports
            
        except Exception as e:
            logger.error(f"Error generating comprehensive report: {e}")
            raise
    
    def generate_live_demonstration_package(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate live demonstration package for presentations
        
        Args:
            analysis_results: Complete analysis results
            
        Returns:
            Path to demonstration package
        """
        demo_dir = self.output_dir / f"live_demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        demo_dir.mkdir(exist_ok=True)
        
        # Generate executive dashboard for live demo
        executive_summary = self._create_executive_summary(analysis_results)
        dashboard_path = self.executive_engine.generate_executive_dashboard(
            analysis_results, executive_summary
        )
        
        # Copy dashboard to demo directory
        import shutil
        shutil.copy2(dashboard_path, demo_dir / "live_dashboard.html")
        
        # Generate presentation slides
        slides_path = self._generate_presentation_slides(analysis_results, demo_dir)
        
        # Generate demo script
        script_path = self._generate_demo_script(analysis_results, demo_dir)
        
        # Create demo package
        package_path = self._create_demo_package(demo_dir)
        
        logger.info(f"Live demonstration package created: {package_path}")
        return str(package_path)
    
    def _create_executive_summary(self, analysis_results: Dict[str, Any]) -> ExecutiveSummary:
        """Create executive summary from analysis results"""
        # Count findings by severity
        critical_count = 0
        high_count = 0
        total_assets = 1  # Default to 1 if not specified
        
        if 'vulnerabilities' in analysis_results:
            vulns = analysis_results['vulnerabilities']
            critical_count = len([v for v in vulns.get('memory_vulnerabilities', []) 
                                if v.get('severity', '').lower() == 'critical'])
            high_count = len([v for v in vulns.get('memory_vulnerabilities', []) 
                            if v.get('severity', '').lower() == 'high'])
        
        # Calculate overall risk score
        risk_factors = []
        if 'corporate_exposure' in analysis_results:
            risk_factors.append(0.8)  # High risk for corporate exposure
        if 'vulnerabilities' in analysis_results:
            risk_factors.append(0.7)  # High risk for vulnerabilities
        if 'threat_intelligence' in analysis_results:
            risk_factors.append(0.6)  # Medium-high risk for threat intel
        
        overall_risk = sum(risk_factors) / len(risk_factors) if risk_factors else 0.3
        
        # Generate key recommendations
        recommendations = []
        if 'corporate_exposure' in analysis_results:
            recommendations.append("Implement immediate credential rotation and secrets management")
        if critical_count > 0:
            recommendations.append("Address critical vulnerabilities with emergency patches")
        if 'threat_intelligence' in analysis_results:
            recommendations.append("Deploy threat hunting capabilities for identified IOCs")
        recommendations.append("Establish continuous security monitoring and assessment")
        
        # Generate executive summary text
        summary_text = f"""
        This comprehensive security analysis reveals significant risks across the analyzed software portfolio.
        The assessment identified {critical_count} critical and {high_count} high-severity vulnerabilities
        requiring immediate attention. Corporate data exposure risks and threat intelligence indicators
        suggest active targeting by sophisticated threat actors. Immediate remediation is recommended
        to prevent potential security breaches and data compromise.
        """
        
        return ExecutiveSummary(
            organization=self.config.organization_name,
            assessment_date=datetime.now(),
            analyst=self.config.analyst_name,
            total_assets_analyzed=total_assets,
            critical_findings=critical_count,
            high_risk_findings=high_count,
            overall_risk_score=overall_risk,
            key_recommendations=recommendations,
            executive_summary=summary_text.strip()
        )
    
    def _extract_technical_findings(self, analysis_results: Dict[str, Any]) -> List[Finding]:
        """Extract technical findings from analysis results"""
        findings = []
        
        # Extract vulnerability findings
        if 'vulnerabilities' in analysis_results:
            vulns = analysis_results['vulnerabilities']
            
            for vuln in vulns.get('memory_vulnerabilities', []):
                evidence = [
                    Evidence(
                        id=f"E_{len(findings)+1}",
                        type=EvidenceType.CODE_SNIPPET,
                        title="Vulnerable Code Location",
                        description=f"Vulnerability found at {vuln.get('location', 'unknown location')}",
                        content=vuln.get('code_snippet', 'Code snippet not available'),
                        confidence=0.9
                    )
                ]
                
                finding = Finding(
                    id=f"F_{len(findings)+1}",
                    title=vuln.get('type', 'Memory Vulnerability'),
                    description=vuln.get('description', 'Memory safety vulnerability detected'),
                    severity=vuln.get('severity', 'Medium'),
                    category="Memory Safety",
                    evidence_chain=evidence,
                    cvss_score=vuln.get('cvss_score'),
                    cwe_id=vuln.get('cwe_id')
                )
                findings.append(finding)
        
        # Extract corporate exposure findings
        if 'corporate_exposure' in analysis_results:
            exposure = analysis_results['corporate_exposure']
            
            for cred in exposure.get('credentials_found', []):
                evidence = [
                    Evidence(
                        id=f"E_{len(findings)+1}",
                        type=EvidenceType.CONFIGURATION,
                        title="Exposed Credential",
                        description=f"Hardcoded credential found in {cred.get('location', 'unknown')}",
                        content=f"Type: {cred.get('type', 'Unknown')}\nLocation: {cred.get('location', 'Unknown')}",
                        confidence=0.95
                    )
                ]
                
                finding = Finding(
                    id=f"F_{len(findings)+1}",
                    title=f"Exposed {cred.get('type', 'Credential')}",
                    description=f"Hardcoded {cred.get('type', 'credential')} discovered in source code",
                    severity="High",
                    category="Data Exposure",
                    evidence_chain=evidence,
                    remediation="Remove hardcoded credentials and implement secure credential management"
                )
                findings.append(finding)
        
        return findings
    
    def _create_methodology_info(self, analysis_results: Dict[str, Any]) -> Methodology:
        """Create methodology information"""
        return Methodology(
            name="AI-Enhanced Universal Binary Analysis",
            description="Comprehensive security analysis using AI-powered decompilation, vulnerability detection, and threat intelligence correlation",
            tools_used=[
                "Ghidra Static Analysis Framework",
                "AI-Enhanced Decompiler",
                "Custom Vulnerability Scanner",
                "Threat Intelligence Correlator",
                "Corporate Exposure Detector"
            ],
            parameters={
                "analysis_depth": "comprehensive",
                "ai_confidence_threshold": 0.8,
                "vulnerability_severity_filter": "medium_and_above",
                "threat_intel_correlation": "enabled"
            },
            validation_method="Multi-stage validation including static analysis, dynamic testing, and manual verification",
            limitations=[
                "Limited to static analysis for certain components",
                "AI models may produce false positives",
                "Obfuscated code may reduce analysis accuracy"
            ],
            references=[
                "NIST Cybersecurity Framework",
                "OWASP Top 10",
                "MITRE ATT&CK Framework",
                "IEEE Security & Privacy Best Practices"
            ]
        )
    
    def _extract_threat_intelligence(self, analysis_results: Dict[str, Any]) -> Optional[ThreatIntelligence]:
        """Extract threat intelligence from analysis results"""
        if 'threat_intelligence' not in analysis_results:
            return None
        
        threat_data = analysis_results['threat_intelligence']
        iocs = []
        
        # Extract IOCs from various sources
        if 'iocs_extracted' in threat_data:
            for ioc_data in threat_data['iocs_extracted']:
                ioc = IOCData(
                    type=ioc_data.get('type', 'unknown'),
                    value=ioc_data.get('value', ''),
                    description=ioc_data.get('description', ''),
                    confidence=ioc_data.get('confidence', 0.5),
                    tlp_level=self.config.tlp_level,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    tags=ioc_data.get('tags', []),
                    source="AI-Enhanced Analysis",
                    context=ioc_data.get('context', {})
                )
                iocs.append(ioc)
        
        if not iocs:
            return None
        
        return ThreatIntelligence(
            id=f"TI_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            name=f"Threat Intelligence - {self.config.organization_name}",
            description="Threat intelligence extracted from binary analysis",
            threat_actor=threat_data.get('apt_attribution', {}).get('group'),
            malware_family=threat_data.get('malware_classification', {}).get('family'),
            attack_patterns=threat_data.get('mitre_attack_mapping', {}).get('techniques', []),
            iocs=iocs,
            vulnerabilities=[],
            confidence=threat_data.get('confidence', 0.7),
            tlp_level=self.config.tlp_level,
            created=datetime.now(),
            modified=datetime.now()
        )
    
    def _create_dataset_info(self, analysis_results: Dict[str, Any]) -> List[Dataset]:
        """Create dataset information for research"""
        datasets = []
        
        # Create dataset entry for analyzed binary
        dataset = Dataset(
            name="Binary Analysis Dataset",
            description="Collection of analyzed binaries and their security characteristics",
            size=1,  # Single binary for now
            format="Mixed (PE, ELF, etc.)",
            source="Security Assessment",
            collection_date=datetime.now(),
            preprocessing_steps=[
                "Malware scanning",
                "File format validation",
                "Metadata extraction"
            ],
            file_path="data/analyzed_binaries.zip",
            checksum="sha256:placeholder"
        )
        datasets.append(dataset)
        
        return datasets
    
    def _generate_abstract(self, executive_summary: ExecutiveSummary, findings: List[Finding]) -> str:
        """Generate abstract for academic paper"""
        return f"""
        This paper presents the results of an AI-enhanced universal binary analysis study
        conducted on software from {executive_summary.organization}. The analysis identified
        {len(findings)} significant security findings, including {executive_summary.critical_findings}
        critical vulnerabilities. Our methodology demonstrates the effectiveness of AI-powered
        reverse engineering in identifying security risks that traditional analysis might miss.
        The findings highlight the urgent need for enhanced security practices in modern
        software development and deployment.
        """
    
    def _generate_threat_intelligence_exports(self, threat_intel: ThreatIntelligence) -> Dict[str, str]:
        """Generate threat intelligence exports"""
        exports = {}
        
        if self.config.export_formats:
            for export_format in self.config.export_formats:
                if export_format == ExportFormat.STIX2_JSON:
                    path = self.export_engine.export_stix2(threat_intel, export_format)
                    exports[f"stix2_json"] = path
                elif export_format == ExportFormat.MISP_JSON:
                    path = self.export_engine.export_misp(threat_intel)
                    exports[f"misp_json"] = path
                elif export_format == ExportFormat.YARA_RULES:
                    path = self.export_engine.export_yara_rules(threat_intel)
                    exports[f"yara_rules"] = path
                elif export_format == ExportFormat.IOC_CSV:
                    path = self.export_engine.export_ioc_csv(threat_intel)
                    exports[f"ioc_csv"] = path
        
        return exports
    
    def _generate_siem_integrations(self, threat_intel: ThreatIntelligence) -> Dict[str, str]:
        """Generate SIEM integration files"""
        integrations = {}
        
        if self.config.siem_integrations:
            for siem_type in self.config.siem_integrations:
                path = self.export_engine.export_siem_format(threat_intel, siem_type)
                integrations[f"siem_{siem_type.value}"] = path
        
        return integrations
    
    def _generate_master_index(self, generated_reports: Dict[str, str], 
                             analysis_results: Dict[str, Any]) -> str:
        """Generate master index HTML file"""
        index_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Security Analysis Report - {self.config.organization_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .section {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .report-link {{ display: block; padding: 10px; margin: 5px 0; background-color: #f8f9fa; border-radius: 5px; text-decoration: none; color: #007bff; }}
        .report-link:hover {{ background-color: #e9ecef; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Comprehensive Security Analysis Report</h1>
        <p>Organization: {self.config.organization_name}</p>
        <p>Analyst: {self.config.analyst_name}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Executive Reports</h2>
        """
        
        for report_type, path in generated_reports.items():
            if "executive" in report_type:
                index_html += f'<a href="{Path(path).name}" class="report-link">{report_type.replace("_", " ").title()}</a>\n'
        
        index_html += """
    </div>
    
    <div class="section">
        <h2>Technical Reports</h2>
        """
        
        for report_type, path in generated_reports.items():
            if "technical" in report_type or "academic" in report_type or "research" in report_type:
                index_html += f'<a href="{Path(path).name}" class="report-link">{report_type.replace("_", " ").title()}</a>\n'
        
        index_html += """
    </div>
    
    <div class="section">
        <h2>Threat Intelligence & Exports</h2>
        """
        
        for report_type, path in generated_reports.items():
            if any(x in report_type for x in ["stix", "misp", "yara", "ioc", "siem"]):
                index_html += f'<a href="{Path(path).name}" class="report-link">{report_type.replace("_", " ").title()}</a>\n'
        
        index_html += """
    </div>
</body>
</html>
        """
        
        index_path = self.output_dir / f"index_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(index_html)
        
        return str(index_path)
    
    def _generate_presentation_slides(self, analysis_results: Dict[str, Any], demo_dir: Path) -> str:
        """Generate presentation slides for live demo"""
        # This would generate PowerPoint or HTML slides
        # For now, create a simple HTML presentation
        slides_path = demo_dir / "presentation_slides.html"
        
        slides_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Presentation</title>
    <style>
        .slide { width: 100%; height: 100vh; padding: 50px; display: none; }
        .slide.active { display: block; }
        .slide h1 { font-size: 3em; color: #2c3e50; }
        .slide h2 { font-size: 2em; color: #34495e; }
    </style>
</head>
<body>
    <div class="slide active">
        <h1>Security Analysis Results</h1>
        <h2>Executive Overview</h2>
    </div>
    <div class="slide">
        <h1>Key Findings</h1>
        <h2>Critical Vulnerabilities Identified</h2>
    </div>
    <div class="slide">
        <h1>Threat Intelligence</h1>
        <h2>IOCs and Attribution</h2>
    </div>
</body>
</html>
        """
        
        with open(slides_path, 'w') as f:
            f.write(slides_content)
        
        return str(slides_path)
    
    def _generate_demo_script(self, analysis_results: Dict[str, Any], demo_dir: Path) -> str:
        """Generate demo script for presentations"""
        script_path = demo_dir / "demo_script.md"
        
        script_content = f"""
# Live Demonstration Script

## Introduction (2 minutes)
- Welcome and overview of AI-Enhanced Binary Analysis
- Demonstration objectives and agenda

## Executive Dashboard (5 minutes)
- Open live_dashboard.html
- Walk through risk metrics and visualizations
- Highlight critical findings and business impact

## Technical Deep Dive (10 minutes)
- Review technical findings and evidence
- Demonstrate proof-of-concepts
- Show remediation recommendations

## Threat Intelligence (5 minutes)
- Present IOCs and threat attribution
- Discuss SIEM integration capabilities
- Show export formats and sharing options

## Q&A and Wrap-up (3 minutes)
- Address questions
- Provide contact information and next steps

## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        return str(script_path)
    
    def _create_demo_package(self, demo_dir: Path) -> str:
        """Create demo package ZIP file"""
        import zipfile
        
        zip_path = self.output_dir / f"demo_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in demo_dir.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(demo_dir)
                    zipf.write(file_path, arcname)
        
        return str(zip_path)

# Example usage
if __name__ == "__main__":
    # Create sample configuration
    config = ReportConfiguration(
        report_types=[
            ReportType.EXECUTIVE_DASHBOARD,
            ReportType.EXECUTIVE_PDF,
            ReportType.TECHNICAL_HTML,
            ReportType.ACADEMIC_PAPER,
            ReportType.THREAT_INTELLIGENCE
        ],
        output_directory="reports/comprehensive",
        organization_name="ACME Corporation",
        analyst_name="Security Research Team",
        export_formats=[ExportFormat.STIX2_JSON, ExportFormat.IOC_CSV],
        siem_integrations=[SIEMType.SPLUNK, SIEMType.ELASTIC]
    )
    
    # Initialize reporting system
    reporting_system = ComprehensiveReportingSystem(config)
    
    # Sample analysis results
    sample_results = {
        'vulnerabilities': {
            'memory_vulnerabilities': [
                {
                    'type': 'Buffer Overflow',
                    'severity': 'Critical',
                    'description': 'Stack buffer overflow in authentication function',
                    'location': 'auth.c:156',
                    'cvss_score': 9.8,
                    'cwe_id': 'CWE-121'
                }
            ]
        },
        'corporate_exposure': {
            'credentials_found': [
                {
                    'type': 'AWS API Key',
                    'location': 'config.js:42'
                }
            ]
        },
        'threat_intelligence': {
            'iocs_extracted': [
                {
                    'type': 'ip',
                    'value': '192.168.1.100',
                    'description': 'C2 server',
                    'confidence': 0.9,
                    'tags': ['malware', 'c2']
                }
            ]
        }
    }
    
    try:
        # Generate comprehensive report
        reports = reporting_system.generate_comprehensive_report(sample_results)
        print("Generated reports:")
        for report_type, path in reports.items():
            print(f"  {report_type}: {path}")
        
        # Generate live demo package
        demo_package = reporting_system.generate_live_demonstration_package(sample_results)
        print(f"Demo package: {demo_package}")
        
    except Exception as e:
        print(f"Error: {e}")
        logger.error(f"Error in example usage: {e}")