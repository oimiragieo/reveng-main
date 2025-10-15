#!/usr/bin/env python3
"""
Technical Documentation and Research Reporting Engine

This module generates detailed technical reports with evidence chains and proof-of-concepts,
creates academic paper templates with LaTeX and IEEE formatting, and implements reproducible
research documentation with datasets and methodologies.

Requirements: 7.2, 7.4
"""

import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import markdown
from jinja2 import Template, Environment, FileSystemLoader
import pandas as pd
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import zipfile
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EvidenceType(Enum):
    """Types of evidence"""
    CODE_SNIPPET = "Code Snippet"
    BINARY_ANALYSIS = "Binary Analysis"
    NETWORK_TRAFFIC = "Network Traffic"
    MEMORY_DUMP = "Memory Dump"
    CONFIGURATION = "Configuration"
    LOG_ENTRY = "Log Entry"
    SCREENSHOT = "Screenshot"
    PROOF_OF_CONCEPT = "Proof of Concept"

class ReportFormat(Enum):
    """Report output formats"""
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"
    LATEX = "latex"
    DOCX = "docx"
    JSON = "json"

@dataclass
class Evidence:
    """Evidence item for technical reports"""
    id: str
    type: EvidenceType
    title: str
    description: str
    content: str
    file_path: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None
    confidence: float = 1.0

@dataclass
class Finding:
    """Technical finding with evidence chain"""
    id: str
    title: str
    description: str
    severity: str
    category: str
    evidence_chain: List[Evidence]
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None

@dataclass
class Methodology:
    """Research methodology documentation"""
    name: str
    description: str
    tools_used: List[str]
    parameters: Dict[str, Any]
    validation_method: str
    limitations: List[str]
    references: List[str]

@dataclass
class Dataset:
    """Research dataset information"""
    name: str
    description: str
    size: int
    format: str
    source: str
    collection_date: datetime
    preprocessing_steps: List[str]
    file_path: str
    checksum: str

class TechnicalReportingEngine:
    """
    Technical documentation and research reporting engine for creating
    detailed technical reports, academic papers, and reproducible research.
    """
    
    def __init__(self, output_dir: str = "reports/technical"):
        """Initialize the technical reporting engine"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize template directories
        self.template_dir = Path("templates/technical")
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        self.latex_template_dir = Path("templates/latex")
        self.latex_template_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(loader=FileSystemLoader([
            str(self.template_dir),
            str(self.latex_template_dir)
        ]))
        
        # Create default templates
        self._create_default_templates()
        
        logger.info(f"Technical reporting engine initialized with output directory: {self.output_dir}")
    
    def generate_technical_report(self, findings: List[Finding], 
                                methodology: Methodology,
                                title: str = "Technical Security Analysis Report",
                                author: str = "Security Research Team",
                                format: ReportFormat = ReportFormat.HTML) -> str:
        """
        Generate comprehensive technical report
        
        Args:
            findings: List of technical findings
            methodology: Research methodology
            title: Report title
            author: Report author
            format: Output format
            
        Returns:
            Path to generated report
        """
        report_data = {
            'title': title,
            'author': author,
            'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': findings,
            'methodology': methodology,
            'total_findings': len(findings),
            'critical_findings': len([f for f in findings if f.severity.lower() == 'critical']),
            'high_findings': len([f for f in findings if f.severity.lower() == 'high']),
            'evidence_count': sum(len(f.evidence_chain) for f in findings)
        }
        
        if format == ReportFormat.HTML:
            return self._generate_html_report(report_data)
        elif format == ReportFormat.PDF:
            return self._generate_pdf_technical_report(report_data)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown_report(report_data)
        elif format == ReportFormat.LATEX:
            return self._generate_latex_report(report_data)
        elif format == ReportFormat.JSON:
            return self._generate_json_report(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def generate_academic_paper(self, findings: List[Finding],
                              methodology: Methodology,
                              datasets: List[Dataset],
                              title: str = "AI-Enhanced Binary Analysis: A Comprehensive Study",
                              authors: List[str] = None,
                              abstract: str = "",
                              keywords: List[str] = None,
                              conference: str = "IEEE") -> str:
        """
        Generate academic paper in LaTeX format
        
        Args:
            findings: Research findings
            methodology: Research methodology
            datasets: Research datasets
            title: Paper title
            authors: List of authors
            abstract: Paper abstract
            keywords: Paper keywords
            conference: Target conference (IEEE, ACM, etc.)
            
        Returns:
            Path to generated LaTeX paper
        """
        if authors is None:
            authors = ["Security Research Team"]
        if keywords is None:
            keywords = ["binary analysis", "reverse engineering", "AI", "security"]
        
        paper_data = {
            'title': title,
            'authors': authors,
            'abstract': abstract,
            'keywords': keywords,
            'findings': findings,
            'methodology': methodology,
            'datasets': datasets,
            'generation_date': datetime.now().strftime('%Y-%m-%d'),
            'conference': conference.lower()
        }
        
        # Select appropriate template based on conference
        template_name = f"academic_paper_{conference.lower()}.tex"
        if not (self.latex_template_dir / template_name).exists():
            template_name = "academic_paper_ieee.tex"
        
        template = self.jinja_env.get_template(template_name)
        latex_content = template.render(**paper_data)
        
        # Save LaTeX file
        paper_path = self.output_dir / f"academic_paper_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tex"
        with open(paper_path, 'w', encoding='utf-8') as f:
            f.write(latex_content)
        
        # Generate bibliography file
        bib_path = self._generate_bibliography(findings, methodology)
        
        # Try to compile LaTeX to PDF
        try:
            pdf_path = self._compile_latex(paper_path, bib_path)
            logger.info(f"Academic paper compiled to PDF: {pdf_path}")
        except Exception as e:
            logger.warning(f"LaTeX compilation failed: {e}")
            logger.info(f"LaTeX source saved: {paper_path}")
        
        return str(paper_path)
    
    def create_reproducible_research_package(self, findings: List[Finding],
                                           methodology: Methodology,
                                           datasets: List[Dataset],
                                           code_files: List[str] = None) -> str:
        """
        Create reproducible research package with all materials
        
        Args:
            findings: Research findings
            methodology: Research methodology
            datasets: Research datasets
            code_files: List of code files to include
            
        Returns:
            Path to research package ZIP file
        """
        package_name = f"research_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        package_dir = self.output_dir / package_name
        package_dir.mkdir(exist_ok=True)
        
        # Create directory structure
        (package_dir / "data").mkdir(exist_ok=True)
        (package_dir / "code").mkdir(exist_ok=True)
        (package_dir / "results").mkdir(exist_ok=True)
        (package_dir / "documentation").mkdir(exist_ok=True)
        
        # Generate main research report
        report_path = self.generate_technical_report(
            findings, methodology, 
            title="Reproducible Research Report",
            format=ReportFormat.HTML
        )
        shutil.copy2(report_path, package_dir / "documentation" / "main_report.html")
        
        # Generate academic paper
        paper_path = self.generate_academic_paper(findings, methodology, datasets)
        shutil.copy2(paper_path, package_dir / "documentation" / "academic_paper.tex")
        
        # Copy datasets
        for dataset in datasets:
            if os.path.exists(dataset.file_path):
                shutil.copy2(dataset.file_path, package_dir / "data" / os.path.basename(dataset.file_path))
        
        # Copy code files
        if code_files:
            for code_file in code_files:
                if os.path.exists(code_file):
                    shutil.copy2(code_file, package_dir / "code" / os.path.basename(code_file))
        
        # Generate methodology documentation
        methodology_doc = self._generate_methodology_documentation(methodology)
        with open(package_dir / "documentation" / "methodology.md", 'w') as f:
            f.write(methodology_doc)
        
        # Generate dataset documentation
        dataset_doc = self._generate_dataset_documentation(datasets)
        with open(package_dir / "documentation" / "datasets.md", 'w') as f:
            f.write(dataset_doc)
        
        # Generate README
        readme_content = self._generate_research_readme(findings, methodology, datasets)
        with open(package_dir / "README.md", 'w') as f:
            f.write(readme_content)
        
        # Create requirements.txt for reproducibility
        requirements = self._generate_requirements_file()
        with open(package_dir / "requirements.txt", 'w') as f:
            f.write(requirements)
        
        # Create ZIP package
        zip_path = self.output_dir / f"{package_name}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(package_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, package_dir)
                    zipf.write(file_path, arcname)
        
        # Clean up temporary directory
        shutil.rmtree(package_dir)
        
        logger.info(f"Reproducible research package created: {zip_path}")
        return str(zip_path)
    
    def generate_proof_of_concept(self, finding: Finding, 
                                language: str = "python",
                                include_comments: bool = True) -> str:
        """
        Generate proof-of-concept code for a finding
        
        Args:
            finding: Technical finding
            language: Programming language for PoC
            include_comments: Include explanatory comments
            
        Returns:
            Path to generated PoC file
        """
        poc_template = self._get_poc_template(finding.category, language)
        
        poc_data = {
            'finding': finding,
            'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'include_comments': include_comments,
            'language': language
        }
        
        poc_content = poc_template.render(**poc_data)
        
        # Save PoC file
        file_extension = self._get_file_extension(language)
        poc_path = self.output_dir / f"poc_{finding.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}"
        
        with open(poc_path, 'w', encoding='utf-8') as f:
            f.write(poc_content)
        
        logger.info(f"Proof-of-concept generated: {poc_path}")
        return str(poc_path)    
  
  def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML technical report"""
        template = self.jinja_env.get_template('technical_report.html')
        html_content = template.render(**report_data)
        
        report_path = self.output_dir / f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML technical report generated: {report_path}")
        return str(report_path)
    
    def _generate_pdf_technical_report(self, report_data: Dict[str, Any]) -> str:
        """Generate PDF technical report"""
        pdf_path = self.output_dir / f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
        
        styles = getSampleStyleSheet()
        story = []
        
        # Title page
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1  # Center alignment
        )
        
        story.append(Paragraph(report_data['title'], title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"Author: {report_data['author']}", styles['Normal']))
        story.append(Paragraph(f"Generated: {report_data['generation_date']}", styles['Normal']))
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        summary_text = f"""
        This technical report presents the results of a comprehensive security analysis.
        A total of {report_data['total_findings']} findings were identified, including
        {report_data['critical_findings']} critical and {report_data['high_findings']} high severity issues.
        The analysis was supported by {report_data['evidence_count']} pieces of evidence.
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Methodology
        story.append(Paragraph("Methodology", styles['Heading1']))
        methodology = report_data['methodology']
        story.append(Paragraph(f"Name: {methodology.name}", styles['Normal']))
        story.append(Paragraph(f"Description: {methodology.description}", styles['Normal']))
        story.append(Paragraph("Tools Used:", styles['Heading3']))
        for tool in methodology.tools_used:
            story.append(Paragraph(f"• {tool}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Findings
        story.append(Paragraph("Technical Findings", styles['Heading1']))
        
        for finding in report_data['findings']:
            story.append(Paragraph(f"Finding: {finding.title}", styles['Heading2']))
            story.append(Paragraph(f"Severity: {finding.severity}", styles['Normal']))
            story.append(Paragraph(f"Category: {finding.category}", styles['Normal']))
            story.append(Paragraph(f"Description: {finding.description}", styles['Normal']))
            
            if finding.cvss_score:
                story.append(Paragraph(f"CVSS Score: {finding.cvss_score}", styles['Normal']))
            
            if finding.cwe_id:
                story.append(Paragraph(f"CWE ID: {finding.cwe_id}", styles['Normal']))
            
            # Evidence chain
            story.append(Paragraph("Evidence Chain:", styles['Heading3']))
            for i, evidence in enumerate(finding.evidence_chain, 1):
                story.append(Paragraph(f"{i}. {evidence.title} ({evidence.type.value})", styles['Normal']))
                story.append(Paragraph(f"   {evidence.description}", styles['Normal']))
            
            if finding.proof_of_concept:
                story.append(Paragraph("Proof of Concept:", styles['Heading3']))
                story.append(Paragraph(finding.proof_of_concept, styles['Code']))
            
            if finding.remediation:
                story.append(Paragraph("Remediation:", styles['Heading3']))
                story.append(Paragraph(finding.remediation, styles['Normal']))
            
            story.append(Spacer(1, 20))
        
        doc.build(story)
        logger.info(f"PDF technical report generated: {pdf_path}")
        return str(pdf_path)
    
    def _generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """Generate Markdown technical report"""
        template = self.jinja_env.get_template('technical_report.md')
        markdown_content = template.render(**report_data)
        
        report_path = self.output_dir / f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown technical report generated: {report_path}")
        return str(report_path)
    
    def _generate_latex_report(self, report_data: Dict[str, Any]) -> str:
        """Generate LaTeX technical report"""
        template = self.jinja_env.get_template('technical_report.tex')
        latex_content = template.render(**report_data)
        
        report_path = self.output_dir / f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tex"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(latex_content)
        
        logger.info(f"LaTeX technical report generated: {report_path}")
        return str(report_path)
    
    def _generate_json_report(self, report_data: Dict[str, Any]) -> str:
        """Generate JSON technical report"""
        # Convert dataclasses to dictionaries for JSON serialization
        json_data = {}
        for key, value in report_data.items():
            if hasattr(value, '__dict__'):
                json_data[key] = asdict(value)
            elif isinstance(value, list) and value and hasattr(value[0], '__dict__'):
                json_data[key] = [asdict(item) for item in value]
            else:
                json_data[key] = value
        
        report_path = self.output_dir / f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        logger.info(f"JSON technical report generated: {report_path}")
        return str(report_path)
    
    def _generate_bibliography(self, findings: List[Finding], methodology: Methodology) -> str:
        """Generate bibliography file for LaTeX"""
        bib_entries = []
        
        # Add methodology references
        for i, ref in enumerate(methodology.references, 1):
            bib_entries.append(f"""
@misc{{methodology_ref_{i},
    title={{{ref}}},
    note={{Accessed: {datetime.now().strftime('%Y-%m-%d')}}}
}}""")
        
        # Add finding references
        for finding in findings:
            if finding.references:
                for i, ref in enumerate(finding.references, 1):
                    bib_entries.append(f"""
@misc{{finding_{finding.id}_ref_{i},
    title={{{ref}}},
    note={{Accessed: {datetime.now().strftime('%Y-%m-%d')}}}
}}""")
        
        bib_content = "\n".join(bib_entries)
        bib_path = self.output_dir / "references.bib"
        
        with open(bib_path, 'w', encoding='utf-8') as f:
            f.write(bib_content)
        
        return str(bib_path)
    
    def _compile_latex(self, tex_path: str, bib_path: str) -> str:
        """Compile LaTeX to PDF"""
        try:
            # Change to output directory for compilation
            original_dir = os.getcwd()
            os.chdir(self.output_dir)
            
            tex_file = os.path.basename(tex_path)
            
            # Run pdflatex
            subprocess.run(['pdflatex', tex_file], check=True, capture_output=True)
            
            # Run bibtex if bibliography exists
            if os.path.exists(bib_path):
                subprocess.run(['bibtex', tex_file.replace('.tex', '')], check=True, capture_output=True)
                subprocess.run(['pdflatex', tex_file], check=True, capture_output=True)
                subprocess.run(['pdflatex', tex_file], check=True, capture_output=True)
            
            pdf_path = tex_path.replace('.tex', '.pdf')
            
            # Return to original directory
            os.chdir(original_dir)
            
            return pdf_path
            
        except subprocess.CalledProcessError as e:
            os.chdir(original_dir)
            raise Exception(f"LaTeX compilation failed: {e}")
        except FileNotFoundError:
            os.chdir(original_dir)
            raise Exception("LaTeX not found. Please install a LaTeX distribution.")
    
    def _generate_methodology_documentation(self, methodology: Methodology) -> str:
        """Generate methodology documentation in Markdown"""
        doc = f"""# Research Methodology: {methodology.name}

## Description
{methodology.description}

## Tools Used
"""
        for tool in methodology.tools_used:
            doc += f"- {tool}\n"
        
        doc += f"""
## Parameters
"""
        for key, value in methodology.parameters.items():
            doc += f"- **{key}**: {value}\n"
        
        doc += f"""
## Validation Method
{methodology.validation_method}

## Limitations
"""
        for limitation in methodology.limitations:
            doc += f"- {limitation}\n"
        
        doc += f"""
## References
"""
        for ref in methodology.references:
            doc += f"- {ref}\n"
        
        return doc
    
    def _generate_dataset_documentation(self, datasets: List[Dataset]) -> str:
        """Generate dataset documentation in Markdown"""
        doc = "# Research Datasets\n\n"
        
        for dataset in datasets:
            doc += f"""## {dataset.name}

**Description**: {dataset.description}

**Size**: {dataset.size} samples

**Format**: {dataset.format}

**Source**: {dataset.source}

**Collection Date**: {dataset.collection_date.strftime('%Y-%m-%d')}

**File Path**: {dataset.file_path}

**Checksum**: {dataset.checksum}

### Preprocessing Steps
"""
            for step in dataset.preprocessing_steps:
                doc += f"1. {step}\n"
            
            doc += "\n---\n\n"
        
        return doc
    
    def _generate_research_readme(self, findings: List[Finding], 
                                methodology: Methodology, 
                                datasets: List[Dataset]) -> str:
        """Generate README for research package"""
        readme = f"""# Reproducible Research Package

This package contains all materials necessary to reproduce the research findings.

## Contents

- `documentation/`: Research reports and papers
- `data/`: Research datasets
- `code/`: Analysis code and scripts
- `results/`: Generated results and outputs

## Quick Start

1. Install dependencies: `pip install -r requirements.txt`
2. Review methodology: `documentation/methodology.md`
3. Examine datasets: `documentation/datasets.md`
4. Run analysis: See individual code files for instructions

## Research Summary

**Total Findings**: {len(findings)}
**Methodology**: {methodology.name}
**Datasets**: {len(datasets)}

## Findings Overview

"""
        for finding in findings:
            readme += f"- **{finding.title}** ({finding.severity}): {finding.description[:100]}...\n"
        
        readme += f"""
## Datasets

"""
        for dataset in datasets:
            readme += f"- **{dataset.name}**: {dataset.size} samples, {dataset.format} format\n"
        
        readme += f"""
## Citation

If you use this research package, please cite:

```
[Generated Research Package]
Title: AI-Enhanced Binary Analysis Research
Date: {datetime.now().strftime('%Y-%m-%d')}
```

## License

This research package is provided for academic and research purposes.
"""
        
        return readme
    
    def _generate_requirements_file(self) -> str:
        """Generate requirements.txt for reproducibility"""
        requirements = """# Core analysis dependencies
numpy>=1.21.0
pandas>=1.3.0
matplotlib>=3.4.0
seaborn>=0.11.0

# Reporting dependencies
jinja2>=3.0.0
markdown>=3.3.0
reportlab>=3.6.0

# Optional LaTeX support
# Install LaTeX distribution separately

# Binary analysis tools
# Install Ghidra, IDA Pro, or other tools as needed
"""
        return requirements
    
    def _get_poc_template(self, category: str, language: str) -> Template:
        """Get proof-of-concept template"""
        template_name = f"poc_{category.lower().replace(' ', '_')}_{language}.j2"
        
        # Try to load specific template
        try:
            return self.jinja_env.get_template(template_name)
        except:
            # Fall back to generic template
            return self.jinja_env.get_template(f"poc_generic_{language}.j2")
    
    def _get_file_extension(self, language: str) -> str:
        """Get file extension for programming language"""
        extensions = {
            'python': 'py',
            'c': 'c',
            'cpp': 'cpp',
            'java': 'java',
            'javascript': 'js',
            'bash': 'sh',
            'powershell': 'ps1'
        }
        return extensions.get(language.lower(), 'txt')
    
    def _create_default_templates(self):
        """Create default report templates"""
        
        # HTML technical report template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .metadata { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .finding { background-color: white; border-left: 5px solid #007bff; padding: 20px; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 5px; }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #fd7e14; }
        .finding.medium { border-left-color: #ffc107; }
        .finding.low { border-left-color: #28a745; }
        .evidence { background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .code { background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; }
        .toc { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .toc ul { list-style-type: none; padding-left: 0; }
        .toc li { margin: 5px 0; }
        .toc a { text-decoration: none; color: #007bff; }
        .severity-badge { padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8em; }
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; color: #212529; }
        .severity-low { background-color: #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>Author: {{ author }}</p>
        <p>Generated: {{ generation_date }}</p>
    </div>
    
    <div class="metadata">
        <h2>Report Summary</h2>
        <ul>
            <li><strong>Total Findings:</strong> {{ total_findings }}</li>
            <li><strong>Critical Findings:</strong> {{ critical_findings }}</li>
            <li><strong>High Severity Findings:</strong> {{ high_findings }}</li>
            <li><strong>Evidence Items:</strong> {{ evidence_count }}</li>
        </ul>
    </div>
    
    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            <li><a href="#methodology">Methodology</a></li>
            <li><a href="#findings">Technical Findings</a></li>
            {% for finding in findings %}
            <li><a href="#finding-{{ loop.index }}">{{ finding.title }}</a></li>
            {% endfor %}
        </ul>
    </div>
    
    <section id="methodology">
        <h2>Methodology</h2>
        <h3>{{ methodology.name }}</h3>
        <p>{{ methodology.description }}</p>
        
        <h4>Tools Used</h4>
        <ul>
        {% for tool in methodology.tools_used %}
            <li>{{ tool }}</li>
        {% endfor %}
        </ul>
        
        <h4>Validation Method</h4>
        <p>{{ methodology.validation_method }}</p>
        
        {% if methodology.limitations %}
        <h4>Limitations</h4>
        <ul>
        {% for limitation in methodology.limitations %}
            <li>{{ limitation }}</li>
        {% endfor %}
        </ul>
        {% endif %}
    </section>
    
    <section id="findings">
        <h2>Technical Findings</h2>
        
        {% for finding in findings %}
        <div class="finding {{ finding.severity.lower() }}" id="finding-{{ loop.index }}">
            <h3>{{ finding.title }} <span class="severity-badge severity-{{ finding.severity.lower() }}">{{ finding.severity }}</span></h3>
            
            <p><strong>Category:</strong> {{ finding.category }}</p>
            {% if finding.cvss_score %}
            <p><strong>CVSS Score:</strong> {{ finding.cvss_score }}</p>
            {% endif %}
            {% if finding.cwe_id %}
            <p><strong>CWE ID:</strong> {{ finding.cwe_id }}</p>
            {% endif %}
            
            <h4>Description</h4>
            <p>{{ finding.description }}</p>
            
            <h4>Evidence Chain</h4>
            {% for evidence in finding.evidence_chain %}
            <div class="evidence">
                <h5>{{ evidence.title }} ({{ evidence.type.value }})</h5>
                <p>{{ evidence.description }}</p>
                {% if evidence.content %}
                <div class="code">{{ evidence.content }}</div>
                {% endif %}
            </div>
            {% endfor %}
            
            {% if finding.proof_of_concept %}
            <h4>Proof of Concept</h4>
            <div class="code">{{ finding.proof_of_concept }}</div>
            {% endif %}
            
            {% if finding.remediation %}
            <h4>Remediation</h4>
            <p>{{ finding.remediation }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </section>
</body>
</html>
        """
        
        with open(self.template_dir / "technical_report.html", 'w') as f:
            f.write(html_template)
        
        # Markdown technical report template
        markdown_template = """# {{ title }}

**Author:** {{ author }}  
**Generated:** {{ generation_date }}

## Report Summary

- **Total Findings:** {{ total_findings }}
- **Critical Findings:** {{ critical_findings }}
- **High Severity Findings:** {{ high_findings }}
- **Evidence Items:** {{ evidence_count }}

## Methodology

### {{ methodology.name }}

{{ methodology.description }}

#### Tools Used

{% for tool in methodology.tools_used %}
- {{ tool }}
{% endfor %}

#### Validation Method

{{ methodology.validation_method }}

{% if methodology.limitations %}
#### Limitations

{% for limitation in methodology.limitations %}
- {{ limitation }}
{% endfor %}
{% endif %}

## Technical Findings

{% for finding in findings %}
### {{ finding.title }} [{{ finding.severity }}]

**Category:** {{ finding.category }}
{% if finding.cvss_score %}**CVSS Score:** {{ finding.cvss_score }}{% endif %}
{% if finding.cwe_id %}**CWE ID:** {{ finding.cwe_id }}{% endif %}

#### Description

{{ finding.description }}

#### Evidence Chain

{% for evidence in finding.evidence_chain %}
##### {{ evidence.title }} ({{ evidence.type.value }})

{{ evidence.description }}

{% if evidence.content %}
```
{{ evidence.content }}
```
{% endif %}

{% endfor %}

{% if finding.proof_of_concept %}
#### Proof of Concept

```
{{ finding.proof_of_concept }}
```
{% endif %}

{% if finding.remediation %}
#### Remediation

{{ finding.remediation }}
{% endif %}

---

{% endfor %}
        """
        
        with open(self.template_dir / "technical_report.md", 'w') as f:
            f.write(markdown_template)
        
        # IEEE LaTeX template
        ieee_template = r"""
\documentclass[conference]{IEEEtran}
\usepackage{cite}
\usepackage{amsmath,amssymb,amsfonts}
\usepackage{algorithmic}
\usepackage{graphicx}
\usepackage{textcomp}
\usepackage{xcolor}
\usepackage{listings}
\usepackage{url}

\lstset{
    basicstyle=\ttfamily\footnotesize,
    breaklines=true,
    frame=single,
    backgroundcolor=\color{gray!10}
}

\begin{document}

\title{{{ title }}}

\author{
{% for author in authors %}
\IEEEauthorblockN{{{ author }}}
{% if not loop.last %}\and{% endif %}
{% endfor %}
}

\maketitle

\begin{abstract}
{{ abstract }}
\end{abstract}

\begin{IEEEkeywords}
{% for keyword in keywords %}{{ keyword }}{% if not loop.last %}, {% endif %}{% endfor %}
\end{IEEEkeywords}

\section{Introduction}

This paper presents the results of an AI-enhanced binary analysis study conducted on {{ generation_date }}. 
The research identified {{ findings|length }} significant findings across multiple categories of security vulnerabilities.

\section{Methodology}

\subsection{{{ methodology.name }}}

{{ methodology.description }}

The analysis employed the following tools:
\begin{itemize}
{% for tool in methodology.tools_used %}
\item {{ tool }}
{% endfor %}
\end{itemize}

\subsection{Validation}

{{ methodology.validation_method }}

{% if methodology.limitations %}
\subsection{Limitations}

\begin{itemize}
{% for limitation in methodology.limitations %}
\item {{ limitation }}
{% endfor %}
\end{itemize}
{% endif %}

\section{Results}

{% for finding in findings %}
\subsection{{{ finding.title }}}

\textbf{Severity:} {{ finding.severity }} \\
\textbf{Category:} {{ finding.category }}
{% if finding.cvss_score %}\textbf{CVSS Score:} {{ finding.cvss_score }}{% endif %}

{{ finding.description }}

{% if finding.proof_of_concept %}
\begin{lstlisting}[caption=Proof of Concept]
{{ finding.proof_of_concept }}
\end{lstlisting}
{% endif %}

{% endfor %}

\section{Conclusion}

This study demonstrates the effectiveness of AI-enhanced binary analysis techniques in identifying security vulnerabilities. 
The {{ findings|length }} findings highlight the importance of comprehensive security analysis in modern software systems.

\bibliographystyle{IEEEtran}
\bibliography{references}

\end{document}
        """
        
        with open(self.latex_template_dir / "academic_paper_ieee.tex", 'w') as f:
            f.write(ieee_template)
        
        logger.info("Default templates created successfully")

# Example usage and testing
if __name__ == "__main__":
    # Initialize the engine
    engine = TechnicalReportingEngine()
    
    # Create sample data for testing
    sample_evidence = [
        Evidence(
            id="E001",
            type=EvidenceType.CODE_SNIPPET,
            title="Buffer Overflow in Login Function",
            description="Vulnerable strcpy call without bounds checking",
            content="strcpy(buffer, user_input); // No bounds checking",
            timestamp=datetime.now(),
            confidence=0.95
        ),
        Evidence(
            id="E002",
            type=EvidenceType.BINARY_ANALYSIS,
            title="Disassembly Analysis",
            description="Assembly code showing vulnerable memory operation",
            content="mov eax, [ebp+user_input]\nmov [ebp+buffer], eax",
            confidence=0.90
        )
    ]
    
    sample_finding = Finding(
        id="F001",
        title="Stack Buffer Overflow in Authentication Module",
        description="A stack-based buffer overflow vulnerability exists in the user authentication function due to unsafe string copying operations.",
        severity="Critical",
        category="Memory Corruption",
        evidence_chain=sample_evidence,
        proof_of_concept="exploit_code = 'A' * 256 + struct.pack('<I', 0x41414141)",
        remediation="Replace strcpy with strncpy and implement proper bounds checking",
        cvss_score=9.8,
        cwe_id="CWE-121"
    )
    
    sample_methodology = Methodology(
        name="AI-Enhanced Static Analysis",
        description="Comprehensive static analysis using AI-powered decompilation and vulnerability detection",
        tools_used=["Ghidra", "IDA Pro", "Custom AI Analysis Engine"],
        parameters={"analysis_depth": "comprehensive", "ai_confidence_threshold": 0.8},
        validation_method="Manual code review and dynamic testing",
        limitations=["Limited to static analysis", "May produce false positives"],
        references=["IEEE Security & Privacy 2023", "USENIX Security 2023"]
    )
    
    sample_dataset = Dataset(
        name="Binary Analysis Test Set",
        description="Collection of vulnerable binaries for testing",
        size=100,
        format="PE/ELF executables",
        source="Security research lab",
        collection_date=datetime.now(),
        preprocessing_steps=["Malware scanning", "Format validation"],
        file_path="data/test_binaries.zip",
        checksum="sha256:abc123..."
    )
    
    # Generate reports
    try:
        # Technical report
        html_report = engine.generate_technical_report(
            [sample_finding], sample_methodology, 
            title="AI-Enhanced Binary Analysis Report",
            format=ReportFormat.HTML
        )
        
        # Academic paper
        paper_path = engine.generate_academic_paper(
            [sample_finding], sample_methodology, [sample_dataset],
            title="AI-Enhanced Binary Analysis: A Comprehensive Study"
        )
        
        # Research package
        package_path = engine.create_reproducible_research_package(
            [sample_finding], sample_methodology, [sample_dataset]
        )
        
        print(f"HTML report generated: {html_report}")
        print(f"Academic paper generated: {paper_path}")
        print(f"Research package generated: {package_path}")
        
    except Exception as e:
        logger.error(f"Error generating reports: {e}")
        print(f"Error: {e}")