#!/usr/bin/env python3
"""
Live Demonstration and Assessment Engine

This module creates live analysis demonstration workflows for client meetings,
real-time security assessment tools for consulting engagements, and portfolio
analysis capabilities for organizational risk assessment.

Requirements: 8.1, 8.3
"""

import json
import os
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DemonstrationStep:
    """Represents a single step in a live demonstration"""
    step_id: str
    title: str
    description: str
    action_type: str  # analysis, visualization, explanation, interaction
    duration_seconds: int
    prerequisites: List[str]
    expected_outcome: str
    interactive_elements: List[Dict[str, Any]]
    visual_aids: List[str]
    talking_points: List[str]

@dataclass
class LiveDemonstration:
    """Represents a complete live demonstration workflow"""
    demo_id: str
    title: str
    description: str
    target_audience: str
    total_duration: int
    steps: List[DemonstrationStep]
    required_files: List[str]
    setup_instructions: List[str]
    cleanup_instructions: List[str]
    contingency_plans: List[Dict[str, Any]]

@dataclass
class AssessmentMetric:
    """Represents a security assessment metric"""
    metric_name: str
    description: str
    measurement_method: str
    current_value: float
    baseline_value: float
    target_value: float
    risk_level: str
    trend: str  # improving, declining, stable
    recommendations: List[str]

@dataclass
class PortfolioAnalysis:
    """Represents analysis of an organization's software portfolio"""
    organization_name: str
    analysis_date: datetime
    applications_analyzed: int
    total_vulnerabilities: int
    critical_findings: List[Dict[str, Any]]
    risk_distribution: Dict[str, int]
    compliance_status: Dict[str, str]
    remediation_roadmap: List[Dict[str, Any]]
    executive_summary: str

class LiveDemonstrationEngine:
    """Manages live demonstrations and real-time assessments"""
    
    def __init__(self, output_dir: str = "live_demonstrations"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize demonstration state
        self.current_demo = None
        self.demo_state = {}
        self.progress_callbacks = []
        self.assessment_queue = queue.Queue()
        
        # Create subdirectories
        (self.output_dir / "demos").mkdir(exist_ok=True)
        (self.output_dir / "assessments").mkdir(exist_ok=True)
        (self.output_dir / "portfolios").mkdir(exist_ok=True)
        
        logger.info(f"Live demonstration engine initialized with output directory: {self.output_dir}")
    
    def create_client_demonstration(self, client_type: str, analysis_results: Dict[str, Any]) -> LiveDemonstration:
        """Create a tailored demonstration for specific client type"""
        
        demo_id = f"client_demo_{client_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if client_type == "executive":
            return self._create_executive_demonstration(demo_id, analysis_results)
        elif client_type == "technical":
            return self._create_technical_demonstration(demo_id, analysis_results)
        elif client_type == "security_team":
            return self._create_security_team_demonstration(demo_id, analysis_results)
        else:
            return self._create_general_demonstration(demo_id, analysis_results)
    
    def _create_executive_demonstration(self, demo_id: str, analysis_results: Dict[str, Any]) -> LiveDemonstration:
        """Create executive-focused demonstration emphasizing business risk"""
        
        steps = [
            DemonstrationStep(
                step_id="exec_intro",
                title="Executive Overview: The New Reality of Software Security",
                description="Introduction to how AI has changed the security landscape",
                action_type="explanation",
                duration_seconds=180,
                prerequisites=[],
                expected_outcome="Executives understand the paradigm shift in reverse engineering",
                interactive_elements=[
                    {"type": "poll", "question": "How confident are you in your current application security?"}
                ],
                visual_aids=["risk_matrix_slide.png", "industry_statistics.png"],
                talking_points=[
                    "Traditional security assumptions are obsolete",
                    "AI can reverse engineer ANY application in minutes",
                    "Your proprietary algorithms are not protected",
                    "Compliance requirements are evolving"
                ]
            ),
            DemonstrationStep(
                step_id="live_analysis",
                title="Live Analysis: Your Application Under the Microscope",
                description="Real-time analysis of a sample application",
                action_type="analysis",
                duration_seconds=300,
                prerequisites=["sample_application.exe"],
                expected_outcome="Demonstrate extraction of sensitive data from compiled application",
                interactive_elements=[
                    {"type": "real_time_results", "display": "credentials_found"},
                    {"type": "risk_calculator", "inputs": ["data_sensitivity", "exposure_level"]}
                ],
                visual_aids=["analysis_dashboard.png", "credential_extraction.png"],
                talking_points=[
                    "Watch as we extract hardcoded credentials in real-time",
                    "Business logic is completely visible",
                    "API keys and database connections exposed",
                    "This takes less than 5 minutes with AI tools"
                ]
            ),
            DemonstrationStep(
                step_id="business_impact",
                title="Business Impact Assessment",
                description="Quantify the financial and operational risks",
                action_type="visualization",
                duration_seconds=240,
                prerequisites=["analysis_results"],
                expected_outcome="Clear understanding of business risks and costs",
                interactive_elements=[
                    {"type": "cost_calculator", "factors": ["breach_cost", "compliance_fines", "reputation_damage"]},
                    {"type": "timeline", "events": ["discovery", "exploitation", "breach", "recovery"]}
                ],
                visual_aids=["cost_breakdown.png", "risk_timeline.png"],
                talking_points=[
                    "Average data breach cost: $4.45M",
                    "Regulatory fines can reach 4% of annual revenue",
                    "Competitive advantage loss is immeasurable",
                    "Recovery time: 6-12 months minimum"
                ]
            ),
            DemonstrationStep(
                step_id="remediation_roadmap",
                title="Strategic Remediation Roadmap",
                description="Present actionable steps for risk mitigation",
                action_type="interaction",
                duration_seconds=300,
                prerequisites=["risk_assessment"],
                expected_outcome="Clear action plan with priorities and timelines",
                interactive_elements=[
                    {"type": "priority_matrix", "axes": ["impact", "effort"]},
                    {"type": "timeline_builder", "milestones": ["immediate", "short_term", "long_term"]}
                ],
                visual_aids=["remediation_roadmap.png", "investment_roi.png"],
                talking_points=[
                    "Immediate actions: Credential rotation and monitoring",
                    "Short-term: Implement secure development practices",
                    "Long-term: Architecture redesign for security",
                    "ROI: Prevention costs 10x less than remediation"
                ]
            )
        ]
        
        return LiveDemonstration(
            demo_id=demo_id,
            title="Executive Security Briefing: The AI Revolution in Reverse Engineering",
            description="Executive-level demonstration of modern security risks and business impact",
            target_audience="C-suite executives, board members, senior management",
            total_duration=1020,  # 17 minutes
            steps=steps,
            required_files=["sample_application.exe", "analysis_tools", "presentation_slides"],
            setup_instructions=[
                "Prepare sample application for analysis",
                "Load presentation slides",
                "Test analysis tools connectivity",
                "Prepare backup scenarios"
            ],
            cleanup_instructions=[
                "Secure deletion of analysis results",
                "Remove temporary files",
                "Document action items"
            ],
            contingency_plans=[
                {
                    "scenario": "Analysis tools fail",
                    "backup": "Use pre-recorded analysis results",
                    "talking_points": ["This is what we would see in real-time"]
                },
                {
                    "scenario": "Network connectivity issues",
                    "backup": "Offline demonstration mode",
                    "talking_points": ["Local analysis capabilities"]
                }
            ]
        )
    
    def _create_technical_demonstration(self, demo_id: str, analysis_results: Dict[str, Any]) -> LiveDemonstration:
        """Create technical demonstration for developers and architects"""
        
        steps = [
            DemonstrationStep(
                step_id="tech_deep_dive",
                title="Technical Deep Dive: Modern Reverse Engineering Techniques",
                description="Detailed technical analysis of reverse engineering methods",
                action_type="analysis",
                duration_seconds=600,
                prerequisites=["sample_binaries", "analysis_tools"],
                expected_outcome="Technical understanding of analysis capabilities",
                interactive_elements=[
                    {"type": "code_viewer", "content": "decompiled_source"},
                    {"type": "hex_editor", "content": "binary_analysis"},
                    {"type": "call_graph", "content": "function_relationships"}
                ],
                visual_aids=["decompilation_process.png", "code_comparison.png"],
                talking_points=[
                    "AI-powered decompilation accuracy: >95%",
                    "Symbol recovery and function identification",
                    "Control flow and data flow analysis",
                    "Cross-reference analysis and dependency mapping"
                ]
            ),
            DemonstrationStep(
                step_id="vulnerability_analysis",
                title="Automated Vulnerability Discovery",
                description="Live vulnerability scanning and analysis",
                action_type="analysis",
                duration_seconds=480,
                prerequisites=["vulnerable_samples"],
                expected_outcome="Identification of security vulnerabilities",
                interactive_elements=[
                    {"type": "vulnerability_scanner", "real_time": True},
                    {"type": "cvss_calculator", "interactive": True},
                    {"type": "exploit_generator", "proof_of_concept": True}
                ],
                visual_aids=["vulnerability_dashboard.png", "exploit_demo.png"],
                talking_points=[
                    "Buffer overflow detection algorithms",
                    "Injection vulnerability patterns",
                    "Authentication bypass techniques",
                    "Proof-of-concept exploit generation"
                ]
            )
        ]
        
        return LiveDemonstration(
            demo_id=demo_id,
            title="Technical Deep Dive: AI-Enhanced Security Analysis",
            description="Technical demonstration for developers and security professionals",
            target_audience="Developers, security engineers, technical architects",
            total_duration=1080,  # 18 minutes
            steps=steps,
            required_files=["sample_binaries", "vulnerable_samples", "analysis_tools"],
            setup_instructions=[
                "Prepare diverse binary samples",
                "Configure analysis environment",
                "Test all demonstration tools",
                "Prepare technical Q&A materials"
            ],
            cleanup_instructions=[
                "Archive analysis results",
                "Clean temporary analysis files",
                "Document technical findings"
            ],
            contingency_plans=[
                {
                    "scenario": "Complex analysis takes too long",
                    "backup": "Switch to pre-analyzed samples",
                    "talking_points": ["Here's what the complete analysis reveals"]
                }
            ]
        )
    
    def _create_security_team_demonstration(self, demo_id: str, analysis_results: Dict[str, Any]) -> LiveDemonstration:
        """Create demonstration focused on security team workflows"""
        
        steps = [
            DemonstrationStep(
                step_id="threat_hunting",
                title="Threat Hunting with AI-Enhanced Analysis",
                description="Demonstrate threat hunting capabilities",
                action_type="analysis",
                duration_seconds=420,
                prerequisites=["malware_samples", "threat_intel_feeds"],
                expected_outcome="Understanding of threat hunting workflows",
                interactive_elements=[
                    {"type": "threat_dashboard", "real_time": True},
                    {"type": "ioc_extractor", "interactive": True},
                    {"type": "attribution_engine", "correlation": True}
                ],
                visual_aids=["threat_landscape.png", "attribution_matrix.png"],
                talking_points=[
                    "Automated IOC extraction from malware",
                    "APT group attribution techniques",
                    "Campaign correlation and tracking",
                    "Integration with existing security tools"
                ]
            ),
            DemonstrationStep(
                step_id="incident_response",
                title="Incident Response Acceleration",
                description="How AI analysis accelerates incident response",
                action_type="interaction",
                duration_seconds=360,
                prerequisites=["incident_samples"],
                expected_outcome="Faster incident analysis and response",
                interactive_elements=[
                    {"type": "incident_timeline", "interactive": True},
                    {"type": "evidence_correlator", "real_time": True},
                    {"type": "response_planner", "automated": True}
                ],
                visual_aids=["incident_workflow.png", "response_timeline.png"],
                talking_points=[
                    "Reduce analysis time from days to hours",
                    "Automated evidence correlation",
                    "Threat actor identification",
                    "Containment strategy recommendations"
                ]
            )
        ]
        
        return LiveDemonstration(
            demo_id=demo_id,
            title="Security Operations Enhancement with AI Analysis",
            description="Demonstration for security operations teams",
            target_audience="SOC analysts, incident responders, threat hunters",
            total_duration=780,  # 13 minutes
            steps=steps,
            required_files=["malware_samples", "incident_samples", "threat_intel_feeds"],
            setup_instructions=[
                "Prepare sanitized malware samples",
                "Configure threat intelligence feeds",
                "Set up incident response scenarios",
                "Test security tool integrations"
            ],
            cleanup_instructions=[
                "Secure malware sample cleanup",
                "Archive incident analysis results",
                "Update threat intelligence database"
            ],
            contingency_plans=[
                {
                    "scenario": "Threat intel feeds unavailable",
                    "backup": "Use cached threat intelligence",
                    "talking_points": ["Offline threat analysis capabilities"]
                }
            ]
        )
    
    def _create_general_demonstration(self, demo_id: str, analysis_results: Dict[str, Any]) -> LiveDemonstration:
        """Create general-purpose demonstration"""
        
        steps = [
            DemonstrationStep(
                step_id="overview",
                title="AI-Enhanced Security Analysis Overview",
                description="General overview of capabilities",
                action_type="explanation",
                duration_seconds=300,
                prerequisites=[],
                expected_outcome="Understanding of analysis capabilities",
                interactive_elements=[
                    {"type": "capability_matrix", "interactive": True}
                ],
                visual_aids=["capability_overview.png"],
                talking_points=[
                    "Universal binary analysis capabilities",
                    "Automated vulnerability discovery",
                    "Threat intelligence correlation",
                    "Real-world security implications"
                ]
            )
        ]
        
        return LiveDemonstration(
            demo_id=demo_id,
            title="AI-Enhanced Security Analysis Demonstration",
            description="General demonstration of analysis capabilities",
            target_audience="Mixed audience",
            total_duration=300,
            steps=steps,
            required_files=["sample_application"],
            setup_instructions=["Prepare sample application"],
            cleanup_instructions=["Clean temporary files"],
            contingency_plans=[]
        )
    
    def execute_live_demonstration(self, demo: LiveDemonstration, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Execute a live demonstration with real-time progress tracking"""
        
        self.current_demo = demo
        self.demo_state = {
            "demo_id": demo.demo_id,
            "start_time": datetime.now(),
            "current_step": 0,
            "total_steps": len(demo.steps),
            "status": "running",
            "results": {},
            "audience_feedback": []
        }
        
        if progress_callback:
            self.progress_callbacks.append(progress_callback)
        
        logger.info(f"Starting live demonstration: {demo.title}")
        
        try:
            for i, step in enumerate(demo.steps):
                self.demo_state["current_step"] = i + 1
                
                logger.info(f"Executing step {i+1}/{len(demo.steps)}: {step.title}")
                
                # Execute step based on action type
                step_result = self._execute_demonstration_step(step)
                self.demo_state["results"][step.step_id] = step_result
                
                # Notify progress callbacks
                for callback in self.progress_callbacks:
                    callback(self.demo_state)
                
                # Simulate step duration (in real demo, this would be actual execution time)
                time.sleep(min(step.duration_seconds / 10, 2))  # Accelerated for testing
            
            self.demo_state["status"] = "completed"
            self.demo_state["end_time"] = datetime.now()
            
            # Generate demonstration report
            report = self._generate_demonstration_report()
            
            logger.info(f"Demonstration completed successfully: {demo.demo_id}")
            return report
            
        except Exception as e:
            self.demo_state["status"] = "failed"
            self.demo_state["error"] = str(e)
            logger.error(f"Demonstration failed: {e}")
            raise
    
    def _execute_demonstration_step(self, step: DemonstrationStep) -> Dict[str, Any]:
        """Execute a single demonstration step"""
        
        step_result = {
            "step_id": step.step_id,
            "start_time": datetime.now(),
            "status": "running",
            "outputs": []
        }
        
        try:
            if step.action_type == "analysis":
                # Simulate analysis execution
                step_result["outputs"] = self._simulate_analysis_execution(step)
            elif step.action_type == "visualization":
                # Generate visualizations
                step_result["outputs"] = self._generate_step_visualizations(step)
            elif step.action_type == "explanation":
                # Prepare explanation materials
                step_result["outputs"] = self._prepare_explanation_materials(step)
            elif step.action_type == "interaction":
                # Handle interactive elements
                step_result["outputs"] = self._handle_interactive_elements(step)
            
            step_result["status"] = "completed"
            step_result["end_time"] = datetime.now()
            
        except Exception as e:
            step_result["status"] = "failed"
            step_result["error"] = str(e)
            logger.error(f"Step execution failed: {e}")
        
        return step_result
    
    def _simulate_analysis_execution(self, step: DemonstrationStep) -> List[Dict[str, Any]]:
        """Simulate analysis execution for demonstration"""
        
        outputs = []
        
        # Simulate different types of analysis outputs
        if "credential" in step.description.lower():
            outputs.append({
                "type": "credential_found",
                "data": {
                    "credential_type": "API_KEY",
                    "location": "0x00401234",
                    "risk_level": "HIGH",
                    "description": "Hardcoded API key found in binary"
                }
            })
        
        if "vulnerability" in step.description.lower():
            outputs.append({
                "type": "vulnerability_found",
                "data": {
                    "vulnerability_type": "Buffer Overflow",
                    "cvss_score": 8.5,
                    "location": "input_handler function",
                    "description": "Stack buffer overflow in user input processing"
                }
            })
        
        if "threat" in step.description.lower():
            outputs.append({
                "type": "threat_detected",
                "data": {
                    "threat_family": "APT29",
                    "confidence": 0.85,
                    "indicators": ["C2 domain pattern", "Encryption algorithm", "File structure"],
                    "description": "Indicators consistent with APT29 campaign"
                }
            })
        
        return outputs
    
    def _generate_step_visualizations(self, step: DemonstrationStep) -> List[Dict[str, Any]]:
        """Generate visualizations for demonstration step"""
        
        visualizations = []
        
        for visual_aid in step.visual_aids:
            visualizations.append({
                "type": "visualization",
                "name": visual_aid,
                "path": f"visualizations/{visual_aid}",
                "description": f"Visual aid for {step.title}"
            })
        
        return visualizations
    
    def _prepare_explanation_materials(self, step: DemonstrationStep) -> List[Dict[str, Any]]:
        """Prepare explanation materials for demonstration step"""
        
        materials = []
        
        for talking_point in step.talking_points:
            materials.append({
                "type": "talking_point",
                "content": talking_point,
                "emphasis": "high" if any(keyword in talking_point.lower() 
                                        for keyword in ["critical", "important", "key", "essential"])
                          else "normal"
            })
        
        return materials
    
    def _handle_interactive_elements(self, step: DemonstrationStep) -> List[Dict[str, Any]]:
        """Handle interactive elements in demonstration step"""
        
        interactions = []
        
        for element in step.interactive_elements:
            interactions.append({
                "type": "interactive_element",
                "element_type": element["type"],
                "data": element,
                "status": "ready"
            })
        
        return interactions
    
    def _generate_demonstration_report(self) -> Dict[str, Any]:
        """Generate comprehensive demonstration report"""
        
        if not self.current_demo or not self.demo_state:
            raise ValueError("No active demonstration to report on")
        
        duration = (self.demo_state.get("end_time", datetime.now()) - 
                   self.demo_state["start_time"]).total_seconds()
        
        report = {
            "demonstration_id": self.demo_state["demo_id"],
            "title": self.current_demo.title,
            "execution_summary": {
                "start_time": self.demo_state["start_time"].isoformat(),
                "end_time": self.demo_state.get("end_time", datetime.now()).isoformat(),
                "duration_seconds": duration,
                "status": self.demo_state["status"],
                "steps_completed": self.demo_state["current_step"],
                "total_steps": self.demo_state["total_steps"]
            },
            "step_results": self.demo_state["results"],
            "audience_feedback": self.demo_state.get("audience_feedback", []),
            "key_findings": self._extract_key_findings(),
            "follow_up_actions": self._generate_follow_up_actions(),
            "effectiveness_metrics": self._calculate_effectiveness_metrics()
        }
        
        # Export report
        report_filename = f"demo_report_{self.demo_state['demo_id']}.json"
        report_filepath = self.output_dir / "demos" / report_filename
        
        with open(report_filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Demonstration report generated: {report_filepath}")
        return report
    
    def _extract_key_findings(self) -> List[Dict[str, Any]]:
        """Extract key findings from demonstration results"""
        
        findings = []
        
        for step_id, step_result in self.demo_state["results"].items():
            for output in step_result.get("outputs", []):
                if output.get("type") in ["credential_found", "vulnerability_found", "threat_detected"]:
                    findings.append({
                        "step": step_id,
                        "finding_type": output["type"],
                        "data": output["data"],
                        "significance": "high"
                    })
        
        return findings
    
    def _generate_follow_up_actions(self) -> List[Dict[str, Any]]:
        """Generate follow-up actions based on demonstration results"""
        
        actions = [
            {
                "action": "Schedule detailed security assessment",
                "priority": "high",
                "timeline": "within 2 weeks",
                "responsible_party": "Security team"
            },
            {
                "action": "Review and update security policies",
                "priority": "medium",
                "timeline": "within 1 month",
                "responsible_party": "Policy team"
            },
            {
                "action": "Implement enhanced monitoring",
                "priority": "high",
                "timeline": "within 1 week",
                "responsible_party": "SOC team"
            }
        ]
        
        return actions
    
    def _calculate_effectiveness_metrics(self) -> Dict[str, Any]:
        """Calculate demonstration effectiveness metrics"""
        
        total_steps = self.demo_state["total_steps"]
        completed_steps = self.demo_state["current_step"]
        
        return {
            "completion_rate": completed_steps / total_steps if total_steps > 0 else 0,
            "audience_engagement": len(self.demo_state.get("audience_feedback", [])),
            "technical_success": self.demo_state["status"] == "completed",
            "key_findings_count": len(self._extract_key_findings()),
            "follow_up_actions_generated": len(self._generate_follow_up_actions())
        }
    
    def create_real_time_assessment(self, organization_name: str, applications: List[str]) -> Dict[str, Any]:
        """Create real-time security assessment for consulting engagement"""
        
        assessment_id = f"assessment_{organization_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        assessment = {
            "assessment_id": assessment_id,
            "organization": organization_name,
            "start_time": datetime.now().isoformat(),
            "applications": applications,
            "status": "in_progress",
            "real_time_findings": [],
            "risk_metrics": {},
            "recommendations": []
        }
        
        # Start assessment in background thread
        def run_assessment():
            try:
                for app in applications:
                    # Simulate real-time analysis
                    findings = self._analyze_application_real_time(app)
                    assessment["real_time_findings"].extend(findings)
                    
                    # Update risk metrics
                    self._update_risk_metrics(assessment, findings)
                    
                    # Generate recommendations
                    recommendations = self._generate_real_time_recommendations(findings)
                    assessment["recommendations"].extend(recommendations)
                
                assessment["status"] = "completed"
                assessment["end_time"] = datetime.now().isoformat()
                
                # Save assessment results
                assessment_filepath = self.output_dir / "assessments" / f"{assessment_id}.json"
                with open(assessment_filepath, "w") as f:
                    json.dump(assessment, f, indent=2, default=str)
                
                logger.info(f"Real-time assessment completed: {assessment_id}")
                
            except Exception as e:
                assessment["status"] = "failed"
                assessment["error"] = str(e)
                logger.error(f"Assessment failed: {e}")
        
        # Start assessment thread
        assessment_thread = threading.Thread(target=run_assessment)
        assessment_thread.start()
        
        return assessment
    
    def _analyze_application_real_time(self, application: str) -> List[Dict[str, Any]]:
        """Simulate real-time application analysis"""
        
        findings = []
        
        # Simulate various types of findings
        finding_types = [
            {
                "type": "credential_exposure",
                "severity": "high",
                "description": f"Hardcoded credentials found in {application}",
                "impact": "Unauthorized access to backend systems"
            },
            {
                "type": "vulnerability",
                "severity": "medium",
                "description": f"Input validation vulnerability in {application}",
                "impact": "Potential injection attacks"
            },
            {
                "type": "data_exposure",
                "severity": "high",
                "description": f"Sensitive data exposed in {application}",
                "impact": "Privacy and compliance violations"
            }
        ]
        
        # Randomly select findings for simulation
        import random
        selected_findings = random.sample(finding_types, random.randint(1, len(finding_types)))
        
        for finding in selected_findings:
            findings.append({
                "application": application,
                "timestamp": datetime.now().isoformat(),
                "finding_id": f"finding_{len(findings)+1}",
                **finding
            })
        
        return findings
    
    def _update_risk_metrics(self, assessment: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Update risk metrics based on new findings"""
        
        if "risk_metrics" not in assessment:
            assessment["risk_metrics"] = {
                "total_findings": 0,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 0,
                "overall_risk_score": 0
            }
        
        for finding in findings:
            assessment["risk_metrics"]["total_findings"] += 1
            
            severity = finding.get("severity", "low")
            if severity == "high":
                assessment["risk_metrics"]["high_severity"] += 1
            elif severity == "medium":
                assessment["risk_metrics"]["medium_severity"] += 1
            else:
                assessment["risk_metrics"]["low_severity"] += 1
        
        # Calculate overall risk score
        high_weight = 3
        medium_weight = 2
        low_weight = 1
        
        total_score = (assessment["risk_metrics"]["high_severity"] * high_weight +
                      assessment["risk_metrics"]["medium_severity"] * medium_weight +
                      assessment["risk_metrics"]["low_severity"] * low_weight)
        
        assessment["risk_metrics"]["overall_risk_score"] = total_score
    
    def _generate_real_time_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate real-time recommendations based on findings"""
        
        recommendations = []
        
        for finding in findings:
            if finding["type"] == "credential_exposure":
                recommendations.append({
                    "finding_id": finding["finding_id"],
                    "recommendation": "Immediately rotate exposed credentials",
                    "priority": "critical",
                    "timeline": "within 24 hours",
                    "effort": "low"
                })
            elif finding["type"] == "vulnerability":
                recommendations.append({
                    "finding_id": finding["finding_id"],
                    "recommendation": "Implement input validation and sanitization",
                    "priority": "high",
                    "timeline": "within 1 week",
                    "effort": "medium"
                })
            elif finding["type"] == "data_exposure":
                recommendations.append({
                    "finding_id": finding["finding_id"],
                    "recommendation": "Implement data encryption and access controls",
                    "priority": "high",
                    "timeline": "within 2 weeks",
                    "effort": "high"
                })
        
        return recommendations
    
    def create_portfolio_analysis(self, organization_name: str, applications: List[Dict[str, Any]]) -> PortfolioAnalysis:
        """Create comprehensive portfolio analysis for organizational risk assessment"""
        
        # Simulate portfolio analysis
        total_vulnerabilities = 0
        critical_findings = []
        risk_distribution = {"high": 0, "medium": 0, "low": 0}
        
        for app in applications:
            # Simulate analysis results for each application
            app_vulns = len(app.get("vulnerabilities", [])) or random.randint(1, 10)
            total_vulnerabilities += app_vulns
            
            # Simulate critical findings
            if app_vulns > 5:
                critical_findings.append({
                    "application": app["name"],
                    "finding": "Multiple high-severity vulnerabilities detected",
                    "risk_level": "critical",
                    "business_impact": "High risk of data breach"
                })
                risk_distribution["high"] += 1
            elif app_vulns > 2:
                risk_distribution["medium"] += 1
            else:
                risk_distribution["low"] += 1
        
        # Generate remediation roadmap
        remediation_roadmap = [
            {
                "phase": "Immediate (0-30 days)",
                "actions": [
                    "Rotate all exposed credentials",
                    "Patch critical vulnerabilities",
                    "Implement emergency monitoring"
                ],
                "cost_estimate": "$50,000",
                "risk_reduction": "60%"
            },
            {
                "phase": "Short-term (1-6 months)",
                "actions": [
                    "Implement secure development practices",
                    "Deploy automated security testing",
                    "Enhance access controls"
                ],
                "cost_estimate": "$200,000",
                "risk_reduction": "80%"
            },
            {
                "phase": "Long-term (6-12 months)",
                "actions": [
                    "Architecture security redesign",
                    "Comprehensive security training",
                    "Continuous security monitoring"
                ],
                "cost_estimate": "$500,000",
                "risk_reduction": "95%"
            }
        ]
        
        portfolio_analysis = PortfolioAnalysis(
            organization_name=organization_name,
            analysis_date=datetime.now(),
            applications_analyzed=len(applications),
            total_vulnerabilities=total_vulnerabilities,
            critical_findings=critical_findings,
            risk_distribution=risk_distribution,
            compliance_status={
                "GDPR": "Non-compliant" if any(f["risk_level"] == "critical" for f in critical_findings) else "Compliant",
                "SOX": "Requires attention",
                "PCI-DSS": "Assessment needed"
            },
            remediation_roadmap=remediation_roadmap,
            executive_summary=f"Analysis of {len(applications)} applications revealed {total_vulnerabilities} vulnerabilities with {len(critical_findings)} critical findings requiring immediate attention."
        )
        
        # Export portfolio analysis
        portfolio_filename = f"portfolio_{organization_name}_{datetime.now().strftime('%Y%m%d')}.json"
        portfolio_filepath = self.output_dir / "portfolios" / portfolio_filename
        
        with open(portfolio_filepath, "w") as f:
            json.dump(asdict(portfolio_analysis), f, indent=2, default=str)
        
        logger.info(f"Portfolio analysis completed for {organization_name}: {portfolio_filepath}")
        return portfolio_analysis

def main():
    """Main function for testing the live demonstration engine"""
    
    # Sample analysis results for testing
    sample_analysis_results = {
        "credentials_found": [
            {"type": "API_KEY", "value": "sk-***", "location": "0x1234"}
        ],
        "vulnerabilities": [
            {"type": "Buffer Overflow", "severity": "high", "cvss_score": 8.5}
        ]
    }
    
    # Initialize engine
    engine = LiveDemonstrationEngine()
    
    # Create executive demonstration
    exec_demo = engine.create_client_demonstration("executive", sample_analysis_results)
    print(f"Created executive demonstration: {exec_demo.title}")
    print(f"Duration: {exec_demo.total_duration} seconds")
    print(f"Steps: {len(exec_demo.steps)}")
    
    # Execute demonstration (simulated)
    def progress_callback(state):
        print(f"Progress: Step {state['current_step']}/{state['total_steps']} - {state['status']}")
    
    try:
        report = engine.execute_live_demonstration(exec_demo, progress_callback)
        print(f"Demonstration completed successfully")
        print(f"Key findings: {len(report['key_findings'])}")
    except Exception as e:
        print(f"Demonstration failed: {e}")
    
    # Create portfolio analysis
    sample_applications = [
        {"name": "WebApp1", "vulnerabilities": ["XSS", "SQL Injection"]},
        {"name": "MobileApp1", "vulnerabilities": ["Hardcoded Keys"]},
        {"name": "DesktopApp1", "vulnerabilities": ["Buffer Overflow", "Privilege Escalation"]}
    ]
    
    portfolio = engine.create_portfolio_analysis("ACME Corp", sample_applications)
    print(f"Portfolio analysis completed for {portfolio.organization_name}")
    print(f"Applications analyzed: {portfolio.applications_analyzed}")
    print(f"Total vulnerabilities: {portfolio.total_vulnerabilities}")

if __name__ == "__main__":
    main()