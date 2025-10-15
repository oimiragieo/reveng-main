#!/usr/bin/env python3
"""Educational Content and Awareness Campaign Generator"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SocialMediaPost:
    platform: str
    title: str
    content: str
    hashtags: List[str]
    call_to_action: str

class EducationalContentGenerator:
    def __init__(self, output_dir: str = "educational_content"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "social_media").mkdir(exist_ok=True)
        (self.output_dir / "blog_posts").mkdir(exist_ok=True)
        (self.output_dir / "presentations").mkdir(exist_ok=True)
        (self.output_dir / "visualizations").mkdir(exist_ok=True)
        logger.info(f"Educational content generator initialized: {self.output_dir}")
    
    def create_social_media_content(self, analysis_results: Dict[str, Any]) -> List[SocialMediaPost]:
        posts = [
            SocialMediaPost(
                platform="twitter",
                title="AI Security Revolution",
                content="Modern AI can reverse engineer ANY software in minutes. #CyberSecurity #AI",
                hashtags=["CyberSecurity", "AI", "InfoSec"],
                call_to_action="RT to spread awareness"
            )
        ]
        
        for i, post in enumerate(posts):
            filename = f"social_post_{i+1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = self.output_dir / "social_media" / filename
            with open(filepath, "w") as f:
                json.dump(asdict(post), f, indent=2)
        
        logger.info(f"Created {len(posts)} social media posts")
        return posts
    
    def create_blog_content(self, analysis_results: Dict[str, Any]) -> List[str]:
        blog_content = """# The AI Security Revolution

Modern AI tools have fundamentally changed cybersecurity. Traditional assumptions about code security are obsolete.

## Key Points:
- AI can reverse engineer binaries in minutes
- Hardcoded credentials are easily extracted
- Business logic can be reconstructed
- Vulnerability discovery is automated

## Conclusion:
Organizations must adapt their security strategies for the AI era.
"""
        
        filename = f"blog_post_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = self.output_dir / "blog_posts" / filename
        with open(filepath, "w") as f:
            f.write(blog_content)
        
        logger.info("Created blog post")
        return [str(filepath)]
    
    def create_conference_presentations(self, analysis_results: Dict[str, Any]) -> List[str]:
        presentation_content = """# The AI Security Revolution
## Demonstrating Modern Reverse Engineering Capabilities

### Slide 1: The New Threat Landscape
- AI can reverse engineer any compiled software in minutes
- Hardcoded secrets are easily extracted
- Business logic can be reconstructed

### Slide 2: Live Demonstration
- Upload and analyze a compiled binary
- Extract credentials and API keys
- Reconstruct source code

### Slide 3: Security Strategy Implications
- Assume all code will be reverse engineered
- Implement defense-in-depth strategies
- Regular AI-powered security assessments
"""
        
        filename = f"presentation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = self.output_dir / "presentations" / filename
        with open(filepath, "w") as f:
            f.write(presentation_content)
        
        logger.info("Created conference presentation")
        return [str(filepath)]
    
    def create_risk_visualization(self, analysis_results: Dict[str, Any], viz_type: str) -> str:
        viz_content = f"""# {viz_type.replace('_', ' ').title()} Visualization
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Analysis Results Summary
"""
        
        if "vulnerabilities" in analysis_results:
            viz_content += "\n### Vulnerabilities Found:\n"
            for vuln in analysis_results["vulnerabilities"]:
                viz_content += f"- {vuln.get('type', 'Unknown')}: {vuln.get('severity', 'Unknown')} severity\n"
        
        filename = f"visualization_{viz_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = self.output_dir / "visualizations" / filename
        with open(filepath, "w") as f:
            f.write(viz_content)
        
        logger.info(f"Visualization created: {filepath}")
        return str(filepath)
    
    def generate_comprehensive_campaign(self, analysis_results: Dict[str, Any], campaign_name: str) -> Dict[str, Any]:
        logger.info(f"Generating comprehensive campaign: {campaign_name}")
        
        # Create all content types
        visualizations = []
        for viz_type in ["risk_matrix", "vulnerability_distribution", "threat_timeline"]:
            viz_path = self.create_risk_visualization(analysis_results, viz_type)
            visualizations.append(viz_path)
        
        social_media_posts = self.create_social_media_content(analysis_results)
        blog_posts = self.create_blog_content(analysis_results)
        presentations = self.create_conference_presentations(analysis_results)
        
        campaign_summary = {
            "campaign_name": campaign_name,
            "generated_date": datetime.now().isoformat(),
            "content_summary": {
                "visualizations": len(visualizations),
                "social_media_posts": len(social_media_posts),
                "blog_posts": len(blog_posts),
                "presentations": len(presentations)
            }
        }
        
        summary_path = self.output_dir / f"campaign_summary_{campaign_name}.json"
        with open(summary_path, "w") as f:
            json.dump(campaign_summary, f, indent=2)
        
        logger.info(f"Campaign generated successfully: {summary_path}")
        return campaign_summary

def main():
    sample_results = {
        "vulnerabilities": [
            {"type": "SQL Injection", "severity": "High"},
            {"type": "XSS", "severity": "Medium"},
            {"type": "Credential Exposure", "severity": "High"}
        ]
    }
    
    generator = EducationalContentGenerator()
    campaign = generator.generate_comprehensive_campaign(sample_results, "ai_security_demo")
    print("Educational content generation completed!")
    print(f"Campaign summary: {json.dumps(campaign, indent=2)}")

if __name__ == "__main__":
    main()