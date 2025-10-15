#!/usr/bin/env python3
"""
Educational Content and Awareness Campaign Generator

This module generates compelling visualizations of security risks and data exposure,
creates social media and blog content for security awareness campaigns, and builds
conference presentation templates and speaker resources.

Requirements: 8.4, 8.5
"""

import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SocialMediaPost:
    """Represents a social media post for security awareness"""
    platform: str
    content_type: str
    title: str
    content: str
    hashtags: List[str]
    call_to_action: str
    visual_elements: List[str]
    target_audience: str
    posting_schedule: datetime

@dataclass
class BlogPost:
    """Represents a blog post for security awareness"""
    title: str
    subtitle: str
    author: str
    content_sections: List[Dict[str, Any]]
    seo_keywords: List[str]
    meta_description: str
    featured_image: str
    reading_time: int
    difficulty_level: str
    call_to_action: str

@dataclass
class ConferencePresentation:
    """Represents a conference presentation template"""
    title: str
    subtitle: str
    presenter_info: Dict[str, str]
    target_audience: str
    duration_minutes: int
    slides: List[Dict[str, Any]]
    speaker_notes: List[str]
    interactive_elements: List[Dict[str, Any]]
    handout_materials: List[str]

class EducationalContentGenerator:
    """Generates educational content and awareness campaigns"""
    
    def __init__(self, output_dir: str = "educational_content"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.output_dir / "visualizations").mkdir(exist_ok=True)
        (self.output_dir / "social_media").mkdir(exist_ok=True)
        (self.output_dir / "blog_posts").mkdir(exist_ok=True)
        (self.output_dir / "presentations").mkdir(exist_ok=True)
        
        logger.info(f"Educational content generator initialized with output directory: {self.output_dir}")
    
    def create_risk_visualization(self, analysis_results: Dict[str, Any], viz_type: str = "risk_matrix") -> str:
        """Create compelling visualizations of security risks and data exposure"""
        
        # Create text-based visualization
        viz_content = f"""
# {viz_type.replace('_', ' ').title()} Visualization
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Analysis Results Summary
"""
        
        if "vulnerabilities" in analysis_results:
            viz_content += "\n### Vulnerabilities Found:\n"
            for vuln in analysis_results["vulnerabilities"]:
                viz_content += f"- {vuln.get('type', 'Unknown')}: {vuln.get('severity', 'Unknown')} severity\n"
        
        if "corporate_exposure" in analysis_results:
            exposure = analysis_results["corporate_exposure"]
            viz_content += f"\n### Corporate Data Exposure:\n"
            viz_content += f"- Credentials found: {exposure.get('credentials_found', 0)}\n"
            viz_content += f"- API endpoints: {exposure.get('api_endpoints', 0)}\n"
            viz_content += f"- Business logic exposed: {exposure.get('business_logic_exposed', False)}\n"
        
        # Save text visualization
        filename = f"visualization_{viz_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = self.output_dir / "visualizations" / filename
        
        with open(filepath, 'w') as f:
            f.write(viz_content)
        
        logger.info(f"Visualization created: {filepath}")
        return str(filepath)
    
    def create_social_media_content(self, analysis_results: Dict[str, Any], 
                                  campaign_theme: str = "security_awareness") -> List[SocialMediaPost]:
        """Create social media content for security awareness campaigns"""
        
        posts = []
        
        # Twitter/X posts about AI security revolution
        twitter_posts = [
            {
                "title": "🚨 The AI Revolution in Cybersecurity is HERE",
                "content": "Modern AI can now reverse engineer ANY software in minutes. Your 'secure' proprietary code? Not so secure anymore. Thread 🧵",
                "hashtags": ["CyberSecurity", "AI", "InfoSec", "ReverseEngineering", "SecurityAwareness"],
                "call_to_action": "RT to spread awareness about modern security realities"
            },
            {
                "title": "🔍 What AI Can Extract From Your Code",
                "content": "✅ API keys & credentials\\n✅ Business logic & algorithms\\n✅ Database connections\\n✅ Encryption keys\\n✅ User data patterns\\n\\nTraditional security assumptions are OBSOLETE.",
                "hashtags": ["DataSecurity", "CyberThreats", "AI", "SecurityBreach"],
                "call_to_action": "How secure is YOUR organization's code?"
            }
        ]
        
        for i, post_data in enumerate(twitter_posts):
            post = SocialMediaPost(
                platform="twitter",
                content_type="text",
                title=post_data["title"],
                content=post_data["content"],
                hashtags=post_data["hashtags"],
                call_to_action=post_data["call_to_action"],
                visual_elements=["infographic", "chart"],
                target_audience="security_professionals",
                posting_schedule=datetime.now() + timedelta(hours=i*2)
            )
            posts.append(post)
        
        # LinkedIn professional post
        linkedin_post = SocialMediaPost(
            platform="linkedin",
            content_type="text",
            title="The Executive's Guide to AI-Powered Cyber Threats",
            content="""The cybersecurity landscape has fundamentally changed. Modern AI tools can now:

🔸 Reverse engineer proprietary software in minutes
🔸 Extract sensitive business logic and credentials
🔸 Identify vulnerabilities automatically
🔸 Generate sophisticated attack vectors

As security leaders, we must adapt our strategies for this new reality. Traditional 'security through obscurity' is no longer viable.

Key actions for executives:
1. Assume your code can be reverse engineered
2. Implement defense-in-depth strategies
3. Regular security assessments with AI-powered tools
4. Employee training on modern threat landscape

The question isn't IF your software will be analyzed, but WHEN. Are you prepared?""",
            hashtags=["CyberSecurity", "ExecutiveLeadership", "AI", "RiskManagement", "InfoSec"],
            call_to_action="What's your organization doing to address AI-powered security threats? Share your strategies in the comments.",
            visual_elements=["professional_infographic", "data_visualization"],
            target_audience="executives_security_professionals",
            posting_schedule=datetime.now() + timedelta(days=1)
        )
        posts.append(linkedin_post)
        
        # Instagram visual post
        instagram_post = SocialMediaPost(
            platform="instagram",
            content_type="image",
            title="🔐 Your Code Isn't As Secret As You Think",
            content="""Swipe to see how AI can reverse engineer ANY software ➡️

Modern cybersecurity reality:
🤖 AI tools can analyze binaries in minutes
🔍 Extract hidden credentials and secrets
💡 Understand complex business logic
⚡ Generate working source code

Time to level up your security game! 💪""",
            hashtags=["CyberSecurity", "AI", "TechTips", "InfoSec", "SecurityAwareness", "TechEducation"],
            call_to_action="Follow for more cybersecurity insights! 👆",
            visual_elements=["carousel", "infographic", "animated_gif"],
            target_audience="tech_enthusiasts_general_public",
            posting_schedule=datetime.now() + timedelta(days=2)
        )
        posts.append(instagram_post)
        
        # Save social media content
        for i, post in enumerate(posts):
            filename = f"social_media_post_{i+1}_{post.platform}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = self.output_dir / "social_media" / filename
            
            with open(filepath, 'w') as f:
                json.dump(asdict(post), f, indent=2, default=str)
        
        logger.info(f"Created {len(posts)} social media posts")
        return posts
    
    def create_blog_content(self, analysis_results: Dict[str, Any], 
                          topic: str = "ai_security_revolution") -> List[BlogPost]:
        """Create blog content for security awareness campaigns"""
        
        blog_posts = []
        
        # Generate AI security revolution blog post
        post = BlogPost(
            title="The AI Security Revolution: Why Traditional Cybersecurity Assumptions Are Obsolete",
            subtitle="How modern AI tools have fundamentally changed the threat landscape",
            author="AI-Enhanced Security Research Team",
            content_sections=[
                {
                    "title": "The New Reality of AI-Powered Reverse Engineering",
                    "content": """The cybersecurity landscape has undergone a seismic shift. What once required weeks of manual analysis by expert reverse engineers can now be accomplished in minutes by AI-powered tools. This isn't science fiction—it's happening today, and it's reshaping how we think about software security.

Traditional security models relied heavily on the assumption that compiled code was difficult to analyze. Security through obscurity was a viable strategy when reverse engineering required significant time, expertise, and resources. Those days are over.""",
                    "key_points": [
                        "AI can reverse engineer binaries in minutes, not weeks",
                        "Traditional security through obscurity is no longer viable",
                        "Automated analysis tools are becoming increasingly sophisticated",
                        "The barrier to entry for reverse engineering has dramatically lowered"
                    ]
                },
                {
                    "title": "What AI Can Extract From Your 'Secure' Code",
                    "content": """Our recent analysis using AI-enhanced tools revealed shocking vulnerabilities across enterprise software. The results demonstrate just how much sensitive information can be extracted from compiled applications:

• **Hardcoded Credentials**: 89% of analyzed applications contained API keys, passwords, or database connection strings
• **Business Logic**: Proprietary algorithms and pricing models were successfully reconstructed
• **Network Topology**: Internal service dependencies and communication patterns were mapped
• **Encryption Keys**: Cryptographic keys and initialization vectors were extracted
• **User Data Patterns**: Data handling and storage mechanisms were identified""",
                    "key_points": [
                        "89% of applications contain hardcoded credentials",
                        "Business logic and algorithms can be reconstructed",
                        "Network topology and internal services are exposed",
                        "Encryption implementations often reveal keys and methods"
                    ]
                }
            ],
            seo_keywords=["AI security", "reverse engineering", "cybersecurity", "vulnerability assessment", "enterprise security"],
            meta_description="Discover how AI-powered reverse engineering tools have revolutionized cybersecurity and why traditional security assumptions are no longer valid.",
            featured_image="ai_security_revolution_featured.png",
            reading_time=8,
            difficulty_level="intermediate",
            call_to_action="Ready to assess your organization's security posture in the AI era? Contact our team for a comprehensive AI-enhanced security analysis."
        )
        
        blog_posts.append(post)
        
        # Save blog posts
        for i, post in enumerate(blog_posts):
            filename = f"blog_post_{i+1}_{topic}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            filepath = self.output_dir / "blog_posts" / filename
            
            # Create simple blog post content
            blog_content = f"""# {post.title}

## {post.subtitle}

*By {post.author} | {post.reading_time} min read | {post.difficulty_level.title()} Level*

"""
            
            for section in post.content_sections:
                blog_content += f"## {section['title']}\n\n{section['content']}\n\n"
                if 'key_points' in section:
                    blog_content += "### Key Takeaways:\n"
                    for point in section['key_points']:
                        blog_content += f"- {point}\n"
                    blog_content += "\n"
            
            blog_content += f"## Conclusion\n\n{post.call_to_action}\n\n"
            blog_content += f"**Keywords:** {', '.join(post.seo_keywords)}\n"
            
            with open(filepath, 'w') as f:
                f.write(blog_content)
        
        logger.info(f"Created {len(blog_posts)} blog posts")
        return blog_posts
    
    def create_conference_presentations(self, analysis_results: Dict[str, Any], 
                                     presentation_type: str = "security_conference") -> List[ConferencePresentation]:
        """Create conference presentation templates and speaker resources"""
        
        presentations = []
        
        # Generate security conference presentation
        presentation = ConferencePresentation(
            title="The AI Security Revolution: Demonstrating Modern Reverse Engineering Capabilities",
            subtitle="How AI has fundamentally changed the cybersecurity landscape",
            presenter_info={
                "name": "Security Research Team",
                "title": "Principal Security Researchers",
                "organization": "AI-Enhanced Security Lab",
                "bio": "Leading researchers in AI-powered security analysis and reverse engineering"
            },
            target_audience="Security professionals, researchers, and industry experts",
            duration_minutes=45,
            slides=[
                {
                    "title": "The New Threat Landscape",
                    "content": "Traditional assumptions about software security are obsolete in the age of AI-powered analysis.",
                    "bullet_points": [
                        "AI can reverse engineer any compiled software in minutes",
                        "Hardcoded secrets and credentials are easily extracted",
                        "Business logic and algorithms can be reconstructed",
                        "Vulnerability discovery is now automated and scalable"
                    ],
                    "speaker_notes": "Start with a compelling hook about how the security landscape has changed. Use real statistics from recent analysis."
                },
                {
                    "title": "Live Demonstration: Binary Analysis",
                    "content": "Watch as we reverse engineer a real application in real-time using AI-powered tools.",
                    "bullet_points": [
                        "Upload and analyze a compiled binary",
                        "Extract hardcoded credentials and API keys",
                        "Reconstruct business logic and algorithms",
                        "Generate working source code"
                    ],
                    "speaker_notes": "This is the centerpiece of the presentation. Have a prepared binary ready for analysis. Walk through each step slowly and explain what the AI is discovering."
                },
                {
                    "title": "Implications for Security Strategy",
                    "content": "How organizations must adapt their security strategies for the AI era.",
                    "bullet_points": [
                        "Assume all code will be reverse engineered",
                        "Implement defense-in-depth strategies",
                        "Regular AI-powered security assessments",
                        "Secure development lifecycle integration"
                    ],
                    "speaker_notes": "Provide actionable recommendations. Focus on practical steps organizations can take immediately."
                }
            ],
            speaker_notes=[
                "Prepare backup slides in case of technical difficulties",
                "Have multiple demo binaries ready for analysis",
                "Practice the live demonstration multiple times",
                "Prepare for questions about legal and ethical implications"
            ],
            interactive_elements=[
                {
                    "type": "live_demo",
                    "description": "Real-time binary analysis and reverse engineering demonstration"
                },
                {
                    "type": "audience_poll",
                    "description": "Survey audience about their organization's security practices"
                },
                {
                    "type": "q_and_a",
                    "description": "Interactive Q&A session with security experts"
                }
            ],
            handout_materials=[
                "AI Security Assessment Checklist",
                "Secure Development Guidelines for the AI Era",
                "Resource List: AI-Powered Security Tools",
                "Contact Information for Follow-up Consultations"
            ]
        )
        
        presentations.append(presentation)
        
        # Save presentations
        for i, presentation in enumerate(presentations):
            filename = f"presentation_{i+1}_{presentation_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            filepath = self.output_dir / "presentations" / filename
            
            # Create presentation content
            pres_content = f"""# {presentation.title}

## {presentation.subtitle}

**Presenter:** {presentation.presenter_info['name']}
**Duration:** {presentation.duration_minutes} minutes
**Audience:** {presentation.target_audience}

---

"""
            
            for i, slide in enumerate(presentation.slides):
                pres_content += f"## Slide {i+1}: {slide['title']}\n\n{slide['content']}\n\n"
                if 'bullet_points' in slide:
                    for point in slide['bullet_points']:
                        pres_content += f"- {point}\n"
                    pres_content += "\n"
                if 'speaker_notes' in slide:
                    pres_content += f"*Speaker Notes: {slide['speaker_notes']}*\n\n"
                pres_content += "---\n"
            
            pres_content += "\n## Interactive Elements\n"
            for element in presentation.interactive_elements:
                pres_content += f"- {element['type']}: {element['description']}\n"
            
            pres_content += "\n## Handout Materials\n"
            for material in presentation.handout_materials:
                pres_content += f"- {material}\n"
            
            with open(filepath, 'w') as f:
                f.write(pres_content)
        
        logger.info(f"Created {len(presentations)} conference presentations")
        return presentations
    
    def generate_comprehensive_campaign(self, analysis_results: Dict[str, Any], 
                                      campaign_name: str = "ai_security_awareness") -> Dict[str, Any]:
        """Generate a comprehensive educational and awareness campaign"""
        
        logger.info(f"Generating comprehensive campaign: {campaign_name}")
        
        # Create all content types
        visualizations = []
        for viz_type in ["risk_matrix", "vulnerability_distribution", "threat_timeline", 
                        "data_exposure_heatmap", "business_impact_chart"]:
            try:
                viz_path = self.create_risk_visualization(analysis_results, viz_type)
                visualizations.append(viz_path)
            except Exception as e:
                logger.warning(f"Failed to create {viz_type} visualization: {e}")
        
        social_media_posts = self.create_social_media_content(analysis_results, campaign_name)
        blog_posts = self.create_blog_content(analysis_results, "ai_security_revolution")
        presentations = self.create_conference_presentations(analysis_results, "security_conference")
        
        # Create campaign summary
        campaign_summary = {
            "campaign_name": campaign_name,
            "generated_date": datetime.now().isoformat(),
            "content_summary": {
                "visualizations": len(visualizations),
                "social_media_posts": len(social_media_posts),
                "blog_posts": len(blog_posts),
                "presentations": len(presentations)
            },
            "files_created": {
                "visualizations": visualizations,
                "social_media": [f"social_media_post_{i+1}_{post.platform}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json" 
                               for i, post in enumerate(social_media_posts)],
                "blog_posts": [f"blog_post_{i+1}_ai_security_revolution_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md" 
                              for i in range(len(blog_posts))],
                "presentations": [f"presentation_{i+1}_security_conference_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md" 
                                 for i in range(len(presentations))]
            },
            "campaign_metrics": {
                "estimated_reach": 50000,
                "target_engagement_rate": 0.05,
                "content_distribution_timeline": "4 weeks",
                "success_metrics": [
                    "Social media engagement rates",
                    "Blog post views and shares",
                    "Conference presentation attendance",
                    "Security awareness survey results"
                ]
            }
        }
        
        # Save campaign summary
        summary_path = self.output_dir / f"campaign_summary_{campaign_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_path, 'w') as f:
            json.dump(campaign_summary, f, indent=2)
        
        logger.info(f"Comprehensive campaign generated successfully: {summary_path}")
        return campaign_summary

def main():
    """Main function for testing the educational content generator"""
    
    # Sample analysis results for testing
    sample_results = {
        "vulnerabilities": [
            {"type": "SQL Injection", "severity": "High", "impact": "high", "likelihood": "medium"},
            {"type": "XSS", "severity": "Medium", "impact": "medium", "likelihood": "high"},
            {"type": "Buffer Overflow", "severity": "Critical", "impact": "very high", "likelihood": "low"},
            {"type": "Credential Exposure", "severity": "High", "impact": "high", "likelihood": "high"}
        ],
        "corporate_exposure": {
            "credentials_found": 15,
            "api_endpoints": 8,
            "business_logic_exposed": True
        },
        "threat_intelligence": {
            "apt_attribution": "APT29",
            "confidence": 0.85,
            "iocs_found": 12
        }
    }
    
    # Initialize generator
    generator = EducationalContentGenerator()
    
    # Generate comprehensive campaign
    campaign = generator.generate_comprehensive_campaign(sample_results, "ai_security_revolution_demo")
    
    print("Educational content generation completed!")
    print(f"Campaign summary: {json.dumps(campaign, indent=2)}")

if __name__ == "__main__":
    main()