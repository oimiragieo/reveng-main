#!/usr/bin/env python3
"""Test script for educational content generator"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tools'))

# Import the module directly
import educational_content_generator

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
generator = educational_content_generator.EducationalContentGenerator()

# Generate comprehensive campaign
campaign = generator.generate_comprehensive_campaign(sample_results, "ai_security_revolution_demo")

print("Educational content generation completed!")
print(f"Campaign summary generated with {campaign['content_summary']['social_media_posts']} social media posts, {campaign['content_summary']['blog_posts']} blog posts, and {campaign['content_summary']['presentations']} presentations")