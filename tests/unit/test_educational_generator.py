"""Tests for the educational content generator."""

from pathlib import Path

import pytest

from reveng.tools.utils.educational_content_generator import EducationalContentGenerator


@pytest.fixture()
def sample_results() -> dict:
    return {
        "vulnerabilities": [
            {
                "type": "SQL Injection",
                "severity": "High",
                "impact": "high",
                "likelihood": "medium",
            },
            {
                "type": "XSS",
                "severity": "Medium",
                "impact": "medium",
                "likelihood": "high",
            },
        ],
        "corporate_exposure": {
            "credentials_found": 3,
            "api_endpoints": 2,
            "business_logic_exposed": True,
        },
        "threat_intelligence": {
            "apt_attribution": "APT29",
            "confidence": 0.85,
            "iocs_found": 5,
        },
    }


def test_generator_creates_output_directories(tmp_path: Path, sample_results: dict):
    generator = EducationalContentGenerator(output_dir=str(tmp_path))

    campaign = generator.generate_comprehensive_campaign(sample_results, "security_demo")

    assert "content_summary" in campaign
    summary = campaign["content_summary"]
    assert summary["social_media_posts"] >= 1
    assert summary["blog_posts"] >= 1

    # Ensure files were written
    for folder in ("visualizations", "social_media", "blog_posts", "presentations"):
        assert any(Path(tmp_path / folder).iterdir()), f"Expected artefacts in {folder}"
