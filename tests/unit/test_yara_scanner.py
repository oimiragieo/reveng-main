"""Unit tests for built-in YARA malware classification support."""

from pathlib import Path

import pytest

from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import REVENGEnterpriseServer
from reveng.security.yara_scanner import YARAScanner

EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_builtin_ruleset_contains_at_least_twenty_rules():
    scanner = YARAScanner()

    assert len(scanner.builtin_rules) >= 20


def test_scan_pe_with_eicar_string_returns_a_builtin_match(tmp_path):
    sample = tmp_path / "eicar_sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64 + EICAR_STRING)

    scanner = YARAScanner()
    matches = scanner.scan_file(str(sample))
    match_names = {match.rule_name.lower() for match in matches}

    assert any("eicar" in match_name for match_name in match_names)


def test_classify_file_returns_family_confidence_and_matched_rules():
    scanner = YARAScanner()

    result = scanner.classify_file(
        str(Path("test_samples") / "sample.exe"),
        use_ollama_family_naming=False,
    )

    assert result["family"]
    assert 0.0 <= result["confidence"] <= 1.0
    assert isinstance(result["matched_rules"], list)
    assert isinstance(result["indicators"], list)


@pytest.mark.asyncio
async def test_mcp_classify_malware_returns_structured_response():
    server = REVENGEnterpriseServer(enable_rate_limiting=False, enable_audit_log=False)

    result = await server.classify_malware(
        {
            "path": str(Path("test_samples") / "sample.exe"),
            "use_ollama_family_naming": False,
        }
    )

    assert result["family"]
    assert 0.0 <= result["confidence"] <= 1.0
    assert isinstance(result["matched_rules"], list)
    assert isinstance(result["indicators"], list)
    assert "coming soon" not in result["content"][0]["text"].lower()
