"""Regression tests for VirusTotalConnector.enrich_analysis.

Task 1.14: enrich_analysis raised KeyError when the input analysis dict
lacked a "threat_intel" key and the hash was not found on VirusTotal,
because the not-found branch assumed enriched["threat_intel"] already
existed.
"""

from reveng.tools.threat_intel.virustotal_connector import VirusTotalConnector


def _make_connector():
    """Build a connector instance without invoking __init__.

    __init__ requires the optional 'vt' package and a real API key, neither
    of which is needed to exercise enrich_analysis once lookup_hash is stubbed.
    """
    return object.__new__(VirusTotalConnector)


def test_enrich_analysis_not_found_without_threat_intel_key():
    """No KeyError when input lacks 'threat_intel' and hash is not found."""
    connector = _make_connector()
    # Simulate "file not found on VirusTotal".
    connector.lookup_hash = lambda sha256: None

    analysis_results = {"sha256": "a" * 64}  # no "threat_intel" key

    enriched = connector.enrich_analysis(analysis_results)

    assert "threat_intel" in enriched
    assert enriched["threat_intel"]["virustotal"]["status"] == "not_found"
