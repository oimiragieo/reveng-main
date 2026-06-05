"""Sanity checks for AI enhanced data model imports."""

from reveng.agents.ai.ai_enhanced_data_models import ConfidenceLevel, EvidenceTracker, MITREMapping


def test_confidence_level_enum_contains_expected_members():
    assert ConfidenceLevel.HIGH.value == "HIGH"
    assert "VERY_HIGH" in {member.value for member in ConfidenceLevel}
    assert "MEDIUM" in {member.value for member in ConfidenceLevel}
    assert "LOW" in {member.value for member in ConfidenceLevel}
    assert "VERY_LOW" in {member.value for member in ConfidenceLevel}


def test_evidence_tracker_records_items():
    tracker = EvidenceTracker()
    # add_evidence takes individual parameters, not Evidence object
    tracker.add_evidence(
        evidence_type="test_evidence",
        description="Test",
        source="unit-test",
        confidence=0.7,  # Now takes float, not enum
    )

    # Evidence is stored in evidence_chain attribute
    assert len(tracker.evidence_chain) == 1
    assert tracker.evidence_chain[0].description == "Test"


def test_mitre_mapping_serialises_round_trip():
    # MITREMapping uses plural fields: tactics and techniques (as lists)
    from dataclasses import asdict

    mapping = MITREMapping(tactics=["TA0001"], techniques=["T1234"])
    serialised = asdict(mapping)  # Use dataclasses.asdict instead of to_dict

    assert "TA0001" in serialised["tactics"]
    assert "T1234" in serialised["techniques"]
