"""Unit tests for the current BusinessLogicExtractor API."""

from pathlib import Path

import pytest

from reveng.analysis.analyzers.business_logic_extractor import (
    ApplicationDomain,
    BusinessLogicAnalysis,
    BusinessLogicExtractor,
    DataFlow,
    DataFlowType,
    FileOperation,
    ReportInfo,
)


@pytest.fixture
def extractor() -> BusinessLogicExtractor:
    return BusinessLogicExtractor()


def test_analyze_application_domain_extracts_real_business_signals(
    extractor: BusinessLogicExtractor,
    tmp_path: Path,
):
    binary_path = tmp_path / "business_logic_sample.exe"
    binary_path.write_bytes(
        b"MZ\x90\x00"
        + b"vulnerability\x00security\x00audit\x00malware\x00"
        + b".nessus\x00summary.xlsx\x00https://api.example.com\x00"
        + b"database\x00query\x00encrypt\x00authentication\x00"
        + b"CreateFile\x00socket\x00connect\x00excel\x00report\x00"
    )

    result = extractor.analyze_application_domain(str(binary_path))

    assert isinstance(result, BusinessLogicAnalysis)
    assert result.application_domain == ApplicationDomain.SECURITY.value
    assert result.confidence_score == pytest.approx(1.0)
    assert any(
        flow.source == "Nessus XML" and flow.destination == "Excel Report"
        for flow in result.data_flows
    )
    assert {
        (operation.operation_type, operation.file_extension) for operation in result.file_operations
    } >= {("read", ".nessus"), ("write", ".xlsx")}
    assert result.report_generation is not None
    assert result.report_generation.report_type == "Excel Report"
    assert result.report_generation.output_format == "XLSX"
    assert any("api.example.com" in value for value in result.network_operations)
    assert {"database", "query"} <= set(result.database_operations)
    assert {"encrypt", "authentication", "malware"} <= set(result.security_features)
    assert "createfile" in result.behavioral_patterns["file_operations"]
    assert {"socket", "connect"} <= set(result.behavioral_patterns["network_operations"])


def test_analyze_application_domain_returns_unknown_for_missing_binary(
    extractor: BusinessLogicExtractor,
    tmp_path: Path,
):
    result = extractor.analyze_application_domain(str(tmp_path / "missing.exe"))

    assert result.application_domain == ApplicationDomain.UNKNOWN.value
    assert result.data_flows == []
    assert result.file_operations == []
    assert result.report_generation is None
    assert result.network_operations == []
    assert result.database_operations == []
    assert result.security_features == []
    assert result.behavioral_patterns == {
        "file_operations": [],
        "network_operations": [],
        "registry_operations": [],
        "process_operations": [],
        "gui_operations": [],
    }
    assert result.confidence_score == pytest.approx(0.1)


def test_extract_strings_keeps_printable_sequences_of_length_four_or_more(
    extractor: BusinessLogicExtractor,
    tmp_path: Path,
):
    binary_path = tmp_path / "strings.exe"
    binary_path.write_bytes(b"MZ\x90\x00abc\x00" + b"query\x00auth\x00" + b"\xff\x00" + b"tls1\x00")

    strings = extractor._extract_strings(str(binary_path))

    assert "abc" not in strings
    assert {"query", "auth", "tls1"} <= set(strings)


def test_supporting_extractors_and_loaders_expose_current_patterns(
    extractor: BusinessLogicExtractor,
):
    data_flows = extractor._extract_data_flows([".xml", "report.pdf", ".csv", "data.json"])
    file_operations = extractor._extract_file_operations([".nessus", "report.pdf", "data.json"])
    report = extractor._detect_report_generation(["html", "report", "template"])
    network_operations = extractor._extract_network_operations(
        ["https://example.com", "ftp://mirror.example.net", "198.51.100.10"]
    )
    behavior = extractor._analyze_behavioral_patterns(
        ["CreateProcess", "RegOpenKey", "CreateWindow"]
    )

    assert {(flow.source, flow.destination, flow.flow_type) for flow in data_flows} == {
        ("XML Data", "PDF Report", DataFlowType.PROCESSING),
        ("CSV Data", "JSON Output", DataFlowType.PROCESSING),
    }
    assert {
        (operation.operation_type, operation.file_extension) for operation in file_operations
    } == {("read", ".nessus"), ("write", ".pdf"), ("write", ".json")}
    assert report is not None
    assert report.report_type == "HTML Report"
    assert report.output_format == "HTML"
    assert {
        "https://example.com",
        "ftp://mirror.example.net",
        "198.51.100.10",
    } <= set(network_operations)
    assert behavior["process_operations"] == ["createprocess"]
    assert behavior["registry_operations"] == ["regopenkey"]
    assert behavior["gui_operations"] == ["createwindow"]

    domain_indicators = extractor._load_domain_indicators()
    assert set(domain_indicators) == {
        ApplicationDomain.SECURITY.value,
        ApplicationDomain.REPORTING.value,
        ApplicationDomain.DATABASE.value,
        ApplicationDomain.WEB_SERVICE.value,
        ApplicationDomain.MALWARE.value,
        ApplicationDomain.UTILITY.value,
        ApplicationDomain.GAME.value,
        ApplicationDomain.MEDIA.value,
    }
    assert all(domain_indicators[domain] for domain in domain_indicators)
    assert len(extractor._load_data_flow_patterns()) == 3
    assert len(extractor._load_file_operation_patterns()) == 5
    assert len(extractor._load_report_indicators()) == 3


def test_calculate_confidence_score_tracks_available_evidence(
    extractor: BusinessLogicExtractor,
):
    high_confidence = extractor._calculate_confidence_score(
        ApplicationDomain.SECURITY.value,
        [
            DataFlow(
                source="Nessus XML",
                destination="Excel Report",
                flow_type=DataFlowType.PROCESSING,
                data_format="XML to XLSX",
                description="Vulnerability data export",
                confidence=0.9,
            )
        ],
        [
            FileOperation(
                operation_type="write",
                file_extension=".xlsx",
                file_path_pattern="*.xlsx",
                description="Excel output",
                frequency=1,
            )
        ],
        ReportInfo(
            report_type="Excel Report",
            output_format="XLSX",
            template_indicators=["template"],
            data_sources=["vulnerability"],
            confidence=0.9,
        ),
    )
    low_confidence = extractor._calculate_confidence_score(
        ApplicationDomain.UNKNOWN.value,
        [],
        [],
        None,
    )

    assert high_confidence == pytest.approx(1.0)
    assert low_confidence == pytest.approx(0.1)
