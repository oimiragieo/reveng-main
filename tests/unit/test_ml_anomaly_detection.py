"""Unit tests for the current malware-forensics anomaly APIs."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from reveng.malware.behavioral_monitor import (
    BehavioralMonitor,
    BehaviorEvent,
    BehaviorType,
    ThreatLevel,
)
from reveng.ml.forensics_anomaly_models import BehavioralAnomalyModel, ForensicsAnomalyModel


def _event(
    behavior_type: BehaviorType,
    operation: str,
    target: str,
    *,
    threat_level: ThreatLevel,
) -> BehaviorEvent:
    return BehaviorEvent(
        timestamp=1.0,
        behavior_type=behavior_type,
        operation=operation,
        target=target,
        threat_level=threat_level,
    )


def test_behavioral_anomaly_model_flags_high_risk_event_stream():
    assessment = BehavioralAnomalyModel().assess_events(
        [
            _event(
                BehaviorType.NETWORK_OPERATION,
                "HttpSendRequest",
                "198.51.100.5:443",
                threat_level=ThreatLevel.HIGH,
            ),
            _event(
                BehaviorType.ANTI_ANALYSIS,
                "IsDebuggerPresent",
                "kernel32.dll",
                threat_level=ThreatLevel.HIGH,
            ),
            _event(
                BehaviorType.PROCESS_OPERATION,
                "CreateRemoteThread",
                "winlogon.exe",
                threat_level=ThreatLevel.CRITICAL,
            ),
            _event(
                BehaviorType.MEMORY_OPERATION,
                "WriteProcessMemory",
                "lsass.exe",
                threat_level=ThreatLevel.CRITICAL,
            ),
        ],
        [
            "HttpSendRequest",
            "IsDebuggerPresent",
            "CreateRemoteThread",
            "WriteProcessMemory",
        ],
    )

    assert assessment.exceeded is True
    assert assessment.score > assessment.threshold
    assert assessment.reasons[0].startswith("ML anomaly score")
    assert assessment.features["indicator_ratio"] == pytest.approx(1.0)
    assert assessment.features["network_ratio"] == pytest.approx(0.25)


def test_behavioral_anomaly_model_leaves_benign_event_stream_below_threshold():
    assessment = BehavioralAnomalyModel().assess_events(
        [
            _event(
                BehaviorType.FILE_OPERATION,
                "FileAccess",
                "readme.txt",
                threat_level=ThreatLevel.LOW,
            ),
            _event(
                BehaviorType.FILE_OPERATION,
                "FileAccess",
                "notes.txt",
                threat_level=ThreatLevel.LOW,
            ),
        ],
        [],
    )

    assert assessment.exceeded is False
    assert assessment.score < assessment.threshold
    assert assessment.reasons == []
    assert assessment.features["network_ratio"] == 0.0


def test_behavioral_monitor_parses_trace_output_and_adds_timeout_event():
    monitor = BehavioralMonitor()
    monitor.binary_path = "sample.exe"
    monitor._sandbox = SimpleNamespace(timeout_seconds=7)
    monitor._sandbox_result = SimpleNamespace(
        sandbox_available=True,
        trace_output=(
            '123 openat(AT_FDCWD, "/tmp/test.txt", O_RDONLY) = 3\n'
            "123 connect(4, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0\n"
            "123 ptrace(PTRACE_TRACEME, 0, NULL, NULL) = 0"
        ),
        timed_out=True,
        container_name="sandbox-1",
        image="python:3.11-slim",
        exit_code=124,
        stdout="",
        stderr="",
        error="",
    )

    events = monitor._events_from_sandbox_result()

    assert [event.operation for event in events[:3]] == ["openat", "connect", "ptrace"]
    assert events[0].behavior_type == BehaviorType.FILE_OPERATION
    assert events[0].target == "/tmp/test.txt"
    assert events[1].behavior_type == BehaviorType.NETWORK_OPERATION
    assert events[1].target == "port:443"
    assert events[2].behavior_type == BehaviorType.ANTI_ANALYSIS
    assert events[-1].operation == "SandboxTimeout"
    assert events[-1].threat_level == ThreatLevel.MEDIUM


def test_behavioral_monitor_creates_static_only_profile_when_sandbox_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ" + bytes(range(64)) * 4)

    monitor = BehavioralMonitor()
    monitor.binary_path = str(binary_path)
    monitor.start_time = 10.0
    monitor._sandbox_result = SimpleNamespace(
        sandbox_available=False,
        image="python:3.11-slim",
        container_name=None,
        exit_code=None,
        stdout="",
        stderr="",
        timed_out=False,
        error="",
    )

    monkeypatch.setattr("reveng.malware.behavioral_monitor.time.time", lambda: 25.0)

    monitor.events = monitor._events_from_sandbox_result()
    profile = monitor._create_behavioral_profile()

    assert profile is not None
    assert profile.total_events == 1
    assert profile.sandbox_available is False
    assert profile.analysis_mode == "static_only"
    assert profile.file_operations[0]["operation"] == "StaticMetadata"
    assert profile.file_operations[0]["target"] == str(binary_path)
    assert profile.analysis_duration == pytest.approx(15.0)


def test_forensics_anomaly_model_distinguishes_suspicious_and_benign_profiles():
    model = ForensicsAnomalyModel()

    suspicious = model.assess_binary_features(
        {
            "file_size_kb": 380.38,
            "entropy": 0.06,
            "is_pe": 0.0,
            "import_count": 191.55,
            "suspicious_import_ratio": 0.96,
            "section_count": 1.1,
            "executable_section_count": 0.14,
            "writable_executable_section_count": 4.85,
            "average_section_entropy": 0.90,
            "max_section_entropy": 0.90,
            "string_indicator_density": 0.89,
        }
    )
    benign = model.assess_binary_features(
        {
            "file_size_kb": 56.0,
            "entropy": 5.60,
            "is_pe": 1.0,
            "import_count": 62.0,
            "suspicious_import_ratio": 0.06,
            "section_count": 6.0,
            "executable_section_count": 2.0,
            "writable_executable_section_count": 0.0,
            "average_section_entropy": 5.10,
            "max_section_entropy": 5.80,
            "string_indicator_density": 0.03,
        }
    )

    assert suspicious.exceeded is True
    assert suspicious.score > suspicious.threshold
    assert suspicious.features["suspicious_import_ratio"] == pytest.approx(0.96)
    assert any(
        "suspicious APIs" in reason
        or "writable and executable sections" in reason
        or "embedded strings" in reason
        for reason in suspicious.reasons[1:]
    )
    assert benign.exceeded is False
    assert benign.score < benign.threshold
    assert benign.reasons == []
