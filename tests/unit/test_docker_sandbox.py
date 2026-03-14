"""Unit tests for Docker-based malware behavioral sandboxing."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from reveng.malware.behavioral_monitor import BehavioralMonitor
from reveng.malware.docker_sandbox import DockerSandbox, SandboxExecutionResult


def _sandbox_stdout(trace_output: str, *, stdout: str = "", stderr: str = "") -> str:
    return "\n".join(
        [
            "__REVENG_EXIT_CODE__=0",
            "__REVENG_STDOUT_START__",
            stdout,
            "__REVENG_STDOUT_END__",
            "__REVENG_STDERR_START__",
            stderr,
            "__REVENG_STDERR_END__",
            "__REVENG_STRACE_START__",
            trace_output,
            "__REVENG_STRACE_END__",
        ]
    )


def test_docker_sandbox_executes_python_slim_container_with_strace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x7fELF")

    captured: dict[str, object] = {}

    class _FakeProcess:
        pid = 4321
        returncode = 0

        def communicate(self, timeout=None):
            captured["timeout"] = timeout
            return (
                _sandbox_stdout(
                    '1234 openat(AT_FDCWD, "/tmp/reveng-target.bin", O_RDONLY) = 3',
                    stdout="hello",
                ),
                "",
            )

        def poll(self):
            return self.returncode

        def terminate(self):
            captured["terminated"] = True

        def kill(self):
            captured["killed"] = True

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return _FakeProcess()

    def fake_run(command, **kwargs):
        captured.setdefault("run_commands", []).append(command)
        return type("Completed", (), {"returncode": 0, "stdout": "[]", "stderr": ""})()

    monkeypatch.setattr("reveng.malware.docker_sandbox.subprocess.Popen", fake_popen)
    monkeypatch.setattr("reveng.malware.docker_sandbox.subprocess.run", fake_run)

    sandbox = DockerSandbox(timeout_seconds=30)
    result = sandbox.execute(str(binary_path))

    command = captured["command"]
    assert command[:6] == ["docker", "run", "--rm", "--network=none", "--name", result.container_name]
    assert any("python:3.11-slim" in arg for arg in command)
    assert any(arg.endswith(":/target:ro") for arg in command)
    assert result.sandbox_available is True
    assert result.trace_output.strip().startswith("1234 openat")
    assert result.stdout.strip() == "hello"


def test_behavioral_monitor_uses_docker_sandbox_and_never_enumerates_host_processes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x7fELF")

    started = threading.Event()

    class _BlockingSandbox:
        instances = []

        def __init__(self, *args, **kwargs):
            self.container_name = "reveng-sandbox-test"
            self._released = threading.Event()
            self.stop_called = False
            type(self).instances.append(self)

        def execute(self, binary_path: str, timeout_seconds: int | None = None):
            started.set()
            self._released.wait(timeout=2.0)
            return SandboxExecutionResult(
                sandbox_available=True,
                container_name=self.container_name,
                image="python:3.11-slim",
                command=["docker", "run"],
                stdout="stdout",
                stderr="stderr",
                trace_output="\n".join(
                    [
                        '1234 openat(AT_FDCWD, "/tmp/reveng-target.bin", O_RDONLY) = 3',
                        '1234 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4',
                        '1234 connect(4, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0',
                        '1234 execve("/tmp/reveng-target.bin", ["/tmp/reveng-target.bin"], 0x7ffc) = 0',
                    ]
                ),
                exit_code=0,
                timed_out=False,
                error=None,
            )

        def stop(self) -> bool:
            self.stop_called = True
            self._released.set()
            return True

    monkeypatch.setattr("reveng.malware.behavioral_monitor.DockerSandbox", _BlockingSandbox)

    monitor = BehavioralMonitor()

    assert monitor.start_monitoring(str(binary_path), duration=1) is True
    assert started.wait(timeout=1.0)

    profile = monitor.stop_monitoring()
    sandbox = _BlockingSandbox.instances[-1]

    assert sandbox.stop_called is True
    assert profile is not None
    assert profile.sandbox_available is True
    assert profile.file_operations
    assert profile.network_connections
    assert profile.process_operations
    assert profile.anomaly_score >= 0.0


def test_behavioral_monitor_skip_sandbox_returns_static_only_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    binary_path = tmp_path / "skipped.bin"
    binary_path.write_bytes(bytes(range(64)))

    monkeypatch.setenv("SKIP_SANDBOX", "true")
    monkeypatch.setattr(
        "reveng.malware.docker_sandbox.subprocess.Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("docker should be skipped")),
    )

    monitor = BehavioralMonitor()

    assert monitor.start_monitoring(str(binary_path), duration=1) is True
    profile = monitor.stop_monitoring()

    assert profile is not None
    assert profile.sandbox_available is False
    assert profile.analysis_mode == "static_only"
    assert profile.total_events >= 1
    assert any("sandbox" in indicator.lower() for indicator in profile.threat_indicators)


def test_behavioral_monitor_parses_trace_output_into_behavioral_events(tmp_path: Path):
    binary_path = tmp_path / "trace.bin"
    binary_path.write_bytes(b"\x7fELF")

    monitor = BehavioralMonitor()
    monitor.binary_path = str(binary_path)
    monitor._sandbox_result = SandboxExecutionResult(
        sandbox_available=True,
        container_name="reveng-sandbox-events",
        image="python:3.11-slim",
        command=["docker", "run"],
        stdout="",
        stderr="",
        trace_output="\n".join(
            [
                '1234 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3',
                '1234 unlink("/tmp/dropper.tmp") = 0',
                '1234 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4',
                '1234 connect(4, {sa_family=AF_INET, sin_port=htons(80)}, 16) = 0',
                '1234 execve("/tmp/reveng-target.bin", ["/tmp/reveng-target.bin"], 0x7ffc) = 0',
            ]
        ),
        exit_code=0,
        timed_out=False,
        error=None,
    )

    events = monitor._events_from_sandbox_result()

    assert [event.behavior_type.value for event in events] == [
        "file_operation",
        "file_operation",
        "network_operation",
        "network_operation",
        "process_operation",
    ]
    assert events[1].threat_level.value in {"medium", "high"}
