"""Hermetic native micro-CLI fixtures (byte-stable --help/--version)."""

from __future__ import annotations

import subprocess

import pytest

from tests.unit import _native_fixture_support as support
from tests.unit._native_fixture_support import emit_skip_marker, locate_fixture


def test_native_fixture_skip_reason_is_actionable(tmp_path, monkeypatch):
    monkeypatch.setattr(support, "NATIVE_ROOT", tmp_path)
    path, reason = locate_fixture("hello_c")
    assert path is None
    assert reason is not None
    assert "make -C test_samples/native" in reason


def test_hello_c_help_and_version_are_byte_stable():
    path, reason = locate_fixture("hello_c")
    if path is None:
        emit_skip_marker("hello_c", reason or "missing")
        pytest.skip(reason or "missing fixture")
    help_proc = subprocess.run([str(path), "--help"], capture_output=True, text=True, check=False)
    assert help_proc.returncode == 0
    assert help_proc.stdout == (
        "Usage: hello_c [--help|--version]\n"
        "  --help     Show this help message\n"
        "  --version  Print version and exit\n"
    )
    ver = subprocess.run([str(path), "--version"], capture_output=True, text=True, check=False)
    assert ver.returncode == 0
    assert ver.stdout == "hello_c 1.0.0\n"


def test_hello_go_help_and_version_are_byte_stable():
    path, reason = locate_fixture("hello_go")
    if path is None:
        emit_skip_marker("hello_go", reason or "missing")
        pytest.skip(reason or "missing fixture")
    help_proc = subprocess.run([str(path), "--help"], capture_output=True, text=True, check=False)
    assert help_proc.returncode == 0
    assert help_proc.stdout == (
        "Usage: hello_go [--help|--version]\n"
        "  --help     Show this help message\n"
        "  --version  Print version and exit\n"
    )
    ver = subprocess.run([str(path), "--version"], capture_output=True, text=True, check=False)
    assert ver.returncode == 0
    assert ver.stdout == "hello_go 1.0.0\n"
