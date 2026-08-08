"""Absent-toolchain skip visibility — two arms required."""

from __future__ import annotations

from tests.unit import _native_fixture_support as support
from tests.unit._native_fixture_support import emit_skip_marker, locate_fixture


def test_absent_toolchain_is_reported_not_silent(capsys):
    marker = emit_skip_marker("hello_c", "cc_not_found")
    assert marker.startswith("NATIVE_FIXTURE_SKIPPED: hello_c")
    assert "reason=cc_not_found" in marker
    captured = capsys.readouterr()
    assert "NATIVE_FIXTURE_SKIPPED: hello_c" in captured.out


def test_present_path_does_not_emit_marker(capsys, tmp_path, monkeypatch):
    """Opposite arm: when the binary exists, no skip marker is emitted."""
    build = tmp_path / "hello_go" / "build"
    build.mkdir(parents=True)
    (build / "hello_go").write_bytes(b"\x7fELF")
    monkeypatch.setattr(support, "NATIVE_ROOT", tmp_path)

    path, reason = locate_fixture("hello_go")
    assert path is not None
    assert reason is None
    # Present path must not call emit_skip_marker — capture proves silence.
    captured = capsys.readouterr()
    assert "NATIVE_FIXTURE_SKIPPED" not in captured.out
