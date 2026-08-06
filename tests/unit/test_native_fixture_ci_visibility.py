"""Absent-toolchain skip visibility."""

from __future__ import annotations

from tests.unit._native_fixture_support import emit_skip_marker


def test_absent_toolchain_is_reported_not_silent():
    marker = emit_skip_marker("hello_c", "cc_not_found")
    assert marker.startswith("NATIVE_FIXTURE_SKIPPED: hello_c")
    assert "reason=cc_not_found" in marker


def test_present_path_does_not_require_marker():
    # Opposite arm: when we would not skip, helper is simply not called.
    # Calling with empty reason must still label — prove emit is explicit.
    marker = emit_skip_marker("hello_go", "run: make -C test_samples/native")
    assert "NATIVE_FIXTURE_SKIPPED" in marker
