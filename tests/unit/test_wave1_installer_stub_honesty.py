"""Wave 1: installer None stubs must advertise deprecated_stub (fail-closed)."""

from __future__ import annotations

from reveng.core.dependency_manager import DependencyManager

STUBS = ("dnspy", "uncompyle6", "exeinfo_pe", "x64dbg", "imhex", "lordpe")


def test_stub_install_emits_deprecated_stub_token():
    dm = DependencyManager()
    results = dm.install_missing_tools(list(STUBS), auto_install=True)
    for name in STUBS:
        assert name in results
        assert results[name].success is False
        err = (results[name].error_message or "").lower()
        assert (
            "deprecated_stub" in err
        ), f"{name}: need deprecated_stub in error_message, got {err!r}"


def test_stub_install_method_is_deprecated_stub():
    dm = DependencyManager()
    status = dm.get_installation_status()
    for name in STUBS:
        assert status[name].install_method == "deprecated_stub"
