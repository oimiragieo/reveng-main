"""Regression tests for Python bytecode decompiler version routing.

The decompiler selection used lexicographic string comparison on the
Python version (e.g. ``python_version <= "3.8"``). That made
``"3.10" <= "3.8"`` evaluate to ``True``, so 3.10+ bytecode was wrongly
routed to uncompyle6 (which only supports up to 3.8). These tests pin the
correct numeric-tuple routing behaviour.
"""

from reveng.tools.languages.python_bytecode_analyzer import PythonDecompiler


def _make_decompiler_all_available():
    """Build a PythonDecompiler with every backend marked available."""
    dec = PythonDecompiler()
    dec.uncompyle6_available = True
    dec.decompyle3_available = True
    dec.pycdc_available = True
    return dec


def _route(monkeypatch, python_version):
    """Return the decompiler name selected for ``python_version``.

    Each backend runner is replaced with a stub that records its name and
    reports success, so the first selected backend is the one returned.
    """
    dec = _make_decompiler_all_available()

    def make_stub(name):
        def stub(pyc_file, output_file):
            return True, f"# decompiled by {name}"

        return stub

    monkeypatch.setattr(dec, "_run_uncompyle6", make_stub("uncompyle6"))
    monkeypatch.setattr(dec, "_run_decompyle3", make_stub("decompyle3"))
    monkeypatch.setattr(dec, "_run_pycdc", make_stub("pycdc"))

    result = dec.decompile("fake.pyc", "out.py", python_version)
    return result.decompiler_used


def test_310_does_not_route_to_uncompyle6(monkeypatch):
    """Python 3.10 must NOT be handed to uncompyle6 (<=3.8 only)."""
    assert _route(monkeypatch, "3.10") != "uncompyle6"


def test_310_does_not_route_to_decompyle3(monkeypatch):
    """Python 3.10 is above decompyle3's 3.9 ceiling; must skip it."""
    assert _route(monkeypatch, "3.10") != "decompyle3"


def test_310_routes_to_pycdc(monkeypatch):
    """With numeric comparison, 3.10 falls through to the pycdc fallback."""
    assert _route(monkeypatch, "3.10") == "pycdc"


def test_38_still_routes_to_uncompyle6(monkeypatch):
    """3.8 must still be served by uncompyle6 (no regression)."""
    assert _route(monkeypatch, "3.8") == "uncompyle6"


def test_39_routes_to_decompyle3_not_uncompyle6(monkeypatch):
    """3.9 is above uncompyle6's ceiling but within decompyle3's range."""
    assert _route(monkeypatch, "3.9") == "decompyle3"
