"""CLI import smoke for Python 3.9 union annotations."""

from __future__ import annotations


def test_cli_module_imports_on_python39():
    from reveng.cli import create_parser, main

    parser = create_parser()
    assert parser is not None
    assert callable(main)
