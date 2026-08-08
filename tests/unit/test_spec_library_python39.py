"""spec_library must import on Python 3.9 (no backslash in f-string exprs)."""

from __future__ import annotations


def test_spec_library_imports_on_python39():
    from reveng.app_reverse_engineering import spec_library

    assert hasattr(spec_library, "extract_keyword_snippets") or hasattr(
        spec_library, "render_directory_structure_doc"
    )
