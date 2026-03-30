"""Regression tests for UTF-8 documentation reads on Windows."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestDocumentationEncoding:
    """Ensure documentation files are read explicitly as UTF-8."""

    def test_main_docs_can_be_read_with_utf8(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        installation = (REPO_ROOT / "INSTALLATION.md").read_text(encoding="utf-8")

        assert "REVENG" in readme
        assert "Installation" in installation

    def test_examples_readme_can_be_read_with_utf8(self):
        examples_readme = (REPO_ROOT / "examples" / "README.md").read_text(encoding="utf-8")

        assert len(examples_readme) > 200
        assert "Examples" in examples_readme
