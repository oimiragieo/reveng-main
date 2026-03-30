#!/usr/bin/env python3
"""Integration tests for the current REVENG documentation layout."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import requests  # type: ignore[import-untyped]

README_PATH = Path("README.md")
INSTALLATION_PATH = Path("INSTALLATION.md")
ARCHITECTURE_PATH = Path("docs/architecture/overview.md")
API_REFERENCE_PATH = Path("docs/api/API_REFERENCE.md")
DOCS_INDEX_PATH = Path("docs/README.md")
EXAMPLES_README_PATH = Path("examples/README.md")

DOCUMENTS_UNDER_TEST = {
    "README.md": {
        "path": README_PATH,
        "required_sections": [
            "## Quick Start",
            "## Key Features",
            "## Documentation",
            "## Contributing",
            "## License",
        ],
        "min_length": 1000,
    },
    "INSTALLATION.md": {
        "path": INSTALLATION_PATH,
        "required_sections": [
            "## Quick Start (Automated Setup)",
            "## System Requirements",
            "## Step-by-Step Installation",
            "## Troubleshooting",
        ],
        "min_length": 500,
    },
    "docs/architecture/overview.md": {
        "path": ARCHITECTURE_PATH,
        "required_sections": [
            "## Entry Points",
            "## Runtime Flow",
            "## Package Map",
        ],
        "min_length": 500,
    },
    "docs/api/API_REFERENCE.md": {
        "path": API_REFERENCE_PATH,
        "required_sections": [
            "## Core API",
            "## Tool APIs",
            "## Web Interface API",
        ],
        "min_length": 500,
    },
}

KEY_DOCS = [
    DOCS_INDEX_PATH,
    Path("docs/architecture/overview.md"),
    Path("docs/developer-guide/DEVELOPER_GUIDE.md"),
    Path("docs/deployment/README.md"),
    API_REFERENCE_PATH,
    Path("docs/getting-started/installation.md"),
    Path("docs/mcp/README.md"),
]

CRITICAL_README_LINKS = [
    "INSTALLATION.md",
    "docs/README.md",
    "docs/getting-started/installation.md",
    "CLI_REFERENCE.md",
    "docs/mcp/README.md",
    "CONTRIBUTING.md",
]

CORE_EXTERNAL_LINKS = [
    "https://github.com/oimiragieo/reveng-main",
    "https://github.com/oimiragieo/reveng-main/issues",
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class TestDocumentationFiles:
    @pytest.mark.parametrize("doc_name", list(DOCUMENTS_UNDER_TEST))
    def test_core_documents_exist_and_have_expected_sections(self, doc_name: str):
        document = DOCUMENTS_UNDER_TEST[doc_name]
        doc_path = document["path"]

        assert doc_path.exists(), f"{doc_path} not found"
        content = read_text(doc_path)
        assert len(content) > document["min_length"], f"{doc_path} is unexpectedly short"

        for section in document["required_sections"]:
            assert section in content, f"{doc_path} missing section: {section}"

    def test_docs_directory_contains_key_guides(self):
        docs_dir = Path("docs")
        assert docs_dir.exists(), "docs directory not found"

        for doc_path in KEY_DOCS:
            assert doc_path.exists(), f"Documentation file missing: {doc_path}"
            assert len(read_text(doc_path)) > 100, f"Documentation file too short: {doc_path}"


class TestDocumentationLinks:
    def test_readme_references_current_core_docs(self):
        content = read_text(README_PATH)

        for link in CRITICAL_README_LINKS:
            assert f"]({link})" in content, f"README missing link to {link}"
            assert Path(link).exists(), f"Linked file missing: {link}"

    @pytest.mark.parametrize("url", CORE_EXTERNAL_LINKS)
    def test_core_external_links_resolve(self, url: str):
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
        except requests.RequestException as exc:
            pytest.skip(f"Could not test external link {url}: {exc}")

        assert response.status_code < 400, f"Broken external link: {url}"


class TestDocumentationContent:
    def test_docs_index_highlights_current_sections(self):
        content = read_text(DOCS_INDEX_PATH)

        for section in [
            "### Getting Started",
            "### User Guide",
            "### Developer Guide",
            "### API Reference",
            "### Deployment",
        ]:
            assert section in content, f"docs/README.md missing section: {section}"

    def test_examples_readme_matches_current_headings(self):
        content = read_text(EXAMPLES_README_PATH)

        assert len(content) > 200, "Examples README too short"
        assert "Quick Start" in content
        assert "Available Examples" in content


class TestDocumentationFormatting:
    def test_markdown_syntax(self):
        for document in DOCUMENTS_UNDER_TEST.values():
            doc_path = document["path"]
            content = read_text(doc_path)

            assert "## " in content, f"{doc_path} missing section headers"
            assert not content.startswith(" "), f"{doc_path} starts with whitespace"
            assert content.endswith("\n"), f"{doc_path} does not end with newline"

    def test_readme_has_code_blocks(self):
        content = read_text(README_PATH)
        code_blocks = re.findall(r"```[\s\S]*?```", content)

        assert code_blocks, "README missing code examples"
        for block in code_blocks:
            if any(language in block for language in ("bash", "python", "cmd")):
                assert block.startswith("```"), f"Malformed code block: {block[:50]}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
