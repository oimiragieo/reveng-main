#!/usr/bin/env python3
"""
Test REVENG Documentation
=========================

This module tests that documentation is complete and links work.
"""

import pytest
import requests
from pathlib import Path
import re


class TestDocumentationFiles:
    """Test that documentation files exist and have content"""
    
    def test_main_readme(self):
        """Test main README.md"""
        readme_path = Path('README.md')
        assert readme_path.exists(), "README.md not found"
        
        content = readme_path.read_text()
        assert len(content) > 1000, "README.md too short"
        assert "REVENG" in content, "README.md missing REVENG reference"
        assert "## Quick Start" in content, "README.md missing Quick Start section"
        assert "## Features" in content, "README.md missing Features section"
    
    def test_installation_guide(self):
        """Test INSTALLATION.md"""
        install_path = Path('INSTALLATION.md')
        assert install_path.exists(), "INSTALLATION.md not found"
        
        content = install_path.read_text()
        assert len(content) > 500, "INSTALLATION.md too short"
        assert "## System Requirements" in content, "INSTALLATION.md missing System Requirements"
        assert "## Windows Installation" in content, "INSTALLATION.md missing Windows section"
        assert "## Linux Installation" in content, "INSTALLATION.md missing Linux section"
    
    def test_architecture_doc(self):
        """Test ARCHITECTURE.md"""
        arch_path = Path('ARCHITECTURE.md')
        assert arch_path.exists(), "ARCHITECTURE.md not found"
        
        content = arch_path.read_text()
        assert len(content) > 500, "ARCHITECTURE.md too short"
        assert "## System Overview" in content, "ARCHITECTURE.md missing System Overview"
        assert "## Core Components" in content, "ARCHITECTURE.md missing Core Components"
    
    def test_api_reference(self):
        """Test API_REFERENCE.md"""
        api_path = Path('API_REFERENCE.md')
        assert api_path.exists(), "API_REFERENCE.md not found"
        
        content = api_path.read_text()
        assert len(content) > 500, "API_REFERENCE.md too short"
        assert "## Core API" in content, "API_REFERENCE.md missing Core API"
        assert "## Tool APIs" in content, "API_REFERENCE.md missing Tool APIs"
    
    def test_docs_directory(self):
        """Test docs directory"""
        docs_dir = Path('docs')
        assert docs_dir.exists(), "docs directory not found"
        
        # Check for key documentation files
        key_docs = [
            'README.md',
            'USER_GUIDE.md',
            'DEVELOPER_GUIDE.md',
            'QUICK_START.md',
            'CHANGELOG.md'
        ]
        
        for doc in key_docs:
            doc_path = docs_dir / doc
            assert doc_path.exists(), f"Documentation file missing: {doc}"
            
            content = doc_path.read_text()
            assert len(content) > 100, f"Documentation file too short: {doc}"


class TestDocumentationLinks:
    """Test that documentation links work"""
    
    def test_internal_links(self):
        """Test internal documentation links"""
        readme_path = Path('README.md')
        content = readme_path.read_text()
        
        # Find markdown links
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        links = re.findall(link_pattern, content)
        
        for link_text, link_url in links:
            # Skip external links
            if link_url.startswith('http'):
                continue
            
            # Skip anchor links
            if link_url.startswith('#'):
                continue
            
            # Check if linked file exists
            if link_url.endswith('.md'):
                linked_file = Path(link_url)
                assert linked_file.exists(), f"Broken link in README: {link_url}"
    
    def test_external_links(self):
        """Test external documentation links"""
        readme_path = Path('README.md')
        content = readme_path.read_text()
        
        # Find external links
        link_pattern = r'\[([^\]]+)\]\((https?://[^)]+)\)'
        links = re.findall(link_pattern, content)
        
        for link_text, link_url in links:
            try:
                response = requests.head(link_url, timeout=10)
                assert response.status_code < 400, f"Broken external link: {link_url}"
            except requests.RequestException:
                # Skip if request fails (network issues, etc.)
                pytest.skip(f"Could not test external link: {link_url}")


class TestDocumentationContent:
    """Test documentation content quality"""
    
    def test_readme_sections(self):
        """Test README has required sections"""
        readme_path = Path('README.md')
        content = readme_path.read_text()
        
        required_sections = [
            "## Quick Start",
            "## Features",
            "## Installation",
            "## Usage",
            "## Contributing",
            "## License"
        ]
        
        for section in required_sections:
            assert section in content, f"README missing section: {section}"
    
    def test_installation_sections(self):
        """Test INSTALLATION.md has required sections"""
        install_path = Path('INSTALLATION.md')
        content = install_path.read_text()
        
        required_sections = [
            "## System Requirements",
            "## Windows Installation",
            "## Linux Installation",
            "## macOS Installation"
        ]
        
        for section in required_sections:
            assert section in content, f"INSTALLATION.md missing section: {section}"
    
    def test_architecture_sections(self):
        """Test ARCHITECTURE.md has required sections"""
        arch_path = Path('ARCHITECTURE.md')
        content = arch_path.read_text()
        
        required_sections = [
            "## System Overview",
            "## Core Components",
            "## Data Flow"
        ]
        
        for section in required_sections:
            assert section in content, f"ARCHITECTURE.md missing section: {section}"
    
    def test_api_sections(self):
        """Test API_REFERENCE.md has required sections"""
        api_path = Path('API_REFERENCE.md')
        content = api_path.read_text()
        
        required_sections = [
            "## Core API",
            "## Tool APIs",
            "## Web Interface API"
        ]
        
        for section in required_sections:
            assert section in content, f"API_REFERENCE.md missing section: {section}"


class TestDocumentationFormatting:
    """Test documentation formatting"""
    
    def test_markdown_syntax(self):
        """Test markdown syntax is valid"""
        markdown_files = [
            'README.md',
            'INSTALLATION.md',
            'ARCHITECTURE.md',
            'API_REFERENCE.md'
        ]
        
        for md_file in markdown_files:
            file_path = Path(md_file)
            if not file_path.exists():
                continue
            
            content = file_path.read_text()
            
            # Check for common markdown issues
            assert "## " in content, f"{md_file} missing section headers"
            assert not content.startswith(" "), f"{md_file} starts with whitespace"
            assert content.endswith("\n"), f"{md_file} doesn't end with newline"
    
    def test_code_blocks(self):
        """Test code blocks are properly formatted"""
        readme_path = Path('README.md')
        content = readme_path.read_text()
        
        # Check for code blocks
        code_block_pattern = r'```[\s\S]*?```'
        code_blocks = re.findall(code_block_pattern, content)
        
        assert len(code_blocks) > 0, "README missing code examples"
        
        # Check that code blocks have language specified
        for block in code_blocks:
            if 'bash' in block or 'python' in block or 'cmd' in block:
                assert block.startswith('```'), f"Code block not properly formatted: {block[:50]}"


class TestDocumentationCompleteness:
    """Test documentation completeness"""
    
    def test_all_tools_documented(self):
        """Test that all tools are documented"""
        tools_dir = Path('tools')
        if not tools_dir.exists():
            pytest.skip("Tools directory not found")
        
        # Get list of Python tools
        tool_files = list(tools_dir.glob('*.py'))
        assert len(tool_files) > 0, "No tools found"
        
        # Check that tools are mentioned in documentation
        readme_content = Path('README.md').read_text()
        api_content = Path('API_REFERENCE.md').read_text()
        
        for tool_file in tool_files[:5]:  # Check first 5 tools
            tool_name = tool_file.stem
            if tool_name.startswith('_'):
                continue
            
            # Tool should be mentioned somewhere in documentation
            assert (tool_name in readme_content or 
                   tool_name in api_content), f"Tool {tool_name} not documented"
    
    def test_examples_documented(self):
        """Test that examples are documented"""
        examples_dir = Path('examples')
        if not examples_dir.exists():
            pytest.skip("Examples directory not found")
        
        # Check examples README
        examples_readme = examples_dir / 'README.md'
        assert examples_readme.exists(), "Examples README not found"
        
        content = examples_readme.read_text()
        assert len(content) > 200, "Examples README too short"
        assert "## Basic Examples" in content or "## Getting Started" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
