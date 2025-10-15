#!/usr/bin/env python3
"""
REVENG Documentation Generator
==============================

This script generates API documentation and other documentation files.
"""

import sys
import subprocess
import os
from pathlib import Path
from typing import List, Dict, Any


class DocumentationGenerator:
    """Generate REVENG documentation"""
    
    def __init__(self):
        self.output_dir = Path('docs/generated')
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_api_docs(self) -> bool:
        """Generate API documentation using Sphinx"""
        print("Generating API Documentation...")
        
        try:
            # Check if Sphinx is available
            result = subprocess.run(['sphinx-build', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print("❌ Sphinx not found. Install with: pip install sphinx")
                return False
            
            # Create Sphinx configuration if it doesn't exist
            conf_py = Path('docs/conf.py')
            if not conf_py.exists():
                self.create_sphinx_config()
            
            # Generate documentation
            result = subprocess.run([
                'sphinx-build', '-b', 'html', 'docs', str(self.output_dir)
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print("✅ API documentation generated")
                print(f"📁 Output: {self.output_dir}")
                return True
            else:
                print(f"❌ Sphinx build failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("⏰ Sphinx build timed out")
            return False
        except Exception as e:
            print(f"❌ Error generating API docs: {e}")
            return False
    
    def create_sphinx_config(self) -> None:
        """Create Sphinx configuration file"""
        conf_content = '''
# Configuration file for the Sphinx documentation builder.

import os
import sys
sys.path.insert(0, os.path.abspath('..'))

# -- Project information -----------------------------------------------------
project = 'REVENG'
copyright = '2025, REVENG Team'
author = 'REVENG Team'
release = '2.0.0'

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
    'sphinx.ext.mathjax',
    'sphinx.ext.ifconfig',
    'sphinx.ext.githubpages',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# -- Extension configuration -------------------------------------------------
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'exclude-members': '__weakref__'
}

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True
'''
        
        docs_dir = Path('docs')
        docs_dir.mkdir(exist_ok=True)
        
        with open(conf_py, 'w') as f:
            f.write(conf_content)
        
        print(f"✅ Created Sphinx configuration: {conf_py}")
    
    def generate_tool_docs(self) -> bool:
        """Generate tool documentation"""
        print("Generating Tool Documentation...")
        
        tools_dir = Path('tools')
        if not tools_dir.exists():
            print("❌ Tools directory not found")
            return False
        
        # Find all Python tools
        tool_files = list(tools_dir.glob('*.py'))
        if not tool_files:
            print("❌ No tools found")
            return False
        
        # Generate documentation for each tool
        tool_docs = []
        for tool_file in tool_files:
            if tool_file.name.startswith('_'):
                continue
            
            try:
                # Extract docstring from tool
                with open(tool_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Find class and function docstrings
                docstrings = self.extract_docstrings(content)
                
                if docstrings:
                    tool_docs.append({
                        'file': tool_file.name,
                        'docstrings': docstrings
                    })
                    print(f"✅ {tool_file.name} - Documentation extracted")
                else:
                    print(f"⚠️  {tool_file.name} - No docstrings found")
            except Exception as e:
                print(f"❌ {tool_file.name} - Error: {e}")
        
        # Save tool documentation
        if tool_docs:
            self.save_tool_docs(tool_docs)
            print(f"✅ Tool documentation generated ({len(tool_docs)} tools)")
            return True
        else:
            print("❌ No tool documentation generated")
            return False
    
    def extract_docstrings(self, content: str) -> List[Dict[str, str]]:
        """Extract docstrings from Python code"""
        import ast
        
        try:
            tree = ast.parse(content)
            docstrings = []
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    if ast.get_docstring(node):
                        docstrings.append({
                            'name': node.name,
                            'type': 'class' if isinstance(node, ast.ClassDef) else 'function',
                            'docstring': ast.get_docstring(node)
                        })
            
            return docstrings
        except SyntaxError:
            return []
    
    def save_tool_docs(self, tool_docs: List[Dict[str, Any]]) -> None:
        """Save tool documentation to file"""
        output_file = self.output_dir / 'tools.md'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# REVENG Tools Documentation\n\n")
            f.write("This document contains documentation for all REVENG tools.\n\n")
            
            for tool in tool_docs:
                f.write(f"## {tool['file']}\n\n")
                
                for doc in tool['docstrings']:
                    f.write(f"### {doc['name']} ({doc['type']})\n\n")
                    f.write(f"{doc['docstring']}\n\n")
                
                f.write("---\n\n")
        
        print(f"📁 Tool documentation saved: {output_file}")
    
    def generate_readme_index(self) -> bool:
        """Generate README index"""
        print("Generating README Index...")
        
        readme_files = [
            'README.md',
            'INSTALLATION.md',
            'ARCHITECTURE.md',
            'API_REFERENCE.md',
            'docs/USER_GUIDE.md',
            'docs/DEVELOPER_GUIDE.md',
            'docs/QUICK_START.md'
        ]
        
        index_content = []
        index_content.append("# REVENG Documentation Index\n")
        index_content.append("This is an automatically generated index of all REVENG documentation.\n\n")
        
        for readme_file in readme_files:
            file_path = Path(readme_file)
            if file_path.exists():
                # Extract title and first paragraph
                content = file_path.read_text(encoding='utf-8')
                lines = content.split('\n')
                
                title = "Untitled"
                description = "No description available"
                
                # Find title (first # header)
                for line in lines[:10]:
                    if line.startswith('# '):
                        title = line[2:].strip()
                        break
                
                # Find description (first paragraph after title)
                in_description = False
                for line in lines:
                    if line.startswith('# '):
                        in_description = True
                        continue
                    elif in_description and line.strip() and not line.startswith('#'):
                        description = line.strip()
                        break
                
                index_content.append(f"## [{title}]({readme_file})\n")
                index_content.append(f"{description}\n\n")
            else:
                index_content.append(f"## {readme_file} (Missing)\n")
                index_content.append("File not found\n\n")
        
        # Save index
        index_file = self.output_dir / 'index.md'
        with open(index_file, 'w', encoding='utf-8') as f:
            f.writelines(index_content)
        
        print(f"✅ README index generated: {index_file}")
        return True
    
    def generate_all(self) -> Dict[str, Any]:
        """Generate all documentation"""
        print("REVENG Documentation Generator")
        print("=" * 40)
        print()
        
        results = {
            'api_docs': False,
            'tool_docs': False,
            'readme_index': False
        }
        
        # Generate API documentation
        results['api_docs'] = self.generate_api_docs()
        
        # Generate tool documentation
        results['tool_docs'] = self.generate_tool_docs()
        
        # Generate README index
        results['readme_index'] = self.generate_readme_index()
        
        # Summary
        print("\n" + "=" * 40)
        print("Documentation Generation Summary")
        print("=" * 40)
        
        successful = sum(1 for r in results.values() if r)
        total = len(results)
        
        print(f"API Documentation: {'✅' if results['api_docs'] else '❌'}")
        print(f"Tool Documentation: {'✅' if results['tool_docs'] else '❌'}")
        print(f"README Index: {'✅' if results['readme_index'] else '❌'}")
        
        print(f"\nTotal: {successful}/{total} documentation types generated")
        print(f"Output directory: {self.output_dir}")
        
        if successful == total:
            print("\n✅ All documentation generated successfully!")
        else:
            print(f"\n⚠️  {successful}/{total} documentation types generated")
        
        return results


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate REVENG documentation')
    parser.add_argument('--api', action='store_true', help='Generate API documentation only')
    parser.add_argument('--tools', action='store_true', help='Generate tool documentation only')
    parser.add_argument('--index', action='store_true', help='Generate README index only')
    parser.add_argument('--output', default='docs/generated', help='Output directory')
    args = parser.parse_args()
    
    generator = DocumentationGenerator()
    
    if args.output != 'docs/generated':
        generator.output_dir = Path(args.output)
        generator.output_dir.mkdir(parents=True, exist_ok=True)
    
    if args.api:
        success = generator.generate_api_docs()
    elif args.tools:
        success = generator.generate_tool_docs()
    elif args.index:
        success = generator.generate_readme_index()
    else:
        results = generator.generate_all()
        success = all(results.values())
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
