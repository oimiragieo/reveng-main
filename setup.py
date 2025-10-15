#!/usr/bin/env python3
"""
REVENG Universal Reverse Engineering Platform - Package Setup
=============================================================

Enterprise-grade, AI-powered reverse engineering platform with complete
binary reconstruction capabilities.

Author: REVENG Development Team
License: MIT
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    """Read README.md for long description."""
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as fh:
            return fh.read()
    return "Universal reverse engineering platform with AI-powered analysis"

# Read version from VERSION file
def read_version():
    """Read version from VERSION file."""
    version_path = os.path.join(os.path.dirname(__file__), "VERSION")
    if os.path.exists(version_path):
        with open(version_path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    return "2.1.0"

# Read requirements from requirements.txt
def read_requirements():
    """Read requirements from requirements.txt."""
    requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.exists(requirements_path):
        with open(requirements_path, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return [
        "requests>=2.28.1",
        "ghidramcp>=0.1.0",
        "lief>=0.13.0",
        "keystone-engine>=0.9.2",
        "capstone>=5.0.0",
        "networkx>=3.0",
        "pydot>=1.4.2",
        "tqdm>=4.64.0",
        "pyyaml>=6.0",
    ]

# Read dev requirements
def read_dev_requirements():
    """Read development requirements."""
    dev_requirements_path = os.path.join(os.path.dirname(__file__), "requirements-dev.txt")
    if os.path.exists(dev_requirements_path):
        with open(dev_requirements_path, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return [
        "pytest>=7.4.0",
        "pytest-cov>=4.1.0",
        "black>=23.12.0",
        "isort>=5.13.0",
        "pylint>=3.0.0",
        "mypy>=1.7.0",
    ]

setup(
    name="reveng-toolkit",
    version=read_version(),
    author="REVENG Development Team",
    author_email="contact@reveng-project.org",
    description="Universal reverse engineering platform with AI-powered analysis",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/oimiragieo/reveng-main",
    project_urls={
        "Bug Tracker": "https://github.com/oimiragieo/reveng-main/issues",
        "Documentation": "https://docs.reveng-toolkit.org",
        "Source Code": "https://github.com/oimiragieo/reveng-main",
        "Changelog": "https://github.com/oimiragieo/reveng-main/blob/main/CHANGELOG.md",
        "Discussions": "https://github.com/oimiragieo/reveng-main/discussions",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Natural Language :: English",
    ],
    keywords=[
        "reverse-engineering",
        "binary-analysis",
        "decompiler",
        "disassembler",
        "ai-powered",
        "malware-analysis",
        "vulnerability-detection",
        "binary-reconstruction",
        "ghidra",
        "security",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.11",
    install_requires=read_requirements(),
    extras_require={
        "dev": read_dev_requirements(),
        "ai": [
            "anthropic>=0.7.0",
            "openai>=1.3.0",
        ],
        "web": [
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
            "websockets>=12.0",
        ],
        "java": [
            "jython>=2.7.3",
        ],
        "all": [
            "anthropic>=0.7.0",
            "openai>=1.3.0",
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
            "websockets>=12.0",
            "jython>=2.7.3",
        ],
    },
    entry_points={
        "console_scripts": [
            "reveng=reveng.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "reveng": [
            "templates/*",
            "config/*.yaml",
            "config/*.yml",
        ],
    },
    zip_safe=False,
    platforms=["any"],
    license="MIT",
    maintainer="REVENG Development Team",
    maintainer_email="contact@reveng-project.org",
    # PyPI metadata
    download_url="https://github.com/oimiragieo/reveng-main/archive/v{}.tar.gz".format(read_version()),
    # Development status
    development_status="Production/Stable",
    # Supported Python versions
    supported_python_versions=["3.11", "3.12"],
    # Minimum Python version
    minimum_python_version="3.11",
)
