# REVENG Documentation Hub

Welcome to the REVENG Universal Reverse Engineering Platform documentation. This hub provides comprehensive guides for users, developers, and AI agents.

## 🚀 Quick Start

- [Installation Guide](getting-started/installation.md) - Platform-specific setup instructions
- [Quick Start](getting-started/quick-start.md) - Get up and running in 3 commands
- [Troubleshooting](getting-started/troubleshooting.md) - Common issues and solutions

## 👥 User Guides

### CLI Usage
- [Command Reference](user-guide/cli-usage.md) - Complete CLI documentation
- [Binary Analysis](user-guide/binary-analysis.md) - Analysis workflows and examples
- [Multi-Language Support](user-guide/multi-language.md) - Java, C#, Python analysis
- [Configuration](user-guide/configuration.md) - Settings and customization

### Web Interface
- [Web UI Guide](user-guide/web-interface.md) - Visual interface documentation
- [Known Limitations](web_interface/STATUS.md) - Current experimental status

## 🛠️ Developer Resources

### Architecture & Development
- [System Architecture](architecture/ARCHITECTURE.md) - High-level system design
- [Contributing Guide](development/CONTRIBUTING.md) - How to contribute
- [Tool Development](development/tool-development.md) - Creating custom tools
- [Plugin Development](guides/plugin-development.md) - Plugin system guide
- [API Reference](api/API_REFERENCE.md) - Complete API documentation
- [Testing Guidelines](development/testing.md) - Test development guide

### Advanced Topics
- [Advanced Analysis](guides/advanced-analysis.md) - Advanced techniques
- [Windows Analysis](guides/windows-analysis.md) - Windows-specific workflows
- [Pipeline Development](guides/pipeline-development.md) - Custom analysis pipelines

## 🤖 AI Assistant Guide

- [Claude Integration](ai-assistant-guide/claude-integration.md) - AI-specific setup
- [Tool Selection Matrix](ai-assistant-guide/tool-selection-matrix.md) - Decision guide for AI agents
- [Automation Workflows](ai-assistant-guide/automation.md) - Workflow automation

## 🚀 Deployment

- [Docker Deployment](deployment/docker.md) - Container deployment
- [Kubernetes Deployment](deployment/kubernetes.md) - K8s orchestration
- [Production Setup](deployment/production.md) - Production deployment guide

## 📊 Case Studies & Reports

### Case Studies
- [KARP Analysis](case-studies/karp-analysis.md) - Complete case study (50% → 90% accuracy)

### Technical Reports
- [Implementation Complete](reports/implementation-complete.md) - Final implementation status
- [Transformation Summary](reports/transformation-summary.md) - Platform transformation overview
- [Security Audit](reports/security-audit.md) - Security assessment results
- [Validation Report](reports/validation-report.md) - Testing and validation results
- [Cross-Platform Testing](reports/cross-platform-testing.md) - Platform compatibility results

## 📚 Training Materials

- [Malware Analysis Fundamentals](training/610.1-malware-analysis-fundamentals.pdf) - SANS FOR610 training materials

## 🔗 External Resources

- [GitHub Repository](https://github.com/oimiragieo/reveng-main)
- [Issue Tracker](https://github.com/oimiragieo/reveng-main/issues)
- [Discussions](https://github.com/oimiragieo/reveng-main/discussions)
- [Releases](https://github.com/oimiragieo/reveng-main/releases)

## 📋 Quick Reference

### Essential Commands
```bash
# Install
pip install reveng-toolkit

# Basic analysis
reveng analyze malware.exe

# Enhanced analysis
reveng analyze --enhanced suspicious.jar

# Web interface
reveng serve --host 0.0.0.0 --port 3000
```

### Python API
```python
from reveng.api import REVENGAPI

# Create API instance
api = REVENGAPI()

# Analyze binary
result = api.analyze_binary('/path/to/binary.exe')

# Detect malware
threat = api.detect_malware('/suspicious.exe')

# Reconstruct binary
source = api.reconstruct_binary('/target.exe', output_format='c')
```

## 🆘 Support

- **Documentation Issues**: [Create an issue](https://github.com/oimiragieo/reveng-main/issues)
- **Feature Requests**: [Start a discussion](https://github.com/oimiragieo/reveng-main/discussions)
- **Security Issues**: [Security Policy](SECURITY.md)

---

*This documentation is continuously updated. Last updated: January 2025*
