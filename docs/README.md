# REVENG Documentation

Welcome to the REVENG documentation. This comprehensive guide covers everything you need to know about the REVENG Universal Reverse Engineering Platform.

## 📚 Documentation Structure

### Getting Started
- [Installation Guide](getting-started/installation.md) - Complete installation instructions
- [Quick Start Guide](getting-started/quick-start.md) - Get up and running in minutes
- [Troubleshooting](getting-started/troubleshooting.md) - Common issues and solutions

### MCP Integration (v4.0 NEW)
- [MCP Overview](mcp/README.md) - Model Context Protocol integration (651 lines)
- [MCP for AI Agents](mcp/claude.md) - AI-specific MCP documentation
- [MCP Configuration](../mcp-config.example.json) - Claude Desktop configuration template
- [MCP Validation](../validate-mcp.py) - Quick validation script
- [MCP Tests](../tests/poc/test_mcp_integration.py) - 14 POC tests

### User Guide
- [CLI Usage](user-guide/cli-usage.md) - Command-line interface reference
- [Web Interface](user-guide/web-interface.md) - Web-based analysis interface
- [Binary Analysis](user-guide/binary-analysis.md) - How to analyze different binary types
- [Multi-Language Support](user-guide/multi-language.md) - Supported languages and formats
- [AI Features](user-guide/ai-features.md) - AI-powered analysis capabilities
- [Advanced Features](user-guide/advanced-features.md) - Enterprise and advanced features
- [Configuration](user-guide/configuration.md) - System configuration options

### Developer Guide
- [Architecture](developer-guide/architecture.md) - System architecture overview
- [Contributing](developer-guide/contributing.md) - How to contribute to REVENG
- [Plugin Development](developer-guide/plugin-development.md) - Creating custom plugins
- [Tool Development](developer-guide/tool-development.md) - Adding new analysis tools
- [Testing](developer-guide/testing.md) - Testing guidelines and procedures
- [Project Structure](development/PROJECT_STRUCTURE.md) - Current project structure

### API Reference
- [Python API](api/python-api.md) - Python programming interface
- [REST API](api/rest-api.md) - Web API endpoints
- [AI API](api/ai-api.md) - AI service integration
- [Schemas](api/schemas/) - API data schemas

### Deployment
- [Docker](deployment/docker.md) - Containerized deployment
- [Kubernetes](deployment/kubernetes.md) - Kubernetes deployment
- [Cloud Providers](deployment/cloud-providers.md) - Cloud deployment options
- [Deployment Checklist](deployment/DEPLOYMENT_CHECKLIST.md) - Pre-deployment verification
- [Deployment Ready](deployment/DEPLOYMENT_READY.md) - Deployment readiness guide
- [Deployment Summary](deployment/DEPLOYMENT_SUMMARY.md) - Deployment overview

### Architecture
- [System Architecture](developer-guide/ARCHITECTURE.md) - Overall system design
- [Ghidra Integration](architecture/ghidra-integration.md) - Ghidra-first architecture
- [AI Integration](guides/AI_ASSISTANT_GUIDE.md) - AI subsystem design
- [Data Flow](developer-guide/CODE_FLOW_ANALYSIS.md) - Data flow through the system

### AI Assistant Guide
- [Overview](ai-assistant-guide/README.md) - AI assistant integration
- [Claude Integration](ai-assistant-guide/claude-integration.md) - Claude AI integration
- [Tool Selection](ai-assistant-guide/tool-selection.md) - Tool selection matrix
- [Automation](ai-assistant-guide/automation.md) - Automated workflows

### Guides
- [Complete Setup Guide](guides/complete-setup-guide.md) - Comprehensive setup
- [Advanced Analysis](guides/advanced-analysis.md) - Advanced analysis techniques
- [Ghidra Integration](guides/ghidra-integration.md) - Ghidra integration guide
- [Migration Guide](guides/migration.md) - Upgrading from older versions
- [Best Practices](guides/best-practices.md) - Recommended practices

### Development
- [Project Structure](development/PROJECT_STRUCTURE.md) - Codebase organization
- [Release Checklist](development/release-checklist.md) - Release procedures
- [Roadmap](development/roadmap.md) - Development roadmap
- [Next Steps](development/NEXT_STEPS.md) - Current development priorities
- [Pre-Publication Checklist](development/PRE_PUBLICATION_CHECKLIST.md) - Publication readiness
- [AI Enhancement History](development/history/ai-enhancements.md) - AI feature development

### Reports
- [Implementation Complete](reports/implementation-complete.md) - Implementation status
- [Security Audit](reports/security-audit.md) - Security assessment
- [Cross-Platform Testing](reports/cross-platform-testing.md) - Testing results
- [Validation Report](reports/validation-report.md) - Validation results
- [Comprehensive Review](reports/comprehensive-review.md) - Complete project review
- [Codebase Investigation](reports/codebase-investigation.md) - Code analysis report
- [Ghidra Integration](reports/ghidra-integration-complete.md) - Ghidra implementation

## 🚀 Quick Navigation

### For Users
- **New to REVENG?** Start with [Quick Start](getting-started/quick-start.md)
- **Need help?** Check [Troubleshooting](getting-started/troubleshooting.md)
- **Advanced features?** See [Advanced Features](user-guide/advanced-features.md)

### For Developers
- **Contributing?** Read [Contributing Guide](developer-guide/contributing.md)
- **Architecture?** See [Architecture](developer-guide/architecture.md)
- **Testing?** Check [Testing Guide](developer-guide/testing.md)

### For AI Assistants
- **🆕 MCP Integration?** See [MCP Documentation](mcp/README.md) - **START HERE for v4.0!**
- **Integration?** See [AI Assistant Guide](ai-assistant-guide/README.md)
- **Tool Selection?** Check [Tool Selection Matrix](ai-assistant-guide/tool-selection-matrix.md)
- **Automation?** Read [Automation Guide](ai-assistant-guide/automation.md)

## 📖 Key Features

- **🆕 MCP Enterprise Server** - 15+ specialized tools for AI agents (v4.0)
- **🆕 GPU Acceleration** - CUDA/ROCm/MPS support for 10-100x speedup (v4.0)
- **🆕 Symbolic Execution** - angr + Z3 integration with 90%+ accuracy (v4.0)
- **🆕 LLM4Decompile** - Specialized decompilation models (90%+ recompilability) (v4.0)
- **Universal Binary Analysis** - Analyze any binary format (PE, ELF, Mach-O, JAR, .NET)
- **AI-Powered Insights** - Multi-model AI ensemble (Gemini, Claude, GPT-4)
- **Binary Recompilation** - 95%+ success rate with AI-powered error recovery
- **JavaScript Deobfuscation** - 10-stage pipeline with 85%+ success rate
- **Multi-Language Support** - Java, C#, Python, Native binaries
- **Enterprise Ready** - Kubernetes deployment, rate limiting, audit logging
- **Type Reconstruction** - ML-based type inference (90%+ accuracy)
- **Extensible** - Plugin system for custom tools

## 🔗 External Resources

- [GitHub Repository](https://github.com/oimiragieo/reveng-main)
- [PyPI Package](https://pypi.org/project/reveng/)
- [Issue Tracker](https://github.com/oimiragieo/reveng-main/issues)
- [Discussions](https://github.com/oimiragieo/reveng-main/discussions)

## 📝 Contributing

We welcome contributions! Please see our [Contributing Guide](developer-guide/contributing.md) for details on how to contribute to REVENG.

## 📄 License

REVENG is licensed under the MIT License. See [LICENSE](../LICENSE) for details.

---

## 📊 Documentation Statistics (v4.0)

- **Total Files**: 303 documentation files
  - 195 markdown files
  - 108 claude.md AI context files
- **Total Lines**: 122,036 lines of code across 335 Python files
- **Test Coverage**: 91% (13,647 lines of test code)
- **MCP Tools**: 15+ specialized reverse engineering tools
- **Production Ready**: Docker/Kubernetes deployment with comprehensive monitoring

---

## 📂 Documentation Organization

As part of the v4.0 enterprise release, documentation has been enhanced:

- **🆕 MCP Integration** - Complete MCP documentation in `mcp/` (v4.0)
- **Deployment docs** - Kubernetes and Docker deployment in `deployment/`
- **Architecture docs** - System architecture in `architecture/`
- **Development artifacts** - Development history in `development/` and `development/history/`
- **Comprehensive reports** - Analysis reports in `reports/`
- **AI Context** - 108 claude.md files providing AI-specific context throughout the codebase

This provides comprehensive coverage for users, developers, and AI agents.

---

*Last updated: November 2025 - v4.0.0 (Enterprise AI Tool Suite)*
