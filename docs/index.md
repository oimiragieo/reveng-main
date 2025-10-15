# Welcome to REVENG

<div align="center">
  <img src="../assets/logo.png" alt="REVENG Logo" width="150" height="150">
  <h1>Universal Reverse Engineering Platform</h1>
  <p><em>The ONLY open-source tool with complete binary reconstruction capabilities</em></p>
</div>

## What is REVENG?

REVENG is an enterprise-grade, AI-powered reverse engineering platform that supports analysis and reconstruction of Java, C#, Python, and native binaries. It's the only open-source tool that can disassemble, modify, and reassemble binaries into working executables.

## Key Features

- 🔄 **Complete Binary Reconstruction** - Disassemble, modify, reassemble any binary
- 🤖 **AI-Powered Analysis** - Ollama, Claude, OpenAI integration for intelligent insights  
- 🌐 **Multi-Language Support** - Java, C#, Python, Native (PE/ELF/Mach-O)
- 🎨 **Modern Web Interface** - React-based UI with real-time collaboration
- 🏢 **Enterprise Ready** - Audit trails, plugins, SOC 2 compliance
- 🧠 **ML-Powered Security** - Malware classification, vulnerability detection

## Quick Start

```bash
# Install REVENG
pip install reveng-toolkit

# Analyze a binary (CLI)
reveng analyze binary.exe

# Launch web interface  
reveng serve --port 3000
# Opens browser to http://localhost:3000
```

## Choose Your Interface

### CLI Users
**Command-line power users** who prefer terminal workflows:
- [CLI Usage Guide →](user-guide/cli-usage.md)
- [Advanced Features →](user-guide/advanced-features.md)

### Web Users  
**Visual interface enthusiasts** who prefer modern web UIs:
- [Web Interface Guide →](user-guide/web-interface.md)
- [Deployment Options →](deployment/docker.md)

### Developers
**Contributors and integrators** who want to extend REVENG:
- [Developer Guide →](developer-guide/README.md)
- [API Reference →](developer-guide/api-reference.md)

### AI Agents
**Automation and AI integration** for intelligent analysis:
- [AI Assistant Guide →](ai-assistant-guide/README.md)
- [Claude Integration →](ai-assistant-guide/claude-integration.md)

## Documentation

- [Getting Started](getting-started/) - Quick installation and first analysis
- [User Guide](user-guide/) - Complete feature documentation  
- [Developer Guide](developer-guide/) - Architecture and contribution
- [AI Assistant Guide](ai-assistant-guide/) - For AI agents and automation
- [Deployment](deployment/) - Docker, Kubernetes, cloud deployment

## Community & Support

- [GitHub Repository](https://github.com/oimiragieo/reveng-main)
- [Issue Tracker](https://github.com/oimiragieo/reveng-main/issues)
- [Discussions](https://github.com/oimiragieo/reveng-main/discussions)
- [Contributing Guide](developer-guide/contributing.md)

## License

MIT License - see [LICENSE](https://github.com/oimiragieo/reveng-main/blob/main/LICENSE)

---

<div align="center">
  <p><strong>Ready to get started?</strong></p>
  <p><a href="getting-started/quick-start.md" class="md-button md-button--primary">Quick Start Guide</a></p>
</div>
