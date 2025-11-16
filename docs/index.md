# REVENG Documentation Hub

Welcome to the home of REVENG reference material. The site is organised so that engineers, analysts, and automation agents can quickly locate the guidance they need.

## Start Here

- [Installation](getting-started/installation.md) – prerequisites and platform-specific notes.
- [Quick Start](getting-started/quick-start.md) – first analysis in minutes.
- [Troubleshooting](getting-started/troubleshooting.md) – targeted fixes for common setup problems.

## Platform Architecture

- [Runtime Overview](architecture/overview.md) – explains the core pipeline, data flow, and service boundaries.
- [Package Map](architecture/package-map.md) – documents top-level packages: `reveng.agents`, `reveng.security`, `reveng.reporting`, and `reveng.integrations`.
- [Pipeline Steps](architecture/pipeline.md) – describes each processing phase, including newly modularised vulnerability and threat intelligence steps.

## User Operations

- [CLI Reference](user-guide/cli-usage.md) – subcommands, flags, and workflows.
- [Binary Analysis Playbooks](user-guide/binary-analysis.md) – practical scenarios across languages.
- [Configuration](user-guide/configuration.md) – YAML, environment, and CLI overrides.

## Automation & AI

### 🆕 MCP Integration (v4.0)
- [MCP Enterprise Server](mcp/README.md) – Model Context Protocol with 15+ specialized tools.
- [MCP for AI Agents](mcp/claude.md) – Claude Desktop integration and natural language workflows.
- [MCP Configuration](../mcp-config.example.json) – Configuration template for AI agents.
- [MCP Validation](../validate-mcp.py) – Quick validation and testing script.

### Legacy AI Integration
- [Agent Integration](ai-assistant-guide/README.md) – how external agents interact with REVENG APIs.
- [Natural-Language Interface](ai-assistant-guide/automation.md) – conversation-driven analysis flows.
- [Model Selection Matrix](ai-assistant-guide/tool-selection-matrix.md) – recommended toolchains.

## Developer & Contributor Resources

- [Developer Guide](developer-guide/README.md) – repository conventions and tooling.
- [Testing Guide](developer-guide/testing.md) – suite structure (`unit`, `integration`, `security`, `e2e`).
- [Extending REVENG](guides/plugin-development.md) – plugin and tool authoring.
- [API Reference](api/API_REFERENCE.md) – HTTP and Python APIs.

## Deployment

- [Docker](deployment/docker.md) – container images and compose layouts.
- [Kubernetes](deployment/kubernetes.md) – production-grade orchestration.
- [Enterprise Playbooks](deployment/enterprise.md) – hardening and observability.

## Reports & History

- [Security Audit](reports/security-audit.md) – vulnerability posture.
- [Validation Report](reports/validation-report.md) – functional test coverage.
- [Historical Snapshots](history/) – archived programme updates and decision logs.

## Quick Reference

```bash
# Install
pip install -r requirements.txt
pip install google-generativeai anthropic openai

# 🆕 Launch MCP Server (v4.0)
./reveng-mcp-server                              # For Claude Desktop
./reveng-mcp-server --transport http --port 8080 # For HTTP access

# Core CLI usage
reveng analyze binary.exe --enhanced

# JavaScript deobfuscation
./reveng-js deobfuscate obfuscated.js -o clean.js

# Launch web UI
reveng serve --host 0.0.0.0 --port 3000
```

```python
# Python API
from reveng.api import REVENGAPI

api = REVENGAPI()
result = api.analyze_binary("/path/to/binary.exe")
threat = api.detect_malware("/suspicious.exe")
```

```bash
# 🆕 AI-Powered Analysis via MCP (v4.0)
# Configure Claude Desktop with mcp-config.example.json, then:
# "Analyze this binary for vulnerabilities: /path/to/suspicious.exe"
# "Deobfuscate this JavaScript and check for malware"
# "Generate an exploit for the buffer overflow at 0x401000"
```

Need help? Open an [issue](https://github.com/oimiragieo/reveng-main/issues) or join the [discussions](https://github.com/oimiragieo/reveng-main/discussions). Security disclosures follow the [policy](../SECURITY.md).
