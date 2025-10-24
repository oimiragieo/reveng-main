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
pip install reveng-toolkit

# Core CLI usage
reveng analyze binary.exe --enhanced

# Launch web UI
reveng serve --host 0.0.0.0 --port 3000
```

```python
from reveng.api import REVENGAPI

api = REVENGAPI()
result = api.analyze_binary("/path/to/binary.exe")
threat = api.detect_malware("/suspicious.exe")
```

Need help? Open an [issue](https://github.com/oimiragieo/reveng-main/issues) or join the [discussions](https://github.com/oimiragieo/reveng-main/discussions). Security disclosures follow the [policy](../SECURITY.md).
