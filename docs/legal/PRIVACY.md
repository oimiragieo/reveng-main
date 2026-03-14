# Privacy Notes

REVENG is primarily a local toolchain. Most analysis happens on the machine where you run it, and output artifacts are written to local directories such as `analysis_<binary-name>/`.

## Local Data

Running REVENG may create:

- analysis output directories
- logs created by individual tools or analyzers
- cached or intermediate artifacts needed for reconstruction workflows

These files stay on your machine unless you explicitly upload or share them.

## Optional Networked Services

Some workflows can talk to external systems when you configure them:

- Ollama (usually local)
- Anthropic / OpenAI APIs
- VirusTotal
- any additional services you wire in yourself

If you enable those integrations, the privacy rules of the selected provider apply to the data you send there.

## Telemetry

This repository does not document a built-in telemetry pipeline. Treat logs, outputs, API calls, and MCP traffic as your responsibility to configure and protect.

## Practical Guidance

- keep analysis runs on trusted systems
- review generated output before sharing it
- store API keys with your normal secret-management practices
- prefer local providers such as Ollama when you need stricter data control

## Related Docs

- [Getting Started](../getting-started/installation.md)
- [MCP Guide](../mcp/README.md)
- [Root Security Policy](../../SECURITY.md)
