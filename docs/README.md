# REVENG Documentation

> **Product maturity:** beta `4.0.0` · **public preview** — not full Scope C GA.  
> Start with the [Support matrix](support/support-matrix.md) and [Honesty rules](support/honesty-rules.md).

This site is organized with **[Diátaxis](https://diataxis.fr/)**: tutorials (learn), how-to guides (goals), explanation (understand), and reference (look up). There are **two doors** for juniors.

## Choose your door

### Analyst track — “How do I use REVENG and trust the output?”

1. [Install and triage](tutorials/analyst/01-install-and-triage.md)
2. [First app reverse-engineer](tutorials/analyst/02-app-reverse-engineer.md)
3. [Reading outputs & grades](tutorials/analyst/03-reading-outputs.md)
4. How-tos: [PE triage](how-to/analyst/triage-pe.md) · [YARA & VT](how-to/analyst/yara-and-vt.md) · [Bun](how-to/analyst/bun-executable.md) · [When Ghidra is required](how-to/analyst/when-ghidra-is-required.md)
5. Language CUJs: [JS](how-to/analyst/app-re-javascript.md) · [JVM](how-to/analyst/app-re-jvm.md) · [Python](how-to/analyst/app-re-python.md) · [.NET](how-to/analyst/app-re-dotnet.md)

### Engineer track — “How is this wired, and where do I change it?”

1. [Dev setup](tutorials/engineer/01-dev-setup.md)
2. [Unit & honesty gates](tutorials/engineer/02-run-unit-and-honesty-gates.md)
3. Explanation: [Architecture](explanation/architecture-overview.md) · [App RE dispatch](explanation/app-re-dispatch.md) · [Result contracts](explanation/result-contracts.md) · [VRL](explanation/vrl-and-verification.md)
4. How-tos: [Add adapter](how-to/engineer/add-adapter.md) · [Extend CLI](how-to/engineer/extend-cli.md) · [Wire MCP tool](how-to/engineer/wire-mcp-tool.md) · [Update support matrix](how-to/engineer/update-support-matrix.md) · [Scoped git](how-to/engineer/scoped-git-and-commits.md)

## Support & trust

| Doc | Purpose |
| --- | --- |
| [Maturity badges](support/maturity-badges.md) | What supported / limited / experimental / unsupported / fixture_only mean |
| [Support matrix](support/support-matrix.md) | Customer-facing boundary (mirrors JSON) |
| [Honesty rules](support/honesty-rules.md) | Fixture ≠ capability, no hollow claims |
| [Reading validation grades](support/reading-validation-grades.md) | App RE grades vs VRL grades |
| [GA-ish path checklist](support/ga-path-checklist.md) | One-pager for supported analyst workflows |

Machine SoT: [`support_matrix.json`](support_matrix.json).

## Reference (look up)

- [CLI](reference/cli.md)
- [Python API](reference/python-api.md)
- [MCP tools](reference/mcp-tools.md)
- [Config & env](reference/config-and-env.md)
- [Corpus & GA scripts](reference/corpus-and-ga-scripts.md)
- Legacy long MCP setup notes: [mcp/README.md](mcp/README.md) (honesty-rewritten; prefer [reference/mcp-tools.md](reference/mcp-tools.md) for capability status)

## Explanation (understand)

- [Architecture overview](explanation/architecture-overview.md)
- [Analysis pipeline](explanation/analysis-pipeline.md)
- [App RE dispatch](explanation/app-re-dispatch.md)
- [VRL & verification](explanation/vrl-and-verification.md)
- [Result contracts](explanation/result-contracts.md)
- [Ghidra boundary](explanation/ghidra-boundary.md)
- [AI providers](explanation/ai-providers.md)
- [pipeline vs pipelines](explanation/pipeline-vs-pipelines.md)
- [Security & exploits](explanation/security-and-exploits.md)

## Ops / program (not product tutorials)

- [Ops index](ops/README.md) — CEO updates, backlog, thinktank, wave criteria
- Living backlog: [`../backlog.md`](../backlog.md)

## Older paths (still linked)

- [Getting started (install)](getting-started/installation.md)
- [CLI usage (user guide)](user-guide/cli-usage.md)
- [Bun reversing](user-guide/bun-reversing.md)
- [Developer guide](developer-guide/DEVELOPER_GUIDE.md)
- [API reference (legacy)](api/API_REFERENCE.md)
- [Deployment](deployment/README.md)

Prefer the **Tutorials / How-to / Explanation / Reference** trees above when learning.
